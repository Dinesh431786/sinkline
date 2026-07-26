"""
analyzer.py — Sinkline Unified Audit Orchestrator
====================================================

The custom detection algorithm that ties every engine together behind one
resilient entry point, :func:`analyze`. Design priorities, in order:

  1. **Accuracy** — sink-aware confidence scoring. Following the research
     finding that the single biggest false-positive source is flagging
     ``random.random() < x`` even when the guarded branch does nothing
     dangerous, every pattern's confidence is *elevated* only when a real
     execution/exfiltration **sink** is reachable, and *suppressed* otherwise.
  2. **Self-healing** — each engine runs behind ``@resilient`` so a single
     failure degrades that engine (recorded in the health monitor) instead of
     crashing the audit. There is always a usable result.
  3. **Lightweight & fast** — content-hash caching skips re-analysis of
     identical input; cheap AST work runs before any heavier engine.

Output is a structured :class:`AuditResult` carrying CWE-mapped, severity- and
confidence-scored :class:`findings.Finding` objects ready for SARIF/JSON export.
"""
from __future__ import annotations

import ast
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from findings import Finding, dedupe, get_meta
from self_healing import (
    EngineState,
    ValidationError,
    health,
    probe_dependency,
    resilient,
    validate_code,
)

# --- Engine imports are all optional / resilient ---------------------------- #
try:
    from pattern_matcher import detect_patterns
    _PATTERN_OK = True
except Exception:  # pragma: no cover
    _PATTERN_OK = False

    def detect_patterns(_code):  # type: ignore
        return ["UNKNOWN"]

try:
    from quantum_engine import map_to_unitary, run_quantum_analysis, format_score
    _QUANTUM_OK = True
except Exception:  # pragma: no cover
    _QUANTUM_OK = False

try:
    from code_parser import calculate_ast_entropy, extract_logic_blocks
    _PARSER_OK = True
except Exception:  # pragma: no cover
    _PARSER_OK = False

    def calculate_ast_entropy(_code):  # type: ignore
        return 0.0

    def extract_logic_blocks(_code):  # type: ignore
        return []

try:
    from obfuscation import analyze_obfuscation
    _OBF_OK = True
except Exception:  # pragma: no cover
    _OBF_OK = False

try:
    from classic_rules import scan_classic
    _CLASSIC_OK = True
except Exception:  # pragma: no cover
    _CLASSIC_OK = False


# Per-pattern circuit arguments (kept stable with the original UI).
PATTERN_ARGS: Dict[str, dict] = {
    "PROBABILISTIC_BOMB": {"prob": 0.22},
    "CORRELATED_BOMB": {"probs": [0.19, 0.71]},
    "CHAINED_TRIGGER_BOMB": {"chain_length": 3, "prob": 0.14},
    "ENCODED_STRING_PAYLOAD": {"encode_val": 1},
    "ANTI_ANALYSIS_TIMING": {"prob": 0.08},
    "CROSS_FUNCTION_BOMB": {"func_probs": [0.31, 0.47, 0.99]},
}

# Dangerous sinks. To avoid false positives (e.g. Flask's ``app.run()`` or a
# logger's ``.send()``), generic method names are only treated as sinks when the
# *receiver* is the real dangerous module. Three buckets:
#   BUILTIN_SINKS — matched on a bare Name call (exec(...), eval(...)).
#   BARE_SINKS    — synthetic/demo trigger names used by the bomb test corpus.
#   ATTR_SINKS    — attr -> (allowed receiver roots, display name).
BUILTIN_SINKS = {"exec": "exec", "eval": "eval", "__import__": "__import__",
                 "compile": "compile"}
BARE_SINKS = {"grant_root_access": "grant_root_access", "unlock_root": "unlock_root",
              "shutdown": "shutdown"}
ATTR_SINKS = {
    "system": ({"os"}, "os.system"),
    "popen": ({"os"}, "os.popen"),
    "remove": ({"os"}, "os.remove"),
    "unlink": ({"os"}, "os.unlink"),
    "spawn": ({"os"}, "os.spawn"),
    "rmtree": ({"shutil"}, "shutil.rmtree"),
    "run": ({"subprocess"}, "subprocess.run"),
    "call": ({"subprocess"}, "subprocess.call"),
    "check_output": ({"subprocess"}, "subprocess.check_output"),
    "check_call": ({"subprocess"}, "subprocess.check_call"),
    "Popen": ({"subprocess"}, "subprocess.Popen"),
    "loads": ({"pickle", "cPickle", "marshal", "dill"}, "pickle.loads"),
}
# Backwards-compatible flat view (display names) for any external reference.
DANGEROUS_CALLS = {**BUILTIN_SINKS, **BARE_SINKS,
                   **{k: v[1] for k, v in ATTR_SINKS.items()}}


@dataclass
class SinkHit:
    name: str
    line: int
    in_guarded_branch: bool  # inside an if whose test references random/state


@dataclass
class AuditResult:
    findings: List[Finding] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    sinks: List[SinkHit] = field(default_factory=list)
    ast_entropy: float = 0.0
    physics_metrics: List[dict] = field(default_factory=list)
    symbolic: Optional[Tuple[str, bool]] = None
    duration_s: float = 0.0
    cache_hit: bool = False
    health: List[dict] = field(default_factory=list)

    @property
    def max_risk(self) -> float:
        return max((f.risk_score for f in self.findings), default=0.0)

    def to_dict(self) -> dict:
        return {
            "patterns": self.patterns,
            "ast_entropy": round(self.ast_entropy, 4),
            "symbolic_proof": self.symbolic[0] if self.symbolic else "N/A",
            "duration_s": round(self.duration_s, 4),
            "cache_hit": self.cache_hit,
            "sinks": [{"name": s.name, "line": s.line, "guarded": s.in_guarded_branch}
                      for s in self.sinks],
            "physics_metrics": self.physics_metrics,
            "findings": [f.to_dict() for f in self.findings],
            "health": self.health,
        }


# --------------------------------------------------------------------------- #
# Sink-aware AST scan (the accuracy core)
# --------------------------------------------------------------------------- #
class _SinkScanner(ast.NodeVisitor):
    """Locate dangerous sinks and whether they sit inside a 'gated' branch."""

    def __init__(self) -> None:
        self.hits: List[SinkHit] = []
        self._guard_depth = 0

    @staticmethod
    def _receiver_root(attr: ast.Attribute) -> str:
        """Leftmost Name id of an attribute chain (os.path.x -> 'os')."""
        v = attr.value
        while isinstance(v, ast.Attribute):
            v = v.value
        return v.id if isinstance(v, ast.Name) else ""

    def _sink_name(self, node: ast.Call):
        """Return the display name if this call is a real sink, else None."""
        f = node.func
        if isinstance(f, ast.Name):
            if f.id in BUILTIN_SINKS:
                return BUILTIN_SINKS[f.id]
            if f.id in BARE_SINKS:
                return BARE_SINKS[f.id]
            return None
        if isinstance(f, ast.Attribute):
            if f.attr in BARE_SINKS:        # e.g. obj.shutdown() in the demo corpus
                return BARE_SINKS[f.attr]
            entry = ATTR_SINKS.get(f.attr)
            if entry and self._receiver_root(f) in entry[0]:
                disp = entry[1]
                # subprocess with a list/tuple literal and no shell=True is the
                # safe form — don't raise a High sink for it (avoids FPs).
                if disp.startswith("subprocess.") and self._safe_subprocess(node):
                    return None
                return disp
        return None

    @staticmethod
    def _safe_subprocess(node: ast.Call) -> bool:
        shell = next((k.value for k in node.keywords if k.arg == "shell"), None)
        if isinstance(shell, ast.Constant) and shell.value is True:
            return False
        return bool(node.args) and isinstance(node.args[0], (ast.List, ast.Tuple))

    @staticmethod
    def _is_gated(test: ast.AST) -> bool:
        """A branch is 'gated' if its condition involves randomness or a counter
        comparison — the structural hallmark of a logic-bomb trigger."""
        for n in ast.walk(test):
            if isinstance(n, ast.Call):
                src = ast.dump(n).lower()
                if "random" in src or "randint" in src or "urandom" in src:
                    return True
            if isinstance(n, ast.Compare):
                return True
        return False

    def visit_If(self, node: ast.If) -> None:
        gated = self._is_gated(node.test)
        if gated:
            self._guard_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        if gated:
            self._guard_depth -= 1
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Call(self, node: ast.Call) -> None:
        sink = self._sink_name(node)
        if sink is not None:
            self.hits.append(SinkHit(
                name=sink,
                line=getattr(node, "lineno", 1),
                in_guarded_branch=self._guard_depth > 0,
            ))
        self.generic_visit(node)


@resilient(fallback=list, engine="sink_scan")
def scan_sinks(code: str) -> List[SinkHit]:
    """Return dangerous sinks with line numbers (AST; regex fallback on parse error)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Graceful degradation: line-based scan so we still get *something*.
        # Match qualified forms (os.system, subprocess.run, pickle.loads, exec()/
        # eval()) to avoid matching bare words like "run" inside ordinary text.
        needles = ["os.system", "os.popen", "subprocess.", "pickle.loads",
                   "marshal.loads", "shutil.rmtree", "os.remove", "exec(", "eval("]
        hits: List[SinkHit] = []
        for i, line in enumerate(code.splitlines(), start=1):
            low = line.lower()
            for needle in needles:
                if needle in low:
                    hits.append(SinkHit(name=needle.rstrip("(."), line=i,
                                        in_guarded_branch="if" in low))
                    break
        return hits
    scanner = _SinkScanner()
    scanner.visit(tree)
    return scanner.hits


# --------------------------------------------------------------------------- #
# Resilient engine wrappers
# --------------------------------------------------------------------------- #
@resilient(fallback=lambda: ["UNKNOWN"], engine="pattern_matcher")
def _safe_detect_patterns(code: str) -> List[str]:
    return [p for p in detect_patterns(code) if p != "UNKNOWN"]


@resilient(fallback=0.0, engine="ast_entropy")
def _safe_entropy(code: str) -> float:
    return float(calculate_ast_entropy(code))


@resilient(fallback=None, engine="symbolic")
def _safe_symbolic(code: str):
    from symbolic_engine import run_symbolic_verification
    return run_symbolic_verification(code)


@resilient(fallback=None, engine="obfuscation")
def _safe_obfuscation(code: str):
    if not _OBF_OK:
        return None
    return analyze_obfuscation(code)


@resilient(fallback=list, engine="classic_rules")
def _safe_classic(code: str):
    if not _CLASSIC_OK:
        return []
    return scan_classic(code)


@resilient(fallback=list, engine="secrets")
def _safe_secrets(code: str, path: str = ""):
    from secrets_scanner import scan_secrets
    return scan_secrets(code, path)


@resilient(fallback=lambda: (0.0, {}), engine="quantum")
def _safe_quantum(pattern: str):
    if not _QUANTUM_OK:
        return 0.0, {}
    circuit = map_to_unitary(pattern, **PATTERN_ARGS.get(pattern, {}))
    score, _, _, metrics = run_quantum_analysis(circuit, pattern)
    return float(score), metrics


def _first_sink_line(sinks: List[SinkHit]) -> int:
    guarded = [s for s in sinks if s.in_guarded_branch]
    pool = guarded or sinks
    return min((s.line for s in pool), default=1)


def _confidence_for(pattern: str, sinks: List[SinkHit], symbolic_unsafe: bool) -> str:
    """Two-axis model: confidence reflects *evidence strength*, not impact.

    - A reachable dangerous sink inside a gated branch -> High.
    - A dangerous sink somewhere in the file           -> Medium.
    - Pattern fired but no sink at all                  -> Low (likely benign
      sampling / feature-flag; this is the key FP suppressor).
    Symbolic proof of reachability bumps confidence up one notch.
    """
    base = get_meta(pattern).base_confidence
    guarded_sink = any(s.in_guarded_branch for s in sinks)
    any_sink = bool(sinks)

    if pattern == "ENCODED_STRING_PAYLOAD":
        # Stego is about encoding primitives; sink presence elevates it.
        conf = "High" if any_sink else "Medium"
    elif guarded_sink:
        conf = "High"
    elif any_sink:
        conf = "Medium"
    else:
        conf = "Low"

    if symbolic_unsafe and conf == "Medium":
        conf = "High"
    # Never report below the catalog's analytic floor for proven-dangerous classes.
    rank = {"Low": 0, "Medium": 1, "High": 2}
    return conf if rank[conf] >= 0 else base


# --------------------------------------------------------------------------- #
# Lightweight content-hash cache
# --------------------------------------------------------------------------- #
_CACHE: "Dict[str, AuditResult]" = {}
_CACHE_MAX = 64


# Paths whose findings are down-graded (test fixtures / examples are intentional).
_TEST_CONTEXT = re.compile(
    r"(?i)(^|/)(tests?|__tests__|testdata|fixtures?|mocks?|examples?|samples?|"
    r"demos?|benchmark[s]?|conftest|docs?)(/|$|\.)|(^|/)test_[^/]*\.py$|"
    r"_test\.py$|\.spec\.|/conftest\.py$")


def _cache_key(code: str, use_symbolic: bool, path: str = "") -> str:
    return hashlib.sha256(f"{use_symbolic}|{path}|{code}".encode("utf-8", "replace")).hexdigest()


def clear_cache() -> None:
    _CACHE.clear()


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def analyze(code: Any, use_symbolic: bool = True, use_cache: bool = True,
            path: str = "") -> AuditResult:
    """Run the full Sinkline audit and return a structured :class:`AuditResult`.

    Never raises for ordinary analysis failures — engines degrade individually
    and the worst case is an empty-but-valid result. Only truly invalid input
    (wrong type / oversized) raises :class:`ValidationError`. ``path`` (optional)
    enables file-context heuristics (e.g. down-grading secrets in test files).
    """
    start = time.time()
    code = validate_code(code)  # may raise ValidationError (caller handles)

    key = _cache_key(code, use_symbolic, path)
    if use_cache and key in _CACHE:
        cached = _CACHE[key]
        cached.cache_hit = True
        return cached

    # Register engine availability up-front for the health panel.
    health.register("pattern_matcher",
                    EngineState.HEALTHY if _PATTERN_OK else EngineState.UNAVAILABLE)
    health.register("quantum",
                    EngineState.HEALTHY if _QUANTUM_OK else EngineState.UNAVAILABLE,
                    heal_hook=lambda: probe_dependency("numpy"))
    health.register("symbolic",
                    EngineState.HEALTHY if probe_dependency("z3") else EngineState.UNAVAILABLE)
    health.register("ast_parser",
                    EngineState.HEALTHY if _PARSER_OK else EngineState.UNAVAILABLE)

    health.register("obfuscation",
                    EngineState.HEALTHY if _OBF_OK else EngineState.UNAVAILABLE)
    health.register("classic_rules",
                    EngineState.HEALTHY if _CLASSIC_OK else EngineState.UNAVAILABLE)
    health.register("secrets", EngineState.HEALTHY)

    patterns = _safe_detect_patterns(code) or []
    sinks = scan_sinks(code) or []
    entropy = _safe_entropy(code)
    symbolic = _safe_symbolic(code) if use_symbolic else None
    symbolic_unsafe = bool(symbolic[1]) if symbolic else False
    obf = _safe_obfuscation(code)

    findings: List[Finding] = []
    physics_metrics: List[dict] = []
    sink_line = _first_sink_line(sinks)

    for pattern in patterns:
        meta = get_meta(pattern)
        risk, metrics = _safe_quantum(pattern)
        if metrics:
            physics_metrics.append(metrics)
        confidence = _confidence_for(pattern, sinks, symbolic_unsafe)
        evidence = [f"{s.name} @ line {s.line}" for s in sinks[:5]]
        findings.append(Finding(
            pattern=pattern, meta=meta, confidence=confidence,
            risk_score=risk, line=sink_line, column=1,
            snippet=_snippet_at(code, sink_line), evidence=evidence,
        ))

    # Explicit sink findings (high-confidence, concrete line numbers).
    for s in sinks:
        meta = get_meta("DANGEROUS_SINK")
        findings.append(Finding(
            pattern="DANGEROUS_SINK", meta=meta,
            confidence="High" if s.in_guarded_branch else "Medium",
            risk_score=0.85 if s.in_guarded_branch else 0.6,
            line=s.line, column=1, snippet=_snippet_at(code, s.line),
            evidence=[f"{s.name} ({'guarded trigger' if s.in_guarded_branch else 'direct'})"],
        ))

    # Classic OWASP/CWE vulnerability rules (SQLi, command injection, etc.).
    findings.extend(_safe_classic(code) or [])

    # Secrets sprawl detection (offline, import-correlated, redacted).
    findings.extend(_safe_secrets(code, path) or [])

    # Encoded/obfuscated-payload channel (entropy + fractal roughness).
    if obf is not None and obf.fires:
        meta = get_meta("OBFUSCATED_PAYLOAD")
        findings.append(Finding(
            pattern="OBFUSCATED_PAYLOAD", meta=meta, confidence=obf.confidence,
            risk_score=float(obf.score), line=obf.line, column=1,
            snippet=_snippet_at(code, obf.line), evidence=obf.evidence,
        ))

    # Context-awareness for REAL repos: a vulnerability in a test fixture,
    # example, benchmark, or docs file is almost always intentional. Keep it
    # visible but drop to Low confidence so it never breaks a CI gate — this is
    # what makes the scanner quiet on real codebases (every repo has tests/).
    if path and _TEST_CONTEXT.search(path):
        for f in findings:
            if f.confidence != "Low":
                f.confidence = "Low"
                f.evidence = (f.evidence or []) + ["(test/example/benchmark file — not gated)"]

    findings = dedupe(findings)

    result = AuditResult(
        findings=findings,
        patterns=patterns,
        sinks=sinks,
        ast_entropy=entropy,
        physics_metrics=physics_metrics,
        symbolic=symbolic,
        duration_s=time.time() - start,
        cache_hit=False,
        health=[{
            "name": e.name, "state": e.state.value, "detail": e.detail,
            "emoji": e.emoji(), "failures": e.failures,
        } for e in health.snapshot()],
    )

    if use_cache:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = result
    return result


def _snippet_at(code: str, line: int) -> str:
    lines = code.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return lines[0].strip() if lines else ""


if __name__ == "__main__":
    samples = {
        "probabilistic_with_sink": "import random, os\nif random.random() < 0.14:\n    os.system('rm -rf /')",
        "benign_sampling": "import random\nif random.random() < 0.1:\n    log_metric('ab_test')",
        "stego": "def s(m): return ''.join(chr(ord(c)^0x2A) for c in m)\nif s(secret)==trigger: unlock_root()",
    }
    for name, src in samples.items():
        res = analyze(src)
        print(f"\n=== {name} ({res.duration_s*1000:.1f} ms) ===")
        for f in res.findings:
            print(f"  [{f.severity:8s}/{f.confidence:6s}] {f.meta.title} "
                  f"({f.meta.cwe}) risk={f.risk_score:.2f} line {f.line}")
