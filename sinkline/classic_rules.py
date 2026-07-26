"""
classic_rules.py — Industry-Standard Classic Vulnerability Rules
================================================================
AST-based detection for the mainstream OWASP/CWE vulnerability classes that real
SAST tools (Bandit, Semgrep, CodeQL) cover — so Sinkline is not only a
logic-bomb/obfuscation auditor but a complete Python security scanner.

Every rule is written to fire on a genuine *interpolation / dynamic / unsafe*
construct and stay quiet on the parameterised/constant-safe form, keeping false
positives low (each rule is paired with safe-variant tests in test_sinkline.py).

Coverage:
  CWE-89  SQL injection            CWE-78  command injection (shell=True/tainted)
  CWE-502 insecure deserialization CWE-798 hard-coded credentials
  CWE-327 weak hash / weak cipher  CWE-330 insufficiently random values
  CWE-918 SSRF                     CWE-22  path traversal
  CWE-295 disabled TLS validation  CWE-611 XXE
  CWE-377 insecure temp file       CWE-489 debug mode in production
  CWE-319 cleartext transmission
"""
from __future__ import annotations

import ast
import re
from typing import List

from findings import Finding, get_meta

# Names that strongly imply a secret when assigned a literal.
_SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)?|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"token|credential|private[_-]?key|client[_-]?secret)")
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)(your[_-]?|example|change[_-]?me|change[_-]?this|placeholder|dummy|redacted|"
    r"insert[_-]?|<[^>]*>|xxx+|\.\.\.|_here\b|here$|sample|fake|foobar|todo)")
_SECRETish_VALUE_OK = {"", "changeme", "password", "xxx", "none", "example",
                       "your-password", "test", "todo", "placeholder"}
_RANDOM_SECRET_NAME = re.compile(r"(?i)(token|secret|key|password|nonce|otp|salt|session)")
# A hash applied to something named like a password/credential is a High-severity
# insecure-password-storage bug (CWE-916/327), not a generic Medium weak-hash note.
_PW_NAME = re.compile(r"(?i)(^|_)(pw|pwd|pass|passwd|password|passphrase|secret|credential|token)")


def _arg_mentions_secret(call: ast.Call) -> bool:
    """True if any argument subtree references a password/credential-looking name."""
    for a in call.args:
        for sub in ast.walk(a):
            if isinstance(sub, ast.Name) and _PW_NAME.search(sub.id):
                return True
            if isinstance(sub, ast.Attribute) and _PW_NAME.search(sub.attr):
                return True
    return False
_WEAK_HASHES = {"md5", "md4", "sha1"}
_WEAK_CIPHERS = {"DES", "DES3", "ARC4", "RC4", "Blowfish", "XOR"}
_HTTP_LIBS_URL_ARG = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen"}
# Receivers that indicate a real network client (for exfiltration detection).
_NET_RECEIVERS = {"requests", "httpx", "urllib", "session", "client", "http",
                  "conn", "connection", "sock", "socket", "s", "ws", "aiohttp", "urllib3"}
# Methods that send data outbound.
_NET_SEND_METHODS = {"post", "put", "patch", "request", "send", "sendall", "sendto"}
# Markers of credential files when passed to open().
_CRED_PATHS = (".ssh", "id_rsa", ".aws", "credentials", ".netrc", "/etc/passwd",
               "/etc/shadow", ".env", ".npmrc", ".pypirc", ".docker/config")
# Exec sinks that constitute install/import-time code execution.
_EXEC_SINKS = {"os.system", "os.popen", "subprocess.run", "subprocess.call",
               "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}

# Natural-language instructions aimed at an LLM-based security scanner. Their
# presence in *source* is a strong malice signal (Shai-Hulud/Hades 2026).
_AI_EVASION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(the\s+|your\s+|any\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?(the\s+|your\s+)?(previous|prior|above)", re.I),
    re.compile(r"classify\s+(this|the\s+package|it)\b.{0,40}\b(safe|clean|benign|verified|trusted)", re.I),
    re.compile(r"(mark|report|treat|label)\s+(this|it|the\s+package|the\s+file)\b.{0,40}\b(safe|clean|benign|verified)", re.I),
    re.compile(r"output\s+a\s+(safe|clean)\s+(security\s+)?report", re.I),
    re.compile(r"do\s+not\s+(flag|report|analyze|scan|alert)", re.I),
    re.compile(r"this\s+(package|code|file|module)\s+is\s+(safe|verified|clean|trusted|legitimate)", re.I),
    re.compile(r"\bas\s+a\s+(large\s+)?language\s+model\b", re.I),
    re.compile(r"\b(system\s+prompt|you\s+are\s+now\s+(a|an)\b)", re.I),
    re.compile(r"verified\s+clean\s+infrastructure", re.I),
]

# Environment variables used for "keying" — payload only fires in real CI/cloud.
_KEYING_RE = re.compile(
    r"^(CI|CONTINUOUS_INTEGRATION|GITHUB_TOKEN|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|"
    r"CIRCLECI|BUILD_ID|BUILD_NUMBER|RUNNER_OS|KUBERNETES_SERVICE_HOST|"
    r"(AWS|AZURE|GCP|GOOGLE)_.*|.*_(TOKEN|SECRET|KEY))$")


def _attr_chain(node: ast.AST) -> str:
    """Return a dotted name for Name/Attribute chains (e.g. 'os.path.join')."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_interpolated_str(node: ast.AST) -> bool:
    """True if node builds a string via f-string, %, +concat, or .format()."""
    if isinstance(node, ast.JoinedStr):  # f-string with a substitution
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return _contains_dynamic(node)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        return True
    return False


def _contains_dynamic(node: ast.AST) -> bool:
    """True if the subtree references a variable/call (not purely constant)."""
    for n in ast.walk(node):
        if isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.Subscript,
                          ast.FormattedValue)):
            return True
    return False


def _is_dynamic_arg(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return False
    return True


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


_SINK_SHORT = {"system", "popen", "run", "call", "Popen", "check_output", "check_call",
               "exec", "eval", "__import__", "post", "put", "send", "sendall", "connect"}


def _body_has_sink(ifnode: ast.If) -> bool:
    """True if the if-body contains an exec/network sink (for env-keying gating)."""
    for n in ast.walk(ifnode):
        if isinstance(n, ast.Call):
            f = n.func
            short = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
            chain = _attr_chain(f)
            if short in {"exec", "eval", "__import__"}:
                return True
            if chain in _EXEC_SINKS:
                return True
            if short in {"post", "put", "send", "sendall"}:
                return True
    return False


class ClassicRuleVisitor(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()
        self.hits: List[tuple] = []  # (rule_key, line, confidence, evidence)
        self._scope = 0  # 0 == module top level
        self._secret_vars = set()  # vars assigned from env/credential sources
        # Packaging context => top-level exec runs at install/import time.
        self._packaging = ("setuptools" in code or "distutils" in code
                           or "setup(" in code or "__init__" in code)

    def _is_secret_source(self, value: ast.AST) -> bool:
        """True if `value` reads env vars or a credential file (light taint)."""
        for sub in ast.walk(value):
            chain = ""
            if isinstance(sub, ast.Attribute):
                chain = _attr_chain(sub)
            elif isinstance(sub, ast.Call):
                chain = _attr_chain(sub.func)
            if chain in {"os.environ", "os.getenv", "getenv"} or chain.endswith(".environ"):
                return True
            if isinstance(sub, ast.Call):
                fn = _attr_chain(sub.func) if isinstance(sub.func, ast.Attribute) else \
                    (sub.func.id if isinstance(sub.func, ast.Name) else "")
                if fn == "open" and sub.args and isinstance(sub.args[0], ast.Constant) \
                        and isinstance(sub.args[0].value, str) \
                        and any(p in sub.args[0].value for p in _CRED_PATHS):
                    return True
        return False

    def _add(self, rule_key, node, confidence, evidence, severity=None):
        # ``severity`` overrides the catalog severity for context-sensitive cases
        # (e.g. a weak hash applied to a *password* is High, not Medium).
        self.hits.append((rule_key, getattr(node, "lineno", 1), confidence, evidence, severity))

    # --- scope tracking (for install/import-time detection) --------------
    def visit_FunctionDef(self, node):
        self._scope += 1
        self.generic_visit(node)
        self._scope -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._scope += 1
        self.generic_visit(node)
        self._scope -= 1

    # --- exfiltration helpers --------------------------------------------
    def _is_network_send(self, node: ast.Call, short: str) -> bool:
        if short in {"send", "sendall", "sendto", "post", "put", "patch", "request"}:
            return True
        if short in {"get", "urlopen"} and isinstance(node.func, ast.Attribute):
            return _attr_chain(node.func).split(".")[0] in _NET_RECEIVERS or "urlopen" in short
        if short == "urlopen":
            return True
        return False

    def _carries_secret(self, node: ast.Call) -> bool:
        for sub in ast.walk(node):
            chain = ""
            if isinstance(sub, ast.Attribute):
                chain = _attr_chain(sub)
            elif isinstance(sub, ast.Call):
                chain = _attr_chain(sub.func)
            if chain in {"os.environ", "os.getenv", "environ", "getenv",
                         "os.environ.copy"} or chain.endswith(".environ"):
                return True
            if isinstance(sub, ast.Name) and (_SECRET_NAME.search(sub.id)
                                              or sub.id in self._secret_vars):
                return True
            if isinstance(sub, ast.Call) and (_attr_chain(sub.func) in {"open"} or
                    (isinstance(sub.func, ast.Name) and sub.func.id == "open")):
                if sub.args and isinstance(sub.args[0], ast.Constant) \
                        and isinstance(sub.args[0].value, str) \
                        and any(p in sub.args[0].value for p in _CRED_PATHS):
                    return True
        return False

    # --- Assignments: secrets, insecure randomness -----------------------
    def visit_Assign(self, node: ast.Assign):
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        # Light taint: remember variables that hold env vars / credential data.
        if self._is_secret_source(node.value):
            self._secret_vars.update(names)
        # Hard-coded credentials (CWE-798). The precise provider/entropy detection
        # is in secrets_scanner; here we only flag the obvious name=literal case,
        # skipping placeholders so example/template values don't false-positive.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            for nm in names:
                if _SECRET_NAME.search(nm) and len(val) >= 6 \
                        and val.strip().lower() not in _SECRETish_VALUE_OK \
                        and not _PLACEHOLDER_VALUE.search(val) \
                        and not val.startswith("${") and "os.environ" not in val:
                    self._add("HARDCODED_SECRET", node, "Medium",
                              f"`{nm}` assigned a hard-coded string literal")
                    break
        # Insecure randomness for a secret-looking target (CWE-330)
        if any(_RANDOM_SECRET_NAME.search(n) for n in names):
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Call) and _attr_chain(sub.func).startswith("random."):
                    # Predictable randomness for a secret/token/salt is High: it
                    # is already name-gated, so precision stays intact.
                    self._add("INSECURE_RANDOM", node, "High",
                              "non-cryptographic random used for a secret/token",
                              severity="High")
                    break
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # Environment keying (CWE-506 / T1480.001): dangerous action gated on a
        # CI/cloud/credential env var.
        if _body_has_sink(node) and self._test_reads_keying_env(node.test):
            self._add("ENVIRONMENT_KEYING", node, "High",
                      "dangerous action gated on a CI/cloud/credential env var")
        self.generic_visit(node)

    @staticmethod
    def _test_reads_keying_env(test: ast.AST) -> bool:
        for n in ast.walk(test):
            # os.getenv("CI") / os.environ.get("GITHUB_TOKEN")
            if isinstance(n, ast.Call):
                chain = _attr_chain(n.func)
                if chain in {"os.getenv", "os.environ.get"} and n.args \
                        and isinstance(n.args[0], ast.Constant) \
                        and isinstance(n.args[0].value, str) and _KEYING_RE.match(n.args[0].value):
                    return True
            # "GITHUB_TOKEN" in os.environ   /   os.environ["AWS_SECRET_ACCESS_KEY"]
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and _KEYING_RE.match(n.value):
                return True
        return False

    def visit_Call(self, node: ast.Call):
        name = _attr_chain(node.func)
        short = node.func.attr if isinstance(node.func, ast.Attribute) else \
            (node.func.id if isinstance(node.func, ast.Name) else "")

        # SQL injection (CWE-89): cursor.execute(f"... {x} ...")
        if short in {"execute", "executemany", "executescript"} and node.args:
            if _is_interpolated_str(node.args[0]):
                self._add("SQL_INJECTION", node, "High",
                          "interpolated string passed to SQL execute()")

        # Command injection (CWE-78)
        if name in {"subprocess.call", "subprocess.run", "subprocess.Popen",
                    "subprocess.check_output", "subprocess.check_call"} or \
           short in {"call", "run", "Popen", "check_output", "check_call"}:
            shell = _kw(node, "shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                conf = "High" if (node.args and _is_dynamic_arg(node.args[0])) else "Medium"
                self._add("COMMAND_INJECTION", node, conf, "subprocess called with shell=True")
        if name in {"os.system", "os.popen"} and node.args and _is_interpolated_str(node.args[0]):
            self._add("COMMAND_INJECTION", node, "High",
                      "interpolated command string passed to os.system/popen")

        # Credential / data exfiltration (CWE-200): secrets -> outbound network.
        if self._is_network_send(node, short) and self._carries_secret(node):
            self._add("CREDENTIAL_EXFILTRATION", node, "High",
                      "environment/secret data passed into an outbound network call")

        # Install/import-time code execution (CWE-506): top-level exec in a
        # packaging context (setup.py / __init__.py) — the supply-chain vector.
        if self._scope == 0 and self._packaging and (
                name in _EXEC_SINKS or short in {"exec", "eval", "__import__"}):
            self._add("INSTALL_HOOK", node, "High",
                      "code execution at package install/import time")

        # Insecure deserialization (CWE-502)
        if name in {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
                    "marshal.loads", "marshal.load", "dill.loads", "dill.load",
                    "shelve.open"}:
            self._add("INSECURE_DESERIALIZATION", node, "High",
                      f"untrusted deserialization via {name}")
        if name in {"yaml.load"}:
            loader = _kw(node, "Loader")
            safe = isinstance(loader, ast.Attribute) and loader.attr in {"SafeLoader", "CSafeLoader"}
            if not safe:
                self._add("INSECURE_DESERIALIZATION", node, "High",
                          "yaml.load() without SafeLoader")

        # Weak hashing (CWE-327)
        if name in {"hashlib.md5", "hashlib.sha1", "hashlib.md4"} or \
           (name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant)
                and str(node.args[0].value).lower() in _WEAK_HASHES):
            ufs = _kw(node, "usedforsecurity")
            if not (isinstance(ufs, ast.Constant) and ufs.value is False):
                if _arg_mentions_secret(node):
                    # md5/sha1 of a password == insecure credential storage (High).
                    self._add("WEAK_HASH", node, "High",
                              "weak hash (md5/sha1) used to hash a password/credential",
                              severity="High")
                else:
                    self._add("WEAK_HASH", node, "Medium",
                              "broken/weak hash algorithm for security use")

        # Disabled TLS validation (CWE-295)
        verify = _kw(node, "verify")
        if isinstance(verify, ast.Constant) and verify.value is False:
            self._add("DISABLED_CERT_VALIDATION", node, "High",
                      "TLS certificate verification disabled (verify=False)")
        if name in {"ssl._create_unverified_context"}:
            self._add("DISABLED_CERT_VALIDATION", node, "High",
                      "unverified SSL context created")

        # SSRF (CWE-918): requests/urlopen with a dynamic URL
        if short in _HTTP_LIBS_URL_ARG and node.args and _is_dynamic_arg(node.args[0]) \
                and ("request" in name or "urlopen" in name or name.startswith("requests.")
                     or name.startswith("httpx.") or name.startswith("urllib")):
            self._add("SSRF", node, "Low", "outbound request to a non-constant URL")

        # Cleartext transmission (CWE-319)
        if short in _HTTP_LIBS_URL_ARG and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) and node.args[0].value.startswith("http://") \
                and "localhost" not in node.args[0].value and "127.0.0.1" not in node.args[0].value:
            self._add("CLEARTEXT_TRANSMISSION", node, "Low", "request over cleartext http://")

        # Path traversal (CWE-22): open() with an interpolated/tainted path
        if name == "open" or short == "open":
            if node.args and _is_interpolated_str(node.args[0]):
                # A path assembled from a variable (f-string/format/concat) is a
                # real traversal risk — gate it (Medium confidence, High severity).
                self._add("PATH_TRAVERSAL", node, "Medium",
                          "file path built from interpolated/dynamic input")
            elif node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) and ".." in node.args[0].value:
                self._add("PATH_TRAVERSAL", node, "Low", "file path contains '..'")

        # XXE (CWE-611): xml parsing of potentially untrusted input.
        # defusedxml is the hardened drop-in -> never flag when it is in use.
        if "defusedxml" not in self.code and name in {
                "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
                "etree.parse", "etree.fromstring", "ET.parse", "ET.fromstring",
                "xml.dom.minidom.parse", "xml.sax.parse"}:
            if node.args and _is_dynamic_arg(node.args[0]):
                # Parsing a non-constant source (a parameter / variable) with a
                # non-hardened parser is a gate-worthy XXE exposure.
                self._add("XXE", node, "Medium",
                          "untrusted XML parsed without an XXE-hardened parser",
                          severity="High")
            else:
                self._add("XXE", node, "Low", "XML parsed without an XXE-hardened parser")

        # Insecure temp file (CWE-377)
        if name in {"tempfile.mktemp"}:
            self._add("INSECURE_TEMP_FILE", node, "Medium", "tempfile.mktemp() is race-prone")

        # Debug mode in production (CWE-489)
        if short == "run":
            debug = _kw(node, "debug")
            if isinstance(debug, ast.Constant) and debug.value is True:
                self._add("DEBUG_ENABLED", node, "Medium", "web app started with debug=True")

        self.generic_visit(node)

    # --- weak cipher via `from Crypto.Cipher import DES` -----------------
    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        if any(lib in module for lib in ("Crypto", "Cryptodome", "cryptography")):
            for alias in node.names:
                if alias.name in _WEAK_CIPHERS:
                    self._add("WEAK_CIPHER", node, "Medium", f"weak cipher {alias.name} imported")
        self.generic_visit(node)

    # --- weak cipher via attribute access (e.g. Crypto.Cipher.DES) -------
    def visit_Attribute(self, node: ast.Attribute):
        if node.attr in _WEAK_CIPHERS:
            chain = _attr_chain(node)
            if any(lib in chain for lib in ("Crypto", "Cryptodome", "cryptography", "Cipher")):
                self._add("WEAK_CIPHER", node, "Medium", f"weak cipher {node.attr}")
        self.generic_visit(node)


def _snippet(code_lines, line):
    return code_lines[line - 1].strip() if 1 <= line <= len(code_lines) else ""


def _scan_ai_evasion(code: str, lines):
    """Raw-text scan for prompt-injection aimed at AI scanners (comments included).

    Python's AST drops comments, so this must run over the raw source — which is
    exactly where the Shai-Hulud/Hades payloads hid their LLM instructions.
    """
    hits = []
    for i, line in enumerate(lines, start=1):
        for pat in _AI_EVASION_PATTERNS:
            if pat.search(line):
                hits.append(("AI_SCANNER_EVASION", i, "High",
                             f"LLM-directed instruction in source: '{line.strip()[:80]}'", None))
                break
    return hits


def scan_classic(code: str) -> List[Finding]:
    """Return classic-vulnerability findings (empty source -> empty list)."""
    lines = code.splitlines()
    hits = list(_scan_ai_evasion(code, lines))  # works even if AST parse fails
    try:
        tree = ast.parse(code)
        v = ClassicRuleVisitor(code)
        v.visit(tree)
        hits.extend(v.hits)
    except SyntaxError:
        pass
    findings: List[Finding] = []
    for rule_key, line, confidence, evidence, *rest in hits:
        sev_override = rest[0] if rest else None
        meta = get_meta(rule_key)
        eff_sev = sev_override or meta.severity
        findings.append(Finding(
            pattern=rule_key, meta=meta, confidence=confidence,
            risk_score=_risk_for(eff_sev), line=line, column=1,
            snippet=_snippet(lines, line), evidence=[evidence],
            severity_override=sev_override or "",
        ))
    return findings


def _risk_for(severity: str) -> float:
    return {"Critical": 0.9, "High": 0.75, "Medium": 0.5, "Low": 0.3, "Info": 0.1}.get(severity, 0.4)


if __name__ == "__main__":
    demo = (
        "import subprocess, hashlib, pickle, requests\n"
        "password = 'hunter2secret'\n"
        "cur.execute(f'SELECT * FROM u WHERE n={name}')\n"
        "subprocess.run(cmd, shell=True)\n"
        "hashlib.md5(data)\n"
        "pickle.loads(blob)\n"
        "requests.get(url, verify=False)\n"
    )
    for f in scan_classic(demo):
        print(f"[{f.severity:8s}/{f.confidence:6s}] {f.meta.cwe} {f.meta.title} @ line {f.line}")
