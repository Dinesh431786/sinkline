"""
findings.py — Sinkline Threat Catalog & Severity Model
=========================================================

Centralizes the industry-standard metadata for every threat Sinkline can
report, so the rest of the codebase never hard-codes severities or CWE IDs.

Two independent axes (per Bandit / OWASP guidance) are modeled separately:

  * **severity**   — potential impact *if* the finding is real
                     (Critical / High / Medium / Low), with a CVSS-style score.
  * **confidence** — probability the finding is a true positive
                     (High / Medium / Low), driven by how the detector fired.

Each pattern is mapped to the most appropriate **CWE** so output integrates
with GitHub code scanning, DefectDojo, SonarQube, etc.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Severity -> (SARIF level, representative CVSS 3.1 base score)
SEVERITY_TO_SARIF = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "none",
}
SEVERITY_TO_CVSS = {
    "Critical": 9.3,
    "High": 7.8,
    "Medium": 5.4,
    "Low": 3.1,
    "Info": 0.0,
}
CONFIDENCE_RANK = {"High": 0.9, "Medium": 0.6, "Low": 0.3}


@dataclass(frozen=True)
class ThreatMeta:
    rule_id: str
    title: str
    cwe: str            # e.g. "CWE-511"
    cwe_name: str
    severity: str       # Critical | High | Medium | Low | Info
    base_confidence: str  # High | Medium | Low
    description: str
    remediation: str
    help_uri: str = ""

    def cwe_number(self) -> str:
        return self.cwe.replace("CWE-", "")

    def cwe_uri(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe_number()}.html"


# --------------------------------------------------------------------------- #
# Threat catalog. CWE choices:
#   CWE-511 Logic/Time Bomb           — probabilistic/chained/entangled triggers
#   CWE-506 Embedded Malicious Code   — distributed / cross-function payloads
#   CWE-515 Covert Storage Channel    — steganographic data hiding
#   CWE-489 Active Debug Code / anti-analysis behaviour (closest fit)
#   CWE-78  OS Command Injection      — os.system / subprocess sinks
#   CWE-95  Eval Injection            — exec / eval
#   CWE-502 Untrusted Deserialization — pickle / marshal / yaml.load
# --------------------------------------------------------------------------- #
CATALOG: Dict[str, ThreatMeta] = {
    "PROBABILISTIC_BOMB": ThreatMeta(
        rule_id="QT.PROBABILISTIC_BOMB",
        title="Probabilistic Logic Bomb",
        cwe="CWE-511", cwe_name="Logic/Time Bomb",
        severity="High", base_confidence="Medium",
        description=(
            "A dangerous action is gated behind a low-probability random check, "
            "so the payload only fires occasionally — a classic evasion tactic "
            "to survive sandbox/CI analysis."),
        remediation=(
            "Remove randomness from security-relevant control flow. If sampling "
            "is legitimate, isolate it from privileged side effects (no os/exec)."),
    ),
    "ENTANGLED_BOMB": ThreatMeta(
        rule_id="QT.ENTANGLED_BOMB",
        title="Entangled (Multi-Condition) Logic Bomb",
        cwe="CWE-511", cwe_name="Logic/Time Bomb",
        severity="High", base_confidence="Medium",
        description=(
            "The trigger depends on several correlated/coupled conditions, hiding "
            "the true activation criteria across multiple random or stateful checks."),
        remediation=(
            "Audit every condition feeding the privileged action; collapse the "
            "coupled checks and verify none combine to form a hidden trigger."),
    ),
    "CHAINED_QUANTUM_BOMB": ThreatMeta(
        rule_id="QT.CHAINED_BOMB",
        title="Chained / Stateful Logic Bomb",
        cwe="CWE-511", cwe_name="Logic/Time Bomb",
        severity="High", base_confidence="Medium",
        description=(
            "A counter or accumulated state must reach a threshold across multiple "
            "iterations before the payload detonates (staged trigger)."),
        remediation=(
            "Trace the state variable's lifecycle; ensure no accumulated counter "
            "unlocks privileged operations after N events."),
    ),
    "CROSS_FUNCTION_QUANTUM_BOMB": ThreatMeta(
        rule_id="QT.CROSS_FUNCTION_BOMB",
        title="Cross-Function Embedded Malicious Code",
        cwe="CWE-506", cwe_name="Embedded Malicious Code",
        severity="Critical", base_confidence="Medium",
        description=(
            "Malicious logic is distributed across multiple functions so no single "
            "function looks suspicious — an interprocedural backdoor."),
        remediation=(
            "Perform interprocedural review; follow the data/control flow between "
            "the cooperating functions to expose the assembled payload."),
    ),
    "QUANTUM_STEGANOGRAPHY": ThreatMeta(
        rule_id="QT.STEGANOGRAPHY",
        title="Steganographic / Covert Data Channel",
        cwe="CWE-515", cwe_name="Covert Storage Channel",
        severity="Critical", base_confidence="Medium",
        description=(
            "Bit-level manipulation (chr/ord/xor/encode-decode) is used to hide a "
            "payload or exfiltrate data through an unobvious channel."),
        remediation=(
            "Inspect the encode/decode routine and the data it transforms; confirm "
            "it is not concealing commands, keys, or exfiltrated data."),
    ),
    "QUANTUM_ANTIDEBUG": ThreatMeta(
        rule_id="QT.ANTIDEBUG",
        title="Anti-Analysis / Anti-Debug Behaviour",
        cwe="CWE-489", cwe_name="Active Debug Code / Anti-Analysis",
        severity="Medium", base_confidence="Medium",
        description=(
            "The code attempts to detect or evade analysis (long sleeps, timing "
            "checks, debugger detection) to hide behaviour during inspection."),
        remediation=(
            "Treat anti-analysis logic as a strong indicator of malice; analyze "
            "what behaviour the code is trying to hide when observed."),
    ),
    "DANGEROUS_SINK": ThreatMeta(
        rule_id="QT.DANGEROUS_SINK",
        title="Dangerous Execution Sink",
        cwe="CWE-78", cwe_name="OS Command Injection",
        severity="High", base_confidence="High",
        description=(
            "A direct call to an OS command / code-execution sink "
            "(os.system, subprocess, exec, eval) was found."),
        remediation=(
            "Avoid shelling out; use safe APIs with argument lists and never pass "
            "untrusted input to exec/eval/os.system."),
    ),
    "OBFUSCATED_PAYLOAD": ThreatMeta(
        rule_id="QT.OBFUSCATED_PAYLOAD",
        title="Encoded / Obfuscated Payload",
        cwe="CWE-506", cwe_name="Embedded Malicious Code",
        severity="Critical", base_confidence="Medium",
        description=(
            "A high-entropy encoded blob (base64/hex/XOR byte array) is decoded "
            "and/or executed at runtime — a common way to hide a malicious payload "
            "from reviewers and signature scanners."),
        remediation=(
            "Decode the literal offline and inspect it; never pass decoded data to "
            "exec/eval. Treat runtime decode-then-execute as malicious until proven "
            "otherwise."),
    ),

    # ---------------- Classic OWASP/CWE vulnerability rules ----------------
    "SQL_INJECTION": ThreatMeta(
        rule_id="QT.SQL_INJECTION", title="SQL Injection",
        cwe="CWE-89", cwe_name="SQL Injection",
        severity="High", base_confidence="Medium",
        description="User-controlled data is concatenated/interpolated into a SQL "
                    "statement passed to execute(), allowing query manipulation.",
        remediation="Use parameterised queries / bound parameters "
                    "(cursor.execute(sql, params)); never f-string SQL."),
    "COMMAND_INJECTION": ThreatMeta(
        rule_id="QT.COMMAND_INJECTION", title="OS Command Injection",
        cwe="CWE-78", cwe_name="OS Command Injection",
        severity="High", base_confidence="Medium",
        description="A shell command is built from dynamic input or run with "
                    "shell=True, allowing arbitrary command execution.",
        remediation="Pass an argument list with shell=False; validate/allow-list "
                    "any external input."),
    "INSECURE_DESERIALIZATION": ThreatMeta(
        rule_id="QT.INSECURE_DESERIALIZATION", title="Insecure Deserialization",
        cwe="CWE-502", cwe_name="Deserialization of Untrusted Data",
        severity="High", base_confidence="High",
        description="Untrusted data is deserialized via pickle/marshal/yaml.load, "
                    "which can execute arbitrary code.",
        remediation="Use safe formats (JSON) or yaml.safe_load; never unpickle "
                    "untrusted data."),
    "HARDCODED_SECRET": ThreatMeta(
        rule_id="QT.HARDCODED_SECRET", title="Hard-coded Credentials",
        cwe="CWE-798", cwe_name="Use of Hard-coded Credentials",
        severity="High", base_confidence="Medium",
        description="A password/API key/token is embedded as a string literal in "
                    "source, exposing it to anyone with code access.",
        remediation="Load secrets from environment variables or a secrets manager; "
                    "rotate any exposed credential."),
    "WEAK_HASH": ThreatMeta(
        rule_id="QT.WEAK_HASH", title="Weak Hash Algorithm",
        cwe="CWE-327", cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
        severity="Medium", base_confidence="Medium",
        description="A broken hash (MD5/SHA1/MD4) is used in a security context.",
        remediation="Use SHA-256+ (hashlib.sha256) or a password KDF "
                    "(bcrypt/scrypt/argon2) for credentials."),
    "WEAK_CIPHER": ThreatMeta(
        rule_id="QT.WEAK_CIPHER", title="Weak Cipher",
        cwe="CWE-327", cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
        severity="Medium", base_confidence="Medium",
        description="A weak/broken cipher (DES/RC4/Blowfish/ECB) is referenced.",
        remediation="Use AES-GCM or ChaCha20-Poly1305 via a vetted library."),
    "INSECURE_RANDOM": ThreatMeta(
        rule_id="QT.INSECURE_RANDOM", title="Insufficiently Random Values",
        cwe="CWE-330", cwe_name="Use of Insufficiently Random Values",
        severity="Medium", base_confidence="Medium",
        description="The non-cryptographic `random` module is used to generate a "
                    "token/secret/key; its output is predictable.",
        remediation="Use the `secrets` module (secrets.token_hex / token_urlsafe)."),
    "SSRF": ThreatMeta(
        rule_id="QT.SSRF", title="Server-Side Request Forgery",
        cwe="CWE-918", cwe_name="Server-Side Request Forgery (SSRF)",
        severity="High", base_confidence="Low",
        description="An outbound HTTP request targets a non-constant URL, which may "
                    "be attacker-controlled and reach internal services.",
        remediation="Validate/allow-list destination hosts; block internal IP ranges."),
    "PATH_TRAVERSAL": ThreatMeta(
        rule_id="QT.PATH_TRAVERSAL", title="Path Traversal",
        cwe="CWE-22", cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
        severity="High", base_confidence="Low",
        description="A filesystem path is built from dynamic input, allowing access "
                    "outside the intended directory via '..'.",
        remediation="Normalise and confine paths (os.path.realpath + prefix check); "
                    "reject '..'."),
    "DISABLED_CERT_VALIDATION": ThreatMeta(
        rule_id="QT.DISABLED_CERT_VALIDATION", title="Disabled TLS Validation",
        cwe="CWE-295", cwe_name="Improper Certificate Validation",
        severity="High", base_confidence="High",
        description="TLS certificate verification is disabled (verify=False / "
                    "unverified SSL context), enabling man-in-the-middle attacks.",
        remediation="Never disable verification; fix the trust store / pin certs "
                    "properly instead."),
    "XXE": ThreatMeta(
        rule_id="QT.XXE", title="XML External Entity (XXE)",
        cwe="CWE-611", cwe_name="Improper Restriction of XML External Entity Reference",
        severity="Medium", base_confidence="Low",
        description="XML is parsed with a parser that may resolve external entities, "
                    "enabling file disclosure or SSRF.",
        remediation="Use defusedxml, or disable entity resolution on the parser."),
    "INSECURE_TEMP_FILE": ThreatMeta(
        rule_id="QT.INSECURE_TEMP_FILE", title="Insecure Temporary File",
        cwe="CWE-377", cwe_name="Insecure Temporary File",
        severity="Medium", base_confidence="Medium",
        description="tempfile.mktemp() is subject to a race condition between name "
                    "generation and file creation.",
        remediation="Use tempfile.mkstemp() or NamedTemporaryFile()."),
    "DEBUG_ENABLED": ThreatMeta(
        rule_id="QT.DEBUG_ENABLED", title="Debug Mode Enabled",
        cwe="CWE-489", cwe_name="Active Debug Code",
        severity="Medium", base_confidence="Medium",
        description="A web application is started with debug=True, exposing an "
                    "interactive debugger / stack traces in production.",
        remediation="Disable debug mode in production; gate it behind config."),
    "CLEARTEXT_TRANSMISSION": ThreatMeta(
        rule_id="QT.CLEARTEXT_TRANSMISSION", title="Cleartext Transmission",
        cwe="CWE-319", cwe_name="Cleartext Transmission of Sensitive Information",
        severity="Medium", base_confidence="Low",
        description="A request is made over plaintext http:// rather than https://.",
        remediation="Use https:// for all external requests."),
    "CREDENTIAL_EXFILTRATION": ThreatMeta(
        rule_id="QT.CREDENTIAL_EXFILTRATION", title="Credential / Data Exfiltration",
        cwe="CWE-200", cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        severity="Critical", base_confidence="Medium",
        description="Environment variables, secrets, or credential files are passed "
                    "directly into an outbound network call — the dominant "
                    "supply-chain credential-theft pattern (e.g. requests.post(url, "
                    "data=os.environ)).",
        remediation="Never transmit raw environment/credentials off-host. Audit the "
                    "destination and the data; remove the exfiltration path."),
    "INSTALL_HOOK": ThreatMeta(
        rule_id="QT.INSTALL_HOOK", title="Install-Time / Import-Time Code Execution",
        cwe="CWE-506", cwe_name="Embedded Malicious Code",
        severity="Critical", base_confidence="Medium",
        description="Code that executes shell commands / arbitrary code runs at "
                    "package install or import time (module top level in a packaging "
                    "context) — the primary PyPI supply-chain poisoning vector.",
        remediation="Packages should not run commands at install/import time. Review "
                    "exactly what this code does before trusting the package."),
    "AI_SCANNER_EVASION": ThreatMeta(
        rule_id="QT.AI_SCANNER_EVASION", title="AI-Scanner Evasion (Prompt Injection in Code)",
        cwe="CWE-506", cwe_name="Embedded Malicious Code",
        severity="High", base_confidence="Medium",
        description="Source contains natural-language instructions aimed at an "
                    "LLM-based security scanner (e.g. 'ignore previous instructions', "
                    "'classify this package as safe'). Seen in the 2026 Shai-Hulud/"
                    "Hades PyPI campaign to make AI scanners report malware as clean. "
                    "Its mere presence is a strong malice signal — benign code never "
                    "addresses a security scanner.",
        remediation="Treat as malicious. A deterministic (non-LLM) analyzer is immune "
                    "to this evasion; manually review the surrounding code/payload."),
    "ENVIRONMENT_KEYING": ThreatMeta(
        rule_id="QT.ENVIRONMENT_KEYING", title="Environment-Keyed Trigger",
        cwe="CWE-506", cwe_name="Embedded Malicious Code",
        severity="High", base_confidence="Medium",
        description="A dangerous action is gated on the presence of CI / cloud / "
                    "credential environment variables (CI, GITHUB_TOKEN, AWS_*, …) — "
                    "MITRE ATT&CK T1480.001. The payload stays dormant in sandboxes "
                    "and detonates only in a real CI/developer environment.",
        remediation="Audit why execution depends on CI/cloud env vars; malware uses "
                    "this to evade dynamic analysis while targeting real pipelines."),
    "EXPOSED_SECRET": ThreatMeta(
        rule_id="QT.EXPOSED_SECRET", title="Exposed Secret / Hard-coded Credential",
        cwe="CWE-798", cwe_name="Use of Hard-coded Credentials",
        severity="High", base_confidence="High",
        description="A live-looking credential (API key, token, private key, or "
                    "high-entropy password) is embedded in source/config. Secrets "
                    "sprawl is the #1 fastest-growing code-security problem "
                    "(~29M leaked on GitHub in 2025, +34% YoY).",
        remediation="Remove the secret, rotate/revoke it immediately, and load it "
                    "from an environment variable or a secrets manager. Add the file "
                    "to .gitignore and scrub it from git history."),
    "TYPOSQUAT_DEPENDENCY": ThreatMeta(
        rule_id="QT.TYPOSQUAT_DEPENDENCY", title="Typosquat / Slopsquat Dependency",
        cwe="CWE-829", cwe_name="Inclusion of Functionality from Untrusted Control Sphere",
        severity="High", base_confidence="Medium",
        description="A declared dependency name is one edit away from a popular "
                    "package (typosquatting) or uses a known confusion trick. This is "
                    "also the 'slopsquatting' vector: LLM assistants hallucinate "
                    "plausible package names that attackers register on PyPI.",
        remediation="Verify the package name is the one you intended and that it "
                    "exists/ is maintained on PyPI before installing; pin the correct "
                    "name and hash."),
}

# Fallback for any unknown rule so reporting never KeyErrors.
_UNKNOWN = ThreatMeta(
    rule_id="QT.UNKNOWN",
    title="Unknown / Generic Finding",
    cwe="CWE-693", cwe_name="Protection Mechanism Failure",
    severity="Low", base_confidence="Low",
    description="An unclassified pattern was reported by a detector.",
    remediation="Review manually.",
)


def get_meta(pattern: str) -> ThreatMeta:
    return CATALOG.get(pattern, _UNKNOWN)


@dataclass
class Finding:
    """A single, deduplicatable audit finding."""
    pattern: str
    meta: ThreatMeta
    confidence: str                  # may be elevated/lowered from base
    risk_score: float = 0.0          # 0-1 quantum risk
    line: int = 1
    column: int = 1
    snippet: str = ""
    evidence: List[str] = field(default_factory=list)
    artifact_uri: str = ""   # source file path (set when scanning files via the CLI)
    severity_override: str = ""  # per-finding severity (e.g. secrets in test files)

    @property
    def severity(self) -> str:
        return self.severity_override or self.meta.severity

    @property
    def cvss(self) -> float:
        return SEVERITY_TO_CVSS.get(self.severity, 0.0)

    def fingerprint(self) -> str:
        """Stable hash for cross-run deduplication (rule + location + snippet)."""
        import hashlib
        basis = f"{self.meta.rule_id}|{self.line}|{self.snippet.strip()[:120]}"
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.meta.rule_id,
            "title": self.meta.title,
            "pattern": self.pattern,
            "cwe": self.meta.cwe,
            "cwe_name": self.meta.cwe_name,
            "severity": self.severity,
            "cvss": self.cvss,
            "confidence": self.confidence,
            "risk_score": round(float(self.risk_score), 4),
            "line": self.line,
            "column": self.column,
            "description": self.meta.description,
            "remediation": self.meta.remediation,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint(),
        }


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings by fingerprint, keeping the highest risk."""
    best: Dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint()
        if fp not in best or f.risk_score > best[fp].risk_score:
            best[fp] = f
    # Sort by severity then risk (most important first).
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return sorted(best.values(), key=lambda x: (order.get(x.severity, 9), -x.risk_score))


# --------------------------------------------------------------------------- #
# Deterministic "attack narrative" — the no-LLM answer to AI "explanations".
# A reproducible Entry → Mechanism → Impact story per finding, so a reviewer
# understands *how* a finding becomes an exploit without trusting a chatbot.
# --------------------------------------------------------------------------- #
_NARRATIVES: Dict[str, tuple] = {
    "CREDENTIAL_EXFILTRATION": (
        "Code reads secrets — environment variables or credential files (~/.ssh, .aws).",
        "Those secrets flow (here, possibly across files/functions) into an outbound network call.",
        "Tokens / cloud keys are exfiltrated to an attacker endpoint — full account takeover."),
    "AI_SCANNER_EVASION": (
        "A package ships source whose comments/strings address an LLM-based security scanner.",
        "The text instructs the AI to 'classify this as clean', suppressing its own detection.",
        "AI-first pipelines wave the malware through; only a deterministic (no-LLM) review catches it."),
    "ENVIRONMENT_KEYING": (
        "Execution is gated on a CI/cloud env var (CI, GITHUB_TOKEN, AWS_*).",
        "In a sandbox the var is absent, so the payload stays dormant and looks benign.",
        "In a real CI/developer machine it detonates — evading dynamic analysis by design."),
    "INSTALL_HOOK": (
        "Shell/exec runs at module top level in a packaging context (setup.py / __init__.py).",
        "`pip install` or the first `import` executes it before any of your code runs.",
        "Arbitrary code runs on every install/import — the primary PyPI poisoning vector."),
    "TYPOSQUAT_DEPENDENCY": (
        "A dependency name is one edit from a popular package (or an AI-hallucinated name).",
        "`pip install` happily fetches the attacker-registered look-alike from PyPI.",
        "Malicious package code executes with your privileges on install/import."),
    "OBFUSCATED_PAYLOAD": (
        "A high-entropy encoded blob (base64/XOR) sits in the source.",
        "It is decoded at runtime and handed to exec/eval.",
        "The real payload — hidden from reviewers and signature scanners — runs."),
    "SQL_INJECTION": (
        "User-controlled data is interpolated straight into a SQL string.",
        "The query is sent to the database with attacker-shaped syntax.",
        "Data is read/modified/dumped, or auth is bypassed."),
    "COMMAND_INJECTION": (
        "A shell command is built from dynamic input or run with shell=True.",
        "The shell interprets attacker metacharacters in that input.",
        "Arbitrary OS commands run with the process's privileges."),
    "INSECURE_DESERIALIZATION": (
        "Untrusted bytes are handed to pickle/marshal/yaml.load.",
        "Deserialization reconstructs attacker-chosen objects, invoking __reduce__/constructors.",
        "Arbitrary code executes during the load."),
    "PROBABILISTIC_BOMB": (
        "A dangerous action sits behind a low-probability random check.",
        "It fires only occasionally, so sandbox/CI runs usually look clean.",
        "On some real executions the payload detonates — a stealthy logic bomb."),
}


def attack_narrative(pattern: str, meta: ThreatMeta, evidence=None) -> List[str]:
    """Return a 3-step Entry → Mechanism → Impact story for a finding."""
    steps = _NARRATIVES.get(pattern)
    if steps is None:
        steps = (
            f"A {meta.cwe} weakness ({meta.cwe_name}) is present in the code.",
            meta.description,
            "If reached by an attacker, this enables the impact above.")
    out = [f"Entry — {steps[0]}", f"Mechanism — {steps[1]}", f"Impact — {steps[2]}"]
    if evidence:
        out.append(f"Evidence — {evidence[0]}")
    return out

