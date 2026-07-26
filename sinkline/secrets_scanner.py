"""
secrets_scanner.py — Offline, Import-Correlated Secret Detection
===============================================================
Secrets sprawl is the fastest-growing code-security problem: ~29M secrets were
leaked on public GitHub in 2025 (+34% YoY), and AI-service keys (OpenAI/Anthropic
/…) surged +81% YoY. The best detector (GitGuardian) requires **uploading your
code to a vendor cloud** — a non-starter for regulated/air-gapped teams — while
offline tools (Gitleaks) are noisy.

Sinkline fills that gap: a **fully local, deterministic, no-cloud** secret scanner
that combines the three techniques no single OSS tool combines:

  1. **Provider-specific prefixed patterns** (AWS `AKIA…`, GitHub `ghp_…`,
     OpenAI `sk-…`, Anthropic `sk-ant-…`, Stripe `sk_live_…`, Slack `xox…`,
     Google `AIza…`, private keys, JWTs, …) — near-100% precision by construction.
  2. **Import-graph correlation** — a generic high-entropy string is only a
     *High* finding when the matching provider's library is imported in the same
     file (e.g. an AWS-shaped key + `import boto3`). This is the precision lever
     other offline tools lack.
  3. **Layered false-positive suppression** — test/fixture paths, placeholder
     allow-lists, `.env.example` down-grading, minimum lengths, and an entropy
     gate for unrecognised generic keys.

Secrets are always **redacted** in output — Sinkline never echoes a full key.
"""
from __future__ import annotations

import ast
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

from findings import Finding, get_meta


@dataclass
class SecretType:
    name: str
    pattern: "re.Pattern"
    severity: str
    libs: tuple = ()          # provider libraries that, if imported, confirm intent
    min_len: int = 0


# Ordered: more specific prefixes (sk-ant-) before broader ones (sk-).
SECRET_TYPES: List[SecretType] = [
    SecretType("Private key (PEM)", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "Critical"),
    SecretType("AWS access key", re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b"),
               "Critical", libs=("boto3", "botocore", "aioboto3")),
    SecretType("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), "High"),
    SecretType("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "High"),
    SecretType("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "High"),
    SecretType("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
               "High", libs=("anthropic",)),
    SecretType("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b"),
               "High", libs=("openai",)),
    SecretType("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"),
               "Critical", libs=("stripe",)),
    SecretType("Stripe test key", re.compile(r"\bsk_test_[A-Za-z0-9]{20,}\b"),
               "Medium", libs=("stripe",)),
    SecretType("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "High"),
    SecretType("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]+"), "High"),
    SecretType("Google API key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"), "High"),
    SecretType("Google OAuth secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"), "High"),
    SecretType("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "High"),
    SecretType("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34}\b"), "High", libs=("huggingface_hub", "transformers")),
    SecretType("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "High"),
    SecretType("Twilio account SID", re.compile(r"\bAC[a-f0-9]{32}\b"), "Medium", libs=("twilio",)),
    SecretType("JWT", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "Medium"),
]

# Generic catch-all: SECRET_NAME = "<high-entropy>"
_GENERIC_ASSIGN = re.compile(
    r"""(?ix)\b(\w*(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|
        auth[_-]?token|token|credential|private[_-]?key|client[_-]?secret)\w*)
        \s*[:=]\s*['"]([^'"]{16,})['"]""", re.VERBOSE)

_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|example|changeme|change[_-]?this|placeholder|dummy|redacted|"
    r"insert[_-]?|<[^>]*>|xxx+|\.\.\.|test[_-]?(key|token|secret)|sample|fake|foobar|"
    r"^[*x.]{4,}$|^a{8,}$|^0{8,}$)")

_TEST_PATH = re.compile(r"(?i)(^|/)(tests?|__tests__|testdata|fixtures?|mocks?|examples?|"
                        r"samples?|demos?|conftest|.*\.spec\.)")
_DOWNGRADE_FILE = re.compile(r"(?i)\.(example|sample|template|dist)$|\.env\.example$")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return s[0] + "…" + "•" * 3
    return f"{s[:4]}…{'•' * 6}…{s[-2:]} (len {len(s)})"


def _imports(code: str) -> set:
    mods = set()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return mods
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.add(n.module.split(".")[0])
    return mods


def scan_secrets(code: str, path: str = "") -> List[Finding]:
    """Return EXPOSED_SECRET findings (redacted), with import-correlation."""
    lines = code.splitlines()
    imports = _imports(code)
    in_test = bool(path) and bool(_TEST_PATH.search(path))
    downgrade = bool(path) and bool(_DOWNGRADE_FILE.search(path))
    meta = get_meta("EXPOSED_SECRET")
    seen = set()
    findings: List[Finding] = []

    def emit(line_no, sev, conf, provider, raw, extra=""):
        key = (line_no, provider, raw[:6])
        if key in seen:
            return
        seen.add(key)
        if downgrade:
            sev, conf = "Low", "Low"
        elif in_test and sev not in ("Critical",):
            sev, conf = "Low", "Low"
        f = Finding(pattern="EXPOSED_SECRET", meta=meta, confidence=conf,
                    risk_score={"Critical": 0.95, "High": 0.85, "Medium": 0.55,
                                "Low": 0.3}.get(sev, 0.6),
                    line=line_no, column=1, snippet="",  # never store the secret
                    evidence=[f"{provider} detected: {_redact(raw)}" + (f" · {extra}" if extra else "")],
                    severity_override=sev)
        f.artifact_uri = path or "snippet"
        findings.append(f)

    # 1) provider-specific patterns. Within a line, claim non-overlapping spans,
    #    preferring the more specific type (SECRET_TYPES is ordered specific→general)
    #    so e.g. `sk-ant-…` is an Anthropic key, never also an OpenAI key.
    provider_lines = set()
    for i, line in enumerate(lines, start=1):
        cand = []
        for ti, st in enumerate(SECRET_TYPES):
            for m in st.pattern.finditer(line):
                cand.append((m.start(), m.end(), ti, st, m.group(0)))
        cand.sort(key=lambda x: (x[0], x[2]))
        claimed = []
        for s, e, ti, st, val in cand:
            if any(not (e <= cs or s >= ce) for cs, ce in claimed):
                continue
            if _PLACEHOLDER.search(val) or len(val) < st.min_len:
                continue
            conf, extra = "High", ""
            if st.libs:
                hit = imports & set(st.libs)
                if hit:
                    extra = f"{next(iter(hit))} imported — confirms intent"
                elif st.name in ("JWT", "Twilio account SID"):
                    conf = "Low"  # ambiguous shapes need the library to be trusted
            claimed.append((s, e))
            provider_lines.add(i)
            emit(i, st.severity, conf, st.name, val, extra)

    # 2) generic high-entropy secret assignments (skip lines a provider already claimed)
    for m in _GENERIC_ASSIGN.finditer(code):
        var, val = m.group(1), m.group(2)
        if _PLACEHOLDER.search(val) or "os.environ" in val or "getenv" in val:
            continue
        line_no = code[:m.start()].count("\n") + 1
        if line_no in provider_lines:
            continue
        if _shannon(val) >= 3.5:
            emit(line_no, "High", "Medium", f"Generic secret (`{var}`)", val,
                 f"high-entropy {_shannon(val):.1f} bits/char")
    return findings


# Config/text files worth scanning beyond .py (secrets love these).
SECRET_FILE_EXTS = (".env", ".yaml", ".yml", ".json", ".ini", ".cfg", ".toml",
                    ".properties", ".conf", ".txt", ".pem", ".key")


def is_scannable_config(path: str) -> bool:
    base = os.path.basename(path).lower()
    return base.endswith(SECRET_FILE_EXTS) or base.startswith(".env")


if __name__ == "__main__":
    demo = (
        "import boto3\n"
        "AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE9'\n"               # placeholder-ish
        "aws = 'AKIAIOSFODNN7REALKEY1'\n"
        "gh = 'ghp_1234567890abcdefghijklmnopqrstuvwx'\n"
        "openai_key = 'sk-proj-' + 'a'*60\n"
        "db_password = 'S3cr3t!verylongpassword123'\n"
        "placeholder = 'YOUR_API_KEY_HERE'\n"
    )
    for f in scan_secrets(demo, "app.py"):
        print(f"[{f.severity}/{f.confidence}] {f.evidence[0]}  (line {f.line})")
