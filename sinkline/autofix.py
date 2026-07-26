"""
autofix.py — Deterministic, No-LLM Remediation
==============================================
The honest answer to "AI fixes your code": for the vulnerability classes where
the correct fix is *unambiguous*, Sinkline produces a reproducible patch — a real
unified diff — with no LLM, so it can never hallucinate a broken fix and the same
input always yields the same patch. Findings whose fix needs human judgement
(SQLi, command injection) are returned as guidance, never silently rewritten.

Auto-applicable rewrites (safe, behaviour-preserving for the secure intent):
  * hashlib.md5/sha1/md4(...)        -> hashlib.sha256(...)        (CWE-327)
  * verify=False                     -> verify=True               (CWE-295)
  * ssl._create_unverified_context() -> ssl.create_default_context()
  * yaml.load(...)                   -> yaml.safe_load(...)        (CWE-502)
  * tempfile.mktemp(...)             -> tempfile.mkstemp(...)      (CWE-377)
  * <web>.run(..., debug=True)       -> debug=False               (CWE-489)
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class Rewrite:
    rule: str
    pattern: "re.Pattern"
    repl: str
    title: str
    guard: Optional[Callable[[str], bool]] = None  # line-level precondition


_REWRITES: List[Rewrite] = [
    Rewrite("WEAK_HASH", re.compile(r"\bhashlib\.(md5|sha1|md4)\s*\("),
            "hashlib.sha256(", "Use SHA-256 instead of a broken hash"),
    Rewrite("DISABLED_CERT_VALIDATION", re.compile(r"\bverify\s*=\s*False\b"),
            "verify=True", "Re-enable TLS certificate verification"),
    Rewrite("DISABLED_CERT_VALIDATION", re.compile(r"\bssl\._create_unverified_context\s*\("),
            "ssl.create_default_context(", "Use a verified SSL context"),
    Rewrite("INSECURE_DESERIALIZATION", re.compile(r"\byaml\.load\s*\("),
            "yaml.safe_load(", "Use yaml.safe_load"),
    Rewrite("INSECURE_TEMP_FILE", re.compile(r"\btempfile\.mktemp\s*\("),
            "tempfile.mkstemp(", "Use the race-safe tempfile.mkstemp"),
    Rewrite("DEBUG_ENABLED", re.compile(r"\bdebug\s*=\s*True\b"),
            "debug=False", "Disable debug mode in production",
            guard=lambda ln: ".run(" in ln),
]


@dataclass
class Fix:
    rule: str
    line: int
    title: str
    before: str
    after: str

    def to_dict(self) -> dict:
        return {"rule": self.rule, "line": self.line, "title": self.title,
                "before": self.before, "after": self.after}


@dataclass
class FixResult:
    fixes: List[Fix] = field(default_factory=list)
    patched: str = ""
    diff: str = ""

    @property
    def count(self) -> int:
        return len(self.fixes)

    def to_dict(self) -> dict:
        return {"count": self.count, "fixes": [f.to_dict() for f in self.fixes],
                "patched": self.patched, "diff": self.diff}


def suggest_fixes(code: str, filename: str = "snippet.py") -> FixResult:
    """Return deterministic auto-fixes (line-accurate) + a unified diff."""
    original_lines = code.splitlines()
    patched_lines = []
    fixes: List[Fix] = []
    for i, line in enumerate(original_lines, start=1):
        new = line
        for rw in _REWRITES:
            if rw.guard and not rw.guard(new):
                continue
            if rw.pattern.search(new):
                candidate = rw.pattern.sub(rw.repl, new)
                if candidate != new:
                    fixes.append(Fix(rule=rw.rule, line=i, title=rw.title,
                                     before=line.strip(), after=candidate.strip()))
                    new = candidate
        patched_lines.append(new)

    patched = "\n".join(patched_lines)
    if code.endswith("\n"):
        patched += "\n"
    diff = ""
    if fixes:
        diff = "".join(difflib.unified_diff(
            [l + "\n" for l in original_lines],
            [l + "\n" for l in patched_lines],
            fromfile=f"a/{filename}", tofile=f"b/{filename}", lineterm="\n"))
    return FixResult(fixes=fixes, patched=patched, diff=diff)


if __name__ == "__main__":
    sample = (
        "import hashlib, yaml, tempfile, requests\n"
        "h = hashlib.md5(data)\n"
        "cfg = yaml.load(stream)\n"
        "tmp = tempfile.mktemp()\n"
        "r = requests.get(url, verify=False)\n"
        "app.run(debug=True)\n"
        "x = some.debug = True\n"  # must NOT be touched (no .run on line)
    )
    res = suggest_fixes(sample)
    print(f"{res.count} auto-fixes:")
    for f in res.fixes:
        print(f"  L{f.line} [{f.rule}] {f.before}  ->  {f.after}")
    print("\n--- diff ---\n" + res.diff)
