"""
baselines.py — run Bandit and Semgrep for comparison
====================================================
The headline metric is *added detections over baseline*, so the baselines have
to be real runs, not remembered numbers. A tool that is not installed is
recorded as unavailable: silently treating it as "found nothing" would inflate
the added-detection count, which is the exact number being claimed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

TIMEOUT_S = 120


@dataclass
class BaselineResult:
    tool: str
    available: bool
    alerted: bool
    detail: str = ""


def _materialise(files: Dict[str, str], root: Path) -> None:
    for rel, src in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(src, encoding="utf-8", errors="replace")


def _run(tool: str, argv, files: Dict[str, str], parse) -> BaselineResult:
    if shutil.which(argv[0]) is None:
        return BaselineResult(tool, False, False, f"{argv[0]} is not available")
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _materialise(files, root)
        try:
            proc = subprocess.run(argv + [str(root)], capture_output=True,
                                  text=True, timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return BaselineResult(tool, True, False, "timed out")
        try:
            return BaselineResult(tool, True, parse(proc.stdout), "")
        except Exception as exc:
            return BaselineResult(tool, True, False, f"unparseable output: {exc}")


def run_bandit(files: Dict[str, str], binary: str = "bandit") -> BaselineResult:
    def parse(out: str) -> bool:
        data = json.loads(out or "{}")
        return any(r.get("issue_severity") in ("MEDIUM", "HIGH")
                   for r in data.get("results", []))
    return _run("bandit", [binary, "-r", "-f", "json", "-q"], files, parse)


class EmptyRuleset(Exception):
    """Semgrep ran but loaded no rules, so 'no findings' means nothing."""


def run_semgrep(files: Dict[str, str], binary: str = "semgrep",
                config: str = "p/security-audit") -> BaselineResult:
    """Run semgrep, refusing to interpret a zero-rule run as a clean result.

    Semgrep pulls its rules from a network registry. When that fetch fails it
    still exits 0 and reports `results: []` with an empty rule list, which is
    indistinguishable from a genuine clean scan unless you check. Counting that
    as a baseline miss would inflate every added-detection number this harness
    produces, so it is reported as unavailable instead.
    """
    def parse(out: str) -> bool:
        data = json.loads(out or "{}")
        if not data.get("time", {}).get("rules"):
            raise EmptyRuleset(
                "semgrep loaded 0 rules (registry unreachable?); "
                "a zero-rule scan is not evidence of anything")
        return bool(data.get("results"))

    result = _run("semgrep", [binary, "--config", config, "--json", "-q"],
                  files, parse)
    if "loaded 0 rules" in result.detail:
        return BaselineResult("semgrep", False, False,
                              "semgrep loaded 0 rules; treated as unavailable")
    return result
