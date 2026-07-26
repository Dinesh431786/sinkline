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
        if len(parts) < 4:
            continue
        version, package, label = parts[-2], parts[-3], parts[-4]
        tmp = Path(tempfile.mkdtemp(prefix="sinkline-sample-"))
        try:
            extract_sample(zip_path, tmp)
            files = read_python_files(tmp)
            if files:
                yield Sample(package, version, label, files)
                yielded += 1
        except Exception:
            continue          # a corrupt sample must not stop the run
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
