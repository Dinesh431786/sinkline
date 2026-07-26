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
            # Containment check: `..` entries would otherwise write anywhere on
            # disk, which is a real technique and not a hypothetical one.
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
