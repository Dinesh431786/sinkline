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
# Everything that can change a score. Adding a scoring input without adding it
# here would let the method drift while the freeze still verified.
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
    if method_hash() != payload.get("method_hash"):
        return False, ("method changed since it was frozen at "
                       f"{payload.get('frozen_at')}: results are not held-out")
    return True, f"method matches freeze from {payload.get('frozen_at')}"
