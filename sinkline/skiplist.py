"""
skiplist.py — one definition of "not the user's code"
=====================================================
Dependency, build and cache directories are somebody else's source. Scanning
them buries real findings under vendored noise and inflates every file count
the UI reports.

This list was previously duplicated in cli.py, webapp.py and web/index.html and
had already drifted apart, so the CLI, the folder upload and the .zip upload
each skipped a different set. Import it here; the browser copy in
web/index.html is asserted equal by the test suite.
"""
from __future__ import annotations

SKIP_DIRS = frozenset({
    ".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache",
    ".pytest_cache", "build", "dist", ".tox", ".eggs", "site-packages",
    ".ruff_cache",
})


def is_vendored(path: str) -> bool:
    """True when any *parent* directory of `path` is a skipped directory.

    Only parents are checked: a file that happens to be named `build` is the
    user's code, a file inside `build/` is not.
    """
    return any(part in SKIP_DIRS for part in path.replace("\\", "/").split("/")[:-1])
