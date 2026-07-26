"""
dependency_audit.py — Typosquat / Slopsquat / Dependency-Confusion Detection
============================================================================
Scans dependency manifests (requirements*.txt, pyproject.toml, setup.py/.cfg)
for package names that are *almost* a popular package — the typosquatting and
"slopsquatting" (AI-hallucinated package name) supply-chain vector. LLM coding
assistants invent plausible-but-nonexistent names (~20% of suggestions in one
USENIX'25 study); attackers register them. ``pip`` gives no warning and no
mainstream SAST tool checks name plausibility.

Fully **offline and deterministic**: it compares against a bundled list of
popular PyPI package names using PyPI's own name-normalization
(`-`, `_`, `.` are equivalent, case-insensitive) so legitimate spellings like
``python-dateutil`` are never flagged. It only raises when a name is
edit-distance 1 from a popular package (a very strong typosquat signal) or uses
the documented ``python-<pkg>`` confusion trick.
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from findings import Finding, get_meta

# A curated set of widely-used PyPI packages (PyPI-normalized: lowercase, [-_.]→-).
_POPULAR = {
    "requests", "urllib3", "setuptools", "certifi", "charset-normalizer", "idna",
    "numpy", "pandas", "python-dateutil", "six", "pyyaml", "packaging", "boto3",
    "botocore", "s3transfer", "typing-extensions", "wheel", "pip", "cryptography",
    "click", "jinja2", "markupsafe", "werkzeug", "flask", "fastapi", "starlette",
    "pydantic", "pydantic-core", "sqlalchemy", "scipy", "matplotlib", "pillow",
    "scikit-learn", "torch", "tensorflow", "keras", "transformers", "tokenizers",
    "huggingface-hub", "aiohttp", "attrs", "multidict", "yarl", "frozenlist",
    "websockets", "httpx", "httpcore", "anyio", "sniffio", "h11", "redis", "celery",
    "gunicorn", "uvicorn", "django", "djangorestframework", "pytz", "asgiref",
    "sqlparse", "psycopg2", "psycopg2-binary", "pymongo", "pymysql", "elasticsearch",
    "protobuf", "grpcio", "google-auth", "google-cloud-storage", "cachetools",
    "rsa", "oauthlib", "requests-oauthlib", "pyjwt", "cffi", "pycparser", "bcrypt",
    "paramiko", "pynacl", "docker", "kubernetes", "ansible", "jsonschema", "zipp",
    "importlib-metadata", "tomli", "tomlkit", "platformdirs", "filelock", "virtualenv",
    "tox", "pytest", "pluggy", "iniconfig", "coverage", "mock", "faker", "hypothesis",
    "black", "flake8", "pycodestyle", "pyflakes", "isort", "mypy", "pylint", "astroid",
    "bandit", "safety", "pre-commit", "rich", "pygments", "colorama", "tqdm",
    "tabulate", "prompt-toolkit", "typer", "docutils", "sphinx", "babel",
    "beautifulsoup4", "soupsieve", "lxml", "html5lib", "markdown", "bleach",
    "openpyxl", "xlrd", "xlsxwriter", "pyarrow", "dask", "numba", "sympy", "mpmath",
    "networkx", "joblib", "statsmodels", "seaborn", "plotly", "bokeh", "dash",
    "gitpython", "pygithub", "wrapt", "pyparsing", "decorator", "future", "toml",
    "jmespath", "python-dotenv", "marshmallow", "gevent", "greenlet", "eventlet",
    "dnspython", "chardet", "sortedcontainers", "ujson", "orjson", "msgpack",
    "cython", "pybind11", "poetry", "poetry-core", "build", "twine", "keyring",
    "requests-toolbelt", "openai", "anthropic", "langchain", "tiktoken", "regex",
    "nltk", "spacy", "gensim", "opencv-python", "imageio", "scikit-image", "pyopenssl",
}

_MANIFESTS = ("requirements", "pyproject.toml", "setup.py", "setup.cfg",
              "pipfile", "constraints")


def normalize(name: str) -> str:
    """PyPI canonical name normalization (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _levenshtein_le1(a: str, b: str) -> bool:
    """True if edit distance between a and b is <= 1 (cheap, no full DP)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if a == b:
        return True
    # find first differing position
    i = 0
    while i < min(la, lb) and a[i] == b[i]:
        i += 1
    if la == lb:                       # one substitution
        return a[i + 1:] == b[i + 1:]
    if la < lb:                        # one insertion into a
        return a[i:] == b[i + 1:]
    return a[i + 1:] == b[i:]          # one deletion from a


def classify_name(name: str):
    """Return (reason, popular_target) if the name is risky, else None."""
    norm = normalize(name)
    if not norm or norm in _POPULAR:
        return None
    # python-<popular> / <popular>-python confusion trick
    for p in _POPULAR:
        if norm == f"python-{p}" or norm == f"{p}-python":
            return ("uses the 'python-<pkg>' confusion trick mimicking", p)
    # edit-distance 1 to a popular package
    for p in _POPULAR:
        if _levenshtein_le1(norm, p):
            return ("is one character away from the popular package", p)
    return None


# --- manifest parsing ------------------------------------------------------ #
def _names_from_requirements(text: str) -> List[Tuple[str, int]]:
    out = []
    for i, line in enumerate(text.splitlines(), start=1):
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith(("-", "git+", "http://", "https://", "file:")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", s)
        if m:
            out.append((m.group(1), i))
    return out


def _names_from_pyproject(text: str) -> List[Tuple[str, int]]:
    names = []
    # PEP 621 [project] dependencies + optional, and poetry [tool.poetry.dependencies]
    try:
        import tomllib
        data = tomllib.loads(text)
        deps = list(data.get("project", {}).get("dependencies", []) or [])
        for grp in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
            deps.extend(grp or [])
        poetry = data.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies"):
            deps.extend((poetry.get(section, {}) or {}).keys())
        specs = deps
    except Exception:
        specs = re.findall(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[].*)?["\']', text)
    out = []
    lines = text.splitlines()
    for spec in specs:
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(spec))
        if not m or m.group(1).lower() == "python":
            continue
        name = m.group(1)
        line = next((i for i, ln in enumerate(lines, 1) if name in ln), 1)
        out.append((name, line))
    return out


def _names_from_setup(text: str) -> List[Tuple[str, int]]:
    names = re.findall(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[].*?)?["\']', text)
    lines = text.splitlines()
    out = []
    for n in names:
        if n.lower() in {"python", "utf-8", "utf8"}:
            continue
        line = next((i for i, ln in enumerate(lines, 1) if n in ln), 1)
        out.append((n, line))
    return out


def is_manifest(path: str) -> bool:
    base = os.path.basename(path).lower()
    return base.endswith(".txt") and "require" in base or base in (
        "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "constraints.txt")


def _parse(path: str, text: str) -> List[Tuple[str, int]]:
    base = os.path.basename(path).lower()
    if base == "pyproject.toml":
        return _names_from_pyproject(text)
    if base in ("setup.py", "setup.cfg"):
        return _names_from_setup(text)
    return _names_from_requirements(text)


def audit_manifest(path: str, text: str) -> List[Finding]:
    """Return TYPOSQUAT_DEPENDENCY findings for a manifest's declared packages."""
    findings: List[Finding] = []
    seen = set()
    for name, line in _parse(path, text):
        key = normalize(name)
        if key in seen:
            continue
        seen.add(key)
        verdict = classify_name(name)
        if verdict is None:
            continue
        reason, target = verdict
        meta = get_meta("TYPOSQUAT_DEPENDENCY")
        f = Finding(
            pattern="TYPOSQUAT_DEPENDENCY", meta=meta, confidence="High",
            risk_score=0.8, line=line, column=1, snippet=name,
            evidence=[f"dependency '{name}' {reason} '{target}' — likely "
                      f"typosquat / AI-hallucinated (slopsquat) name"],
        )
        f.artifact_uri = path
        findings.append(f)
    return findings


if __name__ == "__main__":
    sample = "requests==2.31.0\nrequsts\nnumpyy>=1.0\npython-requests\nflask\nmy-internal-lib\n"
    for f in audit_manifest("requirements.txt", sample):
        print(f"[{f.severity}/{f.confidence}] line {f.line}: {f.evidence[0]}")
