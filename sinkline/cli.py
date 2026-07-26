"""
cli.py — Sinkline command-line scanner
=========================================
A CI/CD-friendly CLI so Sinkline can be used like any industry SAST tool
(Bandit/Semgrep) — no Streamlit required.

Examples:
    python cli.py scan app.py
    python cli.py scan src/ --format sarif --output sinkline.sarif
    python cli.py scan . --min-severity Medium --fail-on High

Exit codes (for pipelines):
    0  no findings at/above --fail-on
    1  usage / I/O error
    2  findings at/above --fail-on were reported
"""
from __future__ import annotations

import argparse
import os
import sys

# Allow running both as `python cli.py` and `python -m cli` from sinkline/.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import analyze                      # noqa: E402
from findings import SEVERITY_TO_CVSS             # noqa: E402
from report import json_report_string, sarif_string  # noqa: E402
from self_healing import ValidationError, health  # noqa: E402

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Reports carry arrows and check marks. Piping them on Windows (cp1252) raised
# UnicodeEncodeError *after* the scan had already finished, turning a completed
# scan into a crash and a useless exit code. Degrade the characters, not the run.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                   # pragma: no cover
        pass

# ANSI colours (auto-disabled when not a TTY).
_COLOR = sys.stdout.isatty()
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _COLOR else s
SEV_C = {"Critical": "1;37;41", "High": "1;31", "Medium": "1;33", "Low": "1;36", "Info": "0;37"}

from skiplist import SKIP_DIRS                    # noqa: E402  (shared with webapp.py)


def _iter_python_files(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


_MANIFEST_NAMES = ("pyproject.toml", "setup.py", "setup.cfg")


def _iter_manifests(path):
    if os.path.isfile(path):
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            low = f.lower()
            if f in _MANIFEST_NAMES or (low.endswith(".txt") and "require" in low):
                yield os.path.join(root, f)


def _rel(p: str) -> str:
    """relpath, but never fatal.

    On Windows os.path.relpath raises when the target and the working directory
    sit on different drives, which crashed the whole scan for a perfectly valid
    path like `sinkline scan E:\\repo` run from C:. Fall back to the absolute path.
    """
    try:
        return os.path.relpath(p)
    except ValueError:
        return os.path.abspath(p)


def _scan_path(path, use_symbolic):
    """Analyze every .py file under path; return (all_findings, files_scanned, errors).

    Runs the per-file analysis plus a package-level cross-file taint pass so that
    a secret read in one module and exfiltrated in another is caught.
    """
    all_findings = []
    files = errors = 0
    corpus = {}  # relpath -> code, for the cross-file taint pass
    for fp in _iter_python_files(path):
        files += 1
        rel = _rel(fp)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                code = fh.read()
            corpus[rel] = code
            res = analyze(code, use_symbolic=use_symbolic, use_cache=False, path=rel)
            for f in res.findings:
                if not getattr(f, "artifact_uri", ""):
                    f.artifact_uri = rel
            all_findings.extend(res.findings)
        except ValidationError as e:
            errors += 1
            print(_c("0;33", f"skip {fp}: {e}"), file=sys.stderr)
        except Exception as e:  # never let one file abort the whole scan
            errors += 1
            print(_c("0;33", f"error {fp}: {e}"), file=sys.stderr)

    # Cross-file interprocedural taint (secret source -> sink across modules).
    try:
        from taint import analyze_package
        all_findings.extend(analyze_package(corpus))
    except Exception as e:
        print(_c("0;33", f"cross-file taint skipped: {e}"), file=sys.stderr)

    # Dependency manifests: typosquat / slopsquat checks.
    try:
        from dependency_audit import audit_manifest
        for mp in _iter_manifests(path):
            try:
                with open(mp, "r", encoding="utf-8", errors="replace") as fh:
                    all_findings.extend(audit_manifest(_rel(mp), fh.read()))
            except Exception:
                pass
    except Exception as e:
        print(_c("0;33", f"dependency audit skipped: {e}"), file=sys.stderr)

    # Secrets in config/text files (.env, .yaml, .json, …) — not just .py.
    try:
        from secrets_scanner import scan_secrets, is_scannable_config
        if os.path.isdir(path):
            for root, dirs, fnames in os.walk(path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fn in fnames:
                    fpath = os.path.join(root, fn)
                    if fpath.endswith(".py") or not is_scannable_config(fpath):
                        continue
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            all_findings.extend(scan_secrets(fh.read(), _rel(fpath)))
                    except Exception:
                        pass
    except Exception as e:
        print(_c("0;33", f"secret scan (configs) skipped: {e}"), file=sys.stderr)

    # Context-awareness: findings in test/example/benchmark/docs files (incl. the
    # manifest & config passes above) drop to Low confidence so they never gate.
    try:
        from analyzer import _TEST_CONTEXT
        for f in all_findings:
            if f.confidence != "Low" and _TEST_CONTEXT.search(getattr(f, "artifact_uri", "")):
                f.confidence = "Low"
    except Exception:
        pass

    return all_findings, files, errors


def _filter(findings, min_sev):
    floor = _RANK[min_sev]
    return [f for f in findings if _RANK.get(f.severity, 0) >= floor]


def _render_text(findings, files):
    if not findings:
        return f"✓ Sinkline: no findings across {files} file(s).\n"
    out = []
    by_file = {}
    for f in findings:
        by_file.setdefault(f.artifact_uri or "snippet", []).append(f)
    for uri in sorted(by_file):
        out.append(_c("1", uri))
        for f in sorted(by_file[uri], key=lambda x: (-_RANK.get(x.severity, 0), x.line)):
            tag = _c(SEV_C.get(f.severity, "0"), f"{f.severity:8s}")
            out.append(f"  {tag} {f.meta.cwe:8s} {f.meta.title}  "
                       f"(conf {f.confidence})  line {f.line}")
            if f.evidence:
                out.append(f"           ↳ {f.evidence[0]}")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if s in counts)
    out.append("")
    out.append(_c("1", f"Summary: {len(findings)} finding(s) across {files} file(s) — {summary}"))
    return "\n".join(out) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(prog="sinkline", description="Sinkline security scanner")
    sub = p.add_subparsers(dest="command")
    sp = sub.add_parser("scan", help="scan a file or directory")
    sp.add_argument("path", help="file or directory to scan")
    sp.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    sp.add_argument("--output", "-o", help="write report to a file instead of stdout")
    sp.add_argument("--min-severity", choices=SEVERITY_ORDER, default="Low",
                    help="hide findings below this severity (default: Low)")
    sp.add_argument("--fail-on", choices=SEVERITY_ORDER, default="High",
                    help="exit code 2 if any finding is at/above this (default: High)")
    sp.add_argument("--no-symbolic", action="store_true", help="skip Z3 symbolic verification")
    sp.add_argument("--ledger", metavar="PATH",
                    help="append this scan to a tamper-evident hash-chained audit ledger")
    vp = sub.add_parser("verify-ledger", help="verify the integrity of an audit ledger")
    vp.add_argument("path", help="ledger file to verify")
    fp = sub.add_parser("fix", help="show/apply deterministic auto-fixes for a file")
    fp.add_argument("path", help="Python file to fix")
    fp.add_argument("--write", action="store_true", help="apply the fixes in place")
    args = p.parse_args(argv)

    if args.command == "verify-ledger":
        from ledger import ledger_summary, verify_ledger
        print(ledger_summary(args.path))
        ok, _ = verify_ledger(args.path)
        return 0 if ok else 2

    if args.command == "fix":
        from autofix import suggest_fixes
        if not os.path.isfile(args.path):
            print(f"file not found: {args.path}", file=sys.stderr)
            return 1
        with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
            code = fh.read()
        res = suggest_fixes(code, os.path.basename(args.path))
        if not res.count:
            print("No deterministic auto-fixes available.")
            return 0
        if args.write:
            with open(args.path, "w", encoding="utf-8") as fh:
                fh.write(res.patched)
            print(f"applied {res.count} fix(es) to {args.path}")
        else:
            sys.stdout.write(res.diff)
            print(f"\n{res.count} fix(es) available — re-run with --write to apply", file=sys.stderr)
        return 0

    if args.command != "scan":
        p.print_help()
        return 1
    if not os.path.exists(args.path):
        print(f"path not found: {args.path}", file=sys.stderr)
        return 1

    findings, files, _ = _scan_path(args.path, use_symbolic=not args.no_symbolic)
    findings = _filter(findings, args.min_severity)

    if args.format == "sarif":
        report = sarif_string(findings)
    elif args.format == "json":
        report = json_report_string(findings, extra={"files_scanned": files})
    else:
        report = _render_text(findings, files)

    # Tamper-evident audit ledger (optional): attest this exact report.
    if args.ledger:
        from ledger import append_scan
        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        rec = append_scan(args.ledger, target=args.path, summary=counts,
                          finding_count=len(findings), report_text=report)
        print(f"ledger: appended record #{rec.index} "
              f"(hash {rec.record_hash[:16]}…)" +
              (" [signed]" if rec.signature else ""), file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"wrote {args.format} report to {args.output} "
              f"({len(findings)} finding(s))", file=sys.stderr)
    else:
        sys.stdout.write(report)

    # Gate on the two-axis model: a finding breaks the build only if it is at/
    # above the severity floor AND not Low-confidence (avoids noisy CI failures).
    gate = _RANK[args.fail_on]
    return 2 if any(_RANK.get(f.severity, 0) >= gate and f.confidence != "Low"
                    for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
