"""
Entry point for the evaluation.

Run as a module from the repository root, so the package-relative imports in
corpus.py and evaluate.py resolve:

    python -m research.run_evaluation research/fixtures --no-baselines
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .corpus import load_datadog
from .evaluate import evaluate
from .freeze import verify_freeze


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
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"samples             : {report['total']}")
    print(f"unconditional       : {report['unconditional']}")
    print(f"conditional fraction: {report['conditional_fraction']:.2f}")
    print(f"trigger detected    : {report['trigger_detected']}")
    print(f"added over baseline : {report['added_over_baseline']}")
    if not args.freeze:
        print("\nNOTE: no --freeze given, so these are development results, "
              "not held-out ones.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
