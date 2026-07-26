"""
evaluate.py — measure added detections over a baseline
======================================================
The claim this harness tests is narrow on purpose: guard surprisal finds
conditionally-triggered payloads that syntactic scanners cannot, at a measured
false-positive cost. It is not a general malware detector, and most samples in
these corpora are unconditional.

Both numbers are reported, so the scope of the claim is visible in the output
rather than only in the paper.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Iterable, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sinkline"))

from guards import extract_guards                          # noqa: E402
from trigger_rarity import TRIGGER_BITS_THRESHOLD, score   # noqa: E402


def _max_bits(files: Dict[str, str]) -> float:
    """The most-hidden sink anywhere in the package."""
    best = 0.0
    for src in files.values():
        for gs in extract_guards(src):
            best = max(best, score(gs).bits)
    return best


def evaluate(samples: Iterable, baselines: bool = True) -> dict:
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
            bandit, semgrep = run_bandit(sample.files), run_semgrep(sample.files)
            if bandit.available or semgrep.available:
                base_alerted = bandit.alerted or semgrep.alerted
            # base_alerted stays None when no baseline ran; an absent tool is
            # not evidence that it would have missed the sample.
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
