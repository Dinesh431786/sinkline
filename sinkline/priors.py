"""
priors.py — how likely is a guard condition to hold?
====================================================
Three tiers, and the tier travels with every answer because it is what makes
the score defensible under scrutiny:

  analytic    exact and needs no defending — `random.random() < 0.005` is 0.005
  calibrated  a measured estimate from data/guard_priors.json
  unknown     unrecognised, and therefore assumed COMMON

The unknown tier is the primary false-positive control. An unrecognised
condition must never look rare, or every benign configuration check becomes a
Critical finding. If you are tempted to make the unknown default smaller,
that is the change that will destroy the false-positive rate.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from guards import GuardPredicate

UNKNOWN_PROBABILITY = 0.5      # deliberately common: unknown != rare

_CALIBRATION_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "data", "guard_priors.json")
_CACHE: dict = {}


@dataclass(frozen=True)
class Prior:
    probability: float
    tier: str          # "analytic" | "calibrated" | "unknown"


def load_calibration(path: Optional[str] = None) -> dict:
    """Load the measured prior table. Cached; degrades to an empty table."""
    target = path or _CALIBRATION_PATH
    if target not in _CACHE:
        try:
            with open(target, encoding="utf-8") as fh:
                _CACHE[target] = json.load(fh)
        except (OSError, ValueError):
            _CACHE[target] = {"source_corpus": "unavailable", "generated": "",
                              "sample_count": 0, "shapes": {}}
    return _CACHE[target]


def shape_of(pred: GuardPredicate) -> str:
    """The predicate with its literal operands erased — what gets counted.

    The specific literal ("build-07") is exactly what varies between attacks,
    so counting whole predicates would learn nothing that generalises.
    """
    return pred.kind


def _analytic(pred: GuardPredicate) -> Optional[float]:
    if pred.kind == "random_lt" and pred.operands:
        return float(pred.operands[0])
    if pred.kind == "random_gt" and pred.operands:
        return 1.0 - float(pred.operands[0])
    if pred.kind == "randint_eq" and len(pred.operands) == 2:
        lo, hi = pred.operands
        span = hi - lo + 1
        return 1.0 / span if span > 0 else UNKNOWN_PROBABILITY
    return None


def prior_for(pred: GuardPredicate) -> Prior:
    """Probability that `pred` holds, with the tier that produced it."""
    probability = _analytic(pred)
    if probability is not None:
        tier = "analytic"
    else:
        shapes = load_calibration().get("shapes", {})
        if shape_of(pred) in shapes:
            probability, tier = float(shapes[shape_of(pred)]), "calibrated"
        else:
            probability, tier = UNKNOWN_PROBABILITY, "unknown"

    if pred.negated:
        probability = 1.0 - probability
    # Clamp: probability 0 would yield infinite surprisal.
    probability = min(max(probability, 1e-9), 1.0)
    return Prior(probability, tier)
