"""
trigger_rarity.py — how many bits of trigger guard a dangerous sink
===================================================================
The discriminator is not severity. A pattern matcher scores an unguarded
os.system and one behind `random() < 0.005 and gethostname() == 'build-07'`
identically. The distinguishing property is severity *conditioned on
improbability*, reported as bits:

    bits = -log2 P(reach sink)

Benign code reaches dangerous sinks under ordinary conditions (~0 bits). A
payload behind a rare, environment-specific trigger sits at 20+ bits, and that
structure is what a logic bomb is.

Time-based guards are reported as dormancy rather than folded into a
probability. A date is not a coin flip, and conflating the two is the easiest
thing in this method to argue against.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict

from guards import GuardedSink
from priors import prior_for

TRIGGER_BITS_THRESHOLD = 8.0     # ~1-in-256; below this, not worth reporting


@dataclass
class Surprisal:
    bits: float = 0.0
    tiers: Dict[str, int] = field(default_factory=dict)
    degraded: bool = False
    dormant: bool = False


def score(gs: GuardedSink) -> Surprisal:
    """Bits of trigger condition guarding this sink."""
    out = Surprisal(tiers={"analytic": 0, "calibrated": 0, "unknown": 0})
    total = 0.0
    for pred in gs.guards:
        if pred.kind == "date_gt" and not pred.negated:
            out.dormant = True
            continue                      # dormancy is reported, not scored
        prior = prior_for(pred)
        out.tiers[prior.tier] = out.tiers.get(prior.tier, 0) + 1
        total += -math.log2(prior.probability)
    out.bits = round(total, 2)
    # Independence is assumed here, which makes the number an upper bound.
    # Model counting replaces this when a solver is available.
    out.degraded = True
    return out
