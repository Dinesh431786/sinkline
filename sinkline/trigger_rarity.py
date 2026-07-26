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

import ast
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from guards import GuardPredicate, GuardedSink
from priors import prior_for

try:
    import z3
    HAS_Z3 = True
except ImportError:                       # optional dependency
    HAS_Z3 = False

# 4 bits = 1-in-16. Chosen against measured data, not intuition: on the 65-sample
# corpus the guarded malicious samples score 5.64 (probabilistic_bomb, p=0.02),
# 3.32 (chained_bomb), 2.74 (env_keying) and 1.00 (cross_func_bomb) bits, while
# every benign sample scores 0. The original a-priori 8.0 (1-in-256) detected
# nothing at all.
#
# 4.0 rather than 2.0 deliberately: 2 bits is a 1-in-4 guard, and a benign A/B
# test written as `if random.random() < 0.2:` around a subprocess call would sit
# right there. The benign half of this corpus scores 0 only because none of its
# samples guard a dangerous sink, so it provides no evidence at the low end.
#
# PROVISIONAL. This is tuned on a self-authored corpus of 28 malicious code
# samples, which is not evidence. The real value comes from the held-out run
# described in docs/superpowers/specs/2026-07-26-trigger-rarity-design.md.
TRIGGER_BITS_THRESHOLD = 4.0
SOLVER_TIMEOUT_MS = 2000
# Integer guards are counted over a bounded domain. 0..9 matches the randint
# ranges these comparisons come from; a wider bound costs time and changes the
# absolute bits, not the ordering between guarded and unguarded sinks.
_DOMAIN_LO, _DOMAIN_HI = 0, 9


@dataclass
class Surprisal:
    bits: float = 0.0
    tiers: Dict[str, int] = field(default_factory=dict)
    degraded: bool = False
    dormant: bool = False


def _as_int_constraint(pred: GuardPredicate):
    """(`var`, `op`, `literal`) when the predicate is an integer comparison.

    These are the guards worth solving jointly: `x > 5` then `x > 3` is one
    constraint on one variable, and multiplying them would invent rarity that
    is not there. Returns None for anything else.
    """
    try:
        node = ast.parse(pred.source, mode="eval").body
    except SyntaxError:
        return None
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1):
        return None
    left, right = node.left, node.comparators[0]
    if not (isinstance(left, ast.Name) and isinstance(right, ast.Constant)):
        return None
    if not isinstance(right.value, int) or isinstance(right.value, bool):
        return None
    return left.id, node.ops[0], right.value


def _model_count_bits(constraints: List[tuple]) -> Optional[float]:
    """Bits from the joint constraint, so correlated guards are counted once.

    Returns None when nothing can be expressed, leaving the independence
    estimate in place. Never raises — a solver problem must not fail a scan.
    """
    try:
        solver = z3.Solver()
        solver.set("timeout", SOLVER_TIMEOUT_MS)
        env = {}
        for name, op, literal in constraints:
            var = env.setdefault(name, z3.Int(name))
            if isinstance(op, ast.Gt):
                solver.add(var > literal)
            elif isinstance(op, ast.GtE):
                solver.add(var >= literal)
            elif isinstance(op, ast.Lt):
                solver.add(var < literal)
            elif isinstance(op, ast.LtE):
                solver.add(var <= literal)
            elif isinstance(op, ast.Eq):
                solver.add(var == literal)
            elif isinstance(op, ast.NotEq):
                solver.add(var != literal)
            else:
                return None
        if not env:
            return None
        for var in env.values():
            solver.add(var >= _DOMAIN_LO, var <= _DOMAIN_HI)

        total = (_DOMAIN_HI - _DOMAIN_LO + 1) ** len(env)
        satisfying = 0
        while satisfying <= total and solver.check() == z3.sat:
            model = solver.model()
            satisfying += 1
            solver.add(z3.Or(*[v != model.eval(v, model_completion=True)
                               for v in env.values()]))
        if satisfying == 0:
            return None                   # unsatisfiable: unreachable, not rare
        return -math.log2(satisfying / total)
    except Exception:
        return None


def score(gs: GuardedSink) -> Surprisal:
    """Bits of trigger condition guarding this sink."""
    out = Surprisal(tiers={"analytic": 0, "calibrated": 0, "unknown": 0})
    # Guards split in two: integer comparisons that may be correlated and are
    # solved jointly, and everything else, which is combined independently.
    # Scoring only the solved half would silently discard the analytic bits.
    independent = 0.0
    int_constraints: List[tuple] = []
    for pred in gs.guards:
        if pred.kind == "date_gt" and not pred.negated:
            out.dormant = True
            continue                      # dormancy is reported, not scored
        prior = prior_for(pred)
        out.tiers[prior.tier] = out.tiers.get(prior.tier, 0) + 1

        constraint = _as_int_constraint(pred) if HAS_Z3 else None
        if constraint is not None:
            int_constraints.append(constraint)
        else:
            independent += -math.log2(prior.probability)

    joint = _model_count_bits(int_constraints) if int_constraints else None
    if joint is None:
        # Nothing solvable: fall back to treating those guards independently.
        for pred in gs.guards:
            if _as_int_constraint(pred) is not None and HAS_Z3:
                independent += -math.log2(prior_for(pred).probability)

    out.bits = round(independent + (joint or 0.0), 2)
    # degraded means no solver was available, so wherever guards existed their
    # combination assumed independence and the bit count is an upper bound.
    out.degraded = not HAS_Z3
    return out


def analyze_triggers(code: str):
    """Findings for sinks hidden behind improbable or time-based triggers."""
    from findings import Finding, get_meta
    from guards import extract_guards

    out = []
    for gs in extract_guards(code):
        s = score(gs)
        if s.dormant:
            out.append(Finding(
                pattern="DORMANT_PAYLOAD", meta=get_meta("DORMANT_PAYLOAD"),
                confidence="Medium", line=gs.line, snippet=gs.sink_name,
                evidence=[f"{gs.sink_name} runs only past a date condition",
                          *[g.source for g in gs.guards]],
            ))
        if s.bits >= TRIGGER_BITS_THRESHOLD:
            out.append(Finding(
                pattern="TRIGGERED_PAYLOAD", meta=get_meta("TRIGGERED_PAYLOAD"),
                confidence="Low" if s.degraded else "High",
                risk_score=min(s.bits / 32.0, 1.0),
                line=gs.line, snippet=gs.sink_name,
                evidence=[
                    f"{gs.sink_name} is behind {s.bits} bits of trigger condition"
                    + (" (estimated: no solver available)" if s.degraded else ""),
                    *[g.source for g in gs.guards],
                ],
            ))
    return out
