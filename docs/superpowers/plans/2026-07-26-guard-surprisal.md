# Guard Surprisal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compute, for every dangerous sink, how many bits of trigger condition guard it, and report sinks hidden behind improbable triggers as a new finding.

**Architecture:** Three new modules. `guards.py` extracts the conjunction of branch conditions dominating each sink. `priors.py` maps each condition to a probability under one of three tiers (analytic / calibrated / unknown). `trigger_rarity.py` combines them into `bits = −log₂ P(reach)` and emits findings. All three are pure functions over source text, so every task is testable without corpora, network or execution.

**Tech Stack:** Python 3.11 stdlib (`ast`, `dataclasses`, `math`, `json`), existing `findings.py` / `analyzer.py`. `z3-solver` is optional and currently **not installed** — the code must work without it.

**Scope:** This plan covers the spec's §3 (components), §5 (degradation), §6 (testing) and §7 (prerequisites). The spec's §4 (evaluation harness, corpora, baselines) is a **separate plan** written after this one lands, because it depends on these interfaces being frozen and produces no working software until they are.

## Global Constraints

- Python 3.11, stdlib only for the core path. `z3` is optional; absent it, results are marked `degraded=True` and must never be reported as headline numbers.
- No machine learning. The calibration table is measured frequency stored as JSON, inspectable and regenerable.
- **Unknown predicates contribute ≈0 bits, never high bits.** This is the primary false-positive control. Any change that lets an unrecognised condition manufacture surprisal is a defect.
- Time-based guards are reported as dormancy, never folded into a probability.
- Tests live in `sinkline/test_sinkline.py` (project convention: one test file). Run with `python -m pytest test_sinkline.py -q` from `sinkline/`.
- Commit after every task. Author is the repo user; **do not add Co-Authored-By trailers.**
- The existing suite must stay green: currently 94 passed, 2 skipped.

---

### Task 1: Reconcile contradictory headline accuracy numbers

README claims 94% recall; `BENCHMARK.md` reports 100% category recall and 93.5% CI-gate recall. Two different numbers for the same tool in the same repo discredit any new claim made alongside them.

**Files:**
- Modify: `README.md`
- Modify: `sinkline/BENCHMARK.md`

- [ ] **Step 1: Regenerate the benchmark to get current ground truth**

Run: `cd sinkline && python benchmark.py`
Expected: rewrites `BENCHMARK.md`; note the exact metric values it prints.

- [ ] **Step 2: Find every accuracy claim in the README**

Run: `grep -n "94%\|100%\|recall\|false.positive\|F1" README.md`

- [ ] **Step 3: Rewrite each README claim to match BENCHMARK.md exactly**

Use the two distinct metrics by their real names — they are not interchangeable:
- "category recall" = the tool named the right threat category
- "CI-gate recall" = the tool raised a High+ finding that would fail a build

State the corpus size and that it is self-authored, in the same sentence:

```markdown
On a 65-sample self-authored corpus (31 malicious reconstructions of documented
campaigns, 34 benign hard-negatives): 100% category recall, 93.5% CI-gate recall,
0% false positives. This corpus is written by this project and is therefore not
independent evidence — see docs/superpowers/specs/2026-07-26-trigger-rarity-design.md
for the external evaluation this is being replaced with.
```

- [ ] **Step 4: Verify no stale number survives**

Run: `grep -rn "94%" README.md sinkline/BENCHMARK.md`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add README.md sinkline/BENCHMARK.md
git commit -m "docs: reconcile contradictory accuracy claims

README said 94% recall while BENCHMARK.md said 100% category and 93.5%
CI-gate. Both now quote the same regenerated numbers, name the two
recall metrics separately because they measure different things, and
state that the corpus is self-authored."
```

---

### Task 2: Rename detection categories that claim quantum content

Six categories are named for quantum mechanics but describe ordinary static analysis. `QUANTUM_STEGANOGRAPHY` detects `chr()`/XOR string building. `QUANTUM_ANTIDEBUG` detects timing checks. A reviewer reads this as overclaiming and stops there.

**Do not rename `qsim.py`, `quantum_engine.py`, or the entropy metric** — those perform genuine quantum simulation (`test_bell_state_entropy_is_ln2` verifies real math against `ln 2`). The defect is that simulation naming leaked into threat taxonomy.

**Files:**
- Modify: `sinkline/findings.py` (CATALOG keys and `rule_id` values)
- Modify: every module referencing the old names (55 occurrences)
- Modify: `sinkline/test_sinkline.py`
- Modify: `sinkline/benchmark.py` (expected-category table)

**Interfaces:**
- Produces: the renamed category strings, consumed by Task 9's CATALOG additions.

| Old | New | Why |
|---|---|---|
| `CHAINED_QUANTUM_BOMB` | `CHAINED_TRIGGER_BOMB` | it is a chain of triggers |
| `CROSS_FUNCTION_QUANTUM_BOMB` | `CROSS_FUNCTION_BOMB` | already descriptive without it |
| `QUANTUM_STEGANOGRAPHY` | `ENCODED_STRING_PAYLOAD` | it is encoded-string construction |
| `QUANTUM_ANTIDEBUG` | `ANTI_ANALYSIS_TIMING` | it is a timing check |
| `ENTANGLED_BOMB` | `CORRELATED_BOMB` | correlation, not entanglement |
| `PROBABILISTIC_BOMB` | *(unchanged)* | already accurate |

- [ ] **Step 1: Enumerate every occurrence before touching anything**

Run: `cd sinkline && grep -rn "QUANTUM_BOMB\|QUANTUM_STEGANOGRAPHY\|QUANTUM_ANTIDEBUG\|ENTANGLED_BOMB" --include=*.py --include=*.md . | tee /tmp/rename-sites.txt | wc -l`
Expected: 55.

- [ ] **Step 2: Add a test asserting the old names are gone**

```python
def test_no_quantum_named_threat_categories():
    """Quantum naming on non-quantum detections reads as overclaiming."""
    import findings
    banned = ("QUANTUM_BOMB", "QUANTUM_STEGANOGRAPHY", "QUANTUM_ANTIDEBUG",
              "ENTANGLED_BOMB")
    offenders = [k for k in findings.CATALOG
                 if any(b in k for b in banned)]
    assert not offenders, f"quantum-named categories remain: {offenders}"
    # qsim/quantum_engine perform real quantum simulation and are untouched.
    import qsim  # noqa: F401
```

- [ ] **Step 3: Run it to verify it fails**

Run: `python -m pytest test_sinkline.py::test_no_quantum_named_threat_categories -v`
Expected: FAIL listing the four offending category keys.

- [ ] **Step 4: Apply the rename across the tree**

```bash
cd sinkline
for pair in "CHAINED_QUANTUM_BOMB:CHAINED_TRIGGER_BOMB" \
            "CROSS_FUNCTION_QUANTUM_BOMB:CROSS_FUNCTION_BOMB" \
            "QUANTUM_STEGANOGRAPHY:ENCODED_STRING_PAYLOAD" \
            "QUANTUM_ANTIDEBUG:ANTI_ANALYSIS_TIMING" \
            "ENTANGLED_BOMB:CORRELATED_BOMB"; do
  old="${pair%%:*}"; new="${pair##*:}"
  grep -rl "$old" --include=*.py --include=*.md . | \
    xargs -r sed -i "s/\b$old\b/$new/g"
done
```

Note `rule_id` values embed the name (`rule_id="QT.QUANTUM_STEGANOGRAPHY"`); the `\b`-anchored substitution updates them too, which is intended — SARIF rule IDs must match the category.

- [ ] **Step 5: Verify the rename is complete and the suite is green**

Run: `grep -rn "QUANTUM_BOMB\|QUANTUM_STEGANOGRAPHY\|QUANTUM_ANTIDEBUG\|ENTANGLED_BOMB" --include=*.py --include=*.md . ; python -m pytest test_sinkline.py -q`
Expected: no grep output; 95 passed, 2 skipped.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: rename threat categories that claimed quantum content

QUANTUM_STEGANOGRAPHY detects chr()/XOR string building and
QUANTUM_ANTIDEBUG detects timing checks; neither involves quantum
computation, and the naming reads as overclaiming. qsim.py and
quantum_engine.py are untouched — they run real quantum simulation."
```

---

### Task 3: Extract the guard set dominating each sink

**Files:**
- Create: `sinkline/guards.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `GuardPredicate(kind: str, source: str, line: int, negated: bool, operands: tuple)`
  - `GuardedSink(sink_name: str, line: int, guards: tuple[GuardPredicate, ...])`
  - `extract_guards(code: str) -> list[GuardedSink]`
  - `kind` is one of: `random_lt`, `random_gt`, `randint_eq`, `env_eq`, `hostname_eq`, `platform_eq`, `date_gt`, `unknown`

- [ ] **Step 1: Write the failing tests**

```python
def test_extract_guards_finds_nested_conditions():
    from guards import extract_guards
    code = ("import os, random, socket\n"
            "if random.random() < 0.005:\n"
            "    if socket.gethostname() == 'build-07':\n"
            "        os.system('curl evil')\n")
    gs = extract_guards(code)
    assert len(gs) == 1
    assert gs[0].sink_name == "os.system"
    assert [g.kind for g in gs[0].guards] == ["random_lt", "hostname_eq"]
    assert gs[0].guards[0].operands == (0.005,)


def test_extract_guards_unguarded_sink_has_no_guards():
    from guards import extract_guards
    code = "import os\nos.system('ls')\n"
    gs = extract_guards(code)
    assert len(gs) == 1 and gs[0].guards == ()


def test_extract_guards_unrecognised_condition_is_unknown():
    from guards import extract_guards
    code = ("import os\n"
            "if some_helper(x).enabled:\n"
            "    os.system('ls')\n")
    gs = extract_guards(code)
    assert [g.kind for g in gs[0].guards] == ["unknown"]


def test_extract_guards_records_negation():
    from guards import extract_guards
    code = ("import os\n"
            "if not os.environ.get('CI'):\n"
            "    os.system('ls')\n")
    gs = extract_guards(code)
    assert gs[0].guards[0].kind == "env_eq" and gs[0].guards[0].negated is True


def test_extract_guards_survives_syntax_error():
    from guards import extract_guards
    assert extract_guards("def broken(:\n") == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k extract_guards -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'guards'`

- [ ] **Step 3: Implement `guards.py`**

```python
"""
guards.py — what conditions must hold for a dangerous sink to run
=================================================================
Sinkline already records whether a sink sits inside a guarded branch, but only
as a boolean. A boolean cannot distinguish `if debug:` from
`if random.random() < 0.005 and gethostname() == 'build-07':`, and that
distinction is the whole signal. This module recovers the actual conjunction of
conditions dominating each sink so it can be quantified.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List, Tuple

SINK_NAMES = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.Popen", "subprocess.check_output", "pickle.loads",
    "marshal.loads", "yaml.load", "exec", "eval", "__import__",
}


@dataclass(frozen=True)
class GuardPredicate:
    kind: str          # see module docs; "unknown" when unrecognised
    source: str        # rendered predicate, shown as evidence
    line: int
    negated: bool = False
    operands: Tuple = ()


@dataclass(frozen=True)
class GuardedSink:
    sink_name: str
    line: int
    guards: Tuple[GuardPredicate, ...] = ()


def _dotted(node: ast.AST) -> str:
    """Render `a.b.c` from an Attribute/Name chain, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _classify(test: ast.AST, negated: bool = False) -> List[GuardPredicate]:
    """Turn one `if` test into predicates. `and` splits into a conjunction."""
    line = getattr(test, "lineno", 1)
    src = ast.unparse(test)

    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _classify(test.operand, not negated)

    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        out: List[GuardPredicate] = []
        for v in test.values:
            out.extend(_classify(v, negated))
        return out

    def pred(kind, operands=()):
        return [GuardPredicate(kind, src, line, negated, operands)]

    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, op, right = test.left, test.ops[0], test.comparators[0]
        lname = _dotted(left.func) if isinstance(left, ast.Call) else ""

        if lname in ("random.random", "random.uniform") and isinstance(right, ast.Constant):
            if isinstance(op, ast.Lt):
                return pred("random_lt", (float(right.value),))
            if isinstance(op, ast.Gt):
                return pred("random_gt", (float(right.value),))
        if lname == "random.randint" and isinstance(op, ast.Eq) and len(left.args) == 2:
            lo, hi = left.args
            if isinstance(lo, ast.Constant) and isinstance(hi, ast.Constant):
                return pred("randint_eq", (int(lo.value), int(hi.value)))
        if lname in ("socket.gethostname", "platform.node") and isinstance(op, ast.Eq):
            return pred("hostname_eq")
        if lname in ("platform.system", "sys.platform") and isinstance(op, ast.Eq):
            return pred("platform_eq")
        if lname in ("os.environ.get", "os.getenv") and isinstance(op, ast.Eq):
            return pred("env_eq")
        if lname in ("datetime.datetime.now", "datetime.date.today", "time.time"):
            if isinstance(op, (ast.Gt, ast.GtE)):
                return pred("date_gt")

    # Bare truthiness of an env lookup: `if os.environ.get("X"):`
    if isinstance(test, ast.Call) and _dotted(test.func) in ("os.environ.get", "os.getenv"):
        return pred("env_eq")

    return pred("unknown")


class _Walker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: List[GuardPredicate] = []
        self.found: List[GuardedSink] = []

    def visit_If(self, node: ast.If) -> None:
        preds = _classify(node.test)
        self.stack.extend(preds)
        for stmt in node.body:
            self.visit(stmt)
        del self.stack[len(self.stack) - len(preds):]
        # The else-branch is guarded by the negation, which is usually the
        # common case; treat it as unguarded rather than inventing rarity.
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func) or (
            node.func.id if isinstance(node.func, ast.Name) else "")
        if name in SINK_NAMES:
            self.found.append(GuardedSink(name, getattr(node, "lineno", 1),
                                          tuple(self.stack)))
        self.generic_visit(node)


def extract_guards(code: str) -> List[GuardedSink]:
    """Every dangerous sink in `code`, with the conditions that gate it.

    Returns [] on unparseable input — a syntax error is not a finding.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    w = _Walker()
    w.visit(tree)
    return w.found
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k extract_guards -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add sinkline/guards.py sinkline/test_sinkline.py
git commit -m "feat: recover the guard conjunction dominating each sink

The existing scanner records only whether a sink is inside a guarded
branch. A boolean cannot separate 'if debug:' from a hostname-plus-
randomness trigger, which is the distinction the detector needs."
```

---

### Task 4: Analytic priors — probabilities that are exactly computable

**Files:**
- Create: `sinkline/priors.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `GuardPredicate` from Task 3.
- Produces:
  - `Prior(probability: float, tier: str)` where `tier` ∈ `{"analytic", "calibrated", "unknown"}`
  - `prior_for(pred: GuardPredicate) -> Prior`

- [ ] **Step 1: Write the failing tests**

```python
def test_analytic_priors_are_exact():
    from guards import GuardPredicate
    from priors import prior_for
    p = prior_for(GuardPredicate("random_lt", "random.random() < 0.005", 1,
                                 operands=(0.005,)))
    assert p.probability == 0.005 and p.tier == "analytic"

    q = prior_for(GuardPredicate("randint_eq", "random.randint(0, 9) == 3", 1,
                                 operands=(0, 9)))
    assert abs(q.probability - 0.1) < 1e-9 and q.tier == "analytic"


def test_negation_inverts_an_analytic_prior():
    from guards import GuardPredicate
    from priors import prior_for
    p = prior_for(GuardPredicate("random_lt", "random.random() < 0.2", 1,
                                 negated=True, operands=(0.2,)))
    assert abs(p.probability - 0.8) < 1e-9


def test_unknown_predicate_is_treated_as_common():
    """The primary false-positive control: opaque conditions never look rare."""
    from guards import GuardPredicate
    from priors import prior_for
    p = prior_for(GuardPredicate("unknown", "some_helper(x).enabled", 1))
    assert p.probability >= 0.5 and p.tier == "unknown"


def test_platform_check_is_common_not_rare():
    from guards import GuardPredicate
    from priors import prior_for
    p = prior_for(GuardPredicate("platform_eq", "platform.system() == 'Linux'", 1))
    assert p.probability >= 0.2
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "priors or predicate_is_treated or platform_check" -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'priors'`

- [ ] **Step 3: Implement `priors.py`**

```python
"""
priors.py — how likely is a guard condition to hold?
====================================================
Three tiers, and the tier travels with every answer because it is what makes
the score defensible: `random.random() < 0.005` is exactly 0.005 and needs no
defending, while an opaque environment comparison is a measured estimate.

The unknown tier is the false-positive control. An unrecognised condition must
never look rare, or every benign config check becomes a finding.
"""
from __future__ import annotations

from dataclasses import dataclass

from guards import GuardPredicate

UNKNOWN_PROBABILITY = 0.5      # deliberately common: unknown != rare
PLATFORM_PROBABILITY = 0.34    # roughly one of {Linux, Windows, Darwin}


@dataclass(frozen=True)
class Prior:
    probability: float
    tier: str          # "analytic" | "calibrated" | "unknown"


def _analytic(pred: GuardPredicate):
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
    p = _analytic(pred)
    if p is not None:
        tier = "analytic"
    elif pred.kind == "platform_eq":
        p, tier = PLATFORM_PROBABILITY, "calibrated"
    else:
        p, tier = UNKNOWN_PROBABILITY, "unknown"

    if pred.negated:
        p = 1.0 - p
    # Clamp: probability 0 would yield infinite surprisal.
    p = min(max(p, 1e-9), 1.0)
    return Prior(p, tier)
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k "priors or predicate_is_treated or platform_check" -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add sinkline/priors.py sinkline/test_sinkline.py
git commit -m "feat: analytic priors for computable guard conditions

Tier travels with every probability. An unrecognised condition resolves
to 0.5 and the unknown tier, so opaque guards can never manufacture
rarity — that is the main false-positive control."
```

---

### Task 5: Calibrated priors loaded from an inspectable table

**Files:**
- Create: `sinkline/data/guard_priors.json`
- Modify: `sinkline/priors.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `Prior`, `prior_for` from Task 4.
- Produces: `load_calibration(path: str | None = None) -> dict`, `shape_of(pred: GuardPredicate) -> str`

- [ ] **Step 1: Write the failing tests**

```python
def test_calibration_table_has_provenance():
    """A measured number with no record of what measured it is not evidence."""
    from priors import load_calibration
    table = load_calibration()
    for key in ("source_corpus", "generated", "sample_count", "shapes"):
        assert key in table, f"calibration table missing {key}"
    assert table["sample_count"] >= 0


def test_calibrated_shape_beats_unknown_default():
    from guards import GuardPredicate
    from priors import prior_for
    p = prior_for(GuardPredicate("hostname_eq", "socket.gethostname() == 'x'", 1))
    assert p.tier == "calibrated"
    assert p.probability < 0.5, "a hostname equality is rarer than the unknown default"


def test_shape_erases_literals():
    from guards import GuardPredicate
    from priors import shape_of
    a = GuardPredicate("env_eq", "os.environ.get('A') == 'x'", 1)
    b = GuardPredicate("env_eq", "os.environ.get('B') == 'y'", 1)
    assert shape_of(a) == shape_of(b) == "env_eq"
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "calibrat or shape_erases" -v`
Expected: FAIL, `ImportError: cannot import name 'load_calibration'`

- [ ] **Step 3: Create the seed table**

`sinkline/data/guard_priors.json` — seeded from reasoning, replaced by measurement in the evaluation plan. `sample_count: 0` states plainly that nothing has been measured yet.

```json
{
  "source_corpus": "seed values, not yet measured",
  "generated": "2026-07-26",
  "sample_count": 0,
  "note": "Regenerate with research/calibrate.py once the benign corpus exists. Until sample_count > 0 these are reasoned estimates and results depending on them are provisional.",
  "shapes": {
    "hostname_eq": 0.02,
    "env_eq": 0.15,
    "platform_eq": 0.34,
    "date_gt": 0.5
  }
}
```

- [ ] **Step 4: Extend `priors.py`**

Add to the imports:

```python
import json
import os
```

Add before `prior_for`:

```python
_CALIBRATION_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "data", "guard_priors.json")
_CACHE: dict = {}


def load_calibration(path: str | None = None) -> dict:
    """Load the measured prior table. Cached; falls back to an empty table."""
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
    """The predicate with its literal operands erased — what gets counted."""
    return pred.kind
```

Then replace the `elif pred.kind == "platform_eq":` branch in `prior_for` with:

```python
    else:
        shapes = load_calibration().get("shapes", {})
        if shape_of(pred) in shapes:
            p, tier = float(shapes[shape_of(pred)]), "calibrated"
        else:
            p, tier = UNKNOWN_PROBABILITY, "unknown"
```

Delete the now-unused `PLATFORM_PROBABILITY` constant from Task 4 — the value
moves into `guard_priors.json` where it can be regenerated by measurement.
Verify nothing still references it: `grep -rn PLATFORM_PROBABILITY sinkline/`
should return no output.

Also update Task 4's `test_platform_check_is_common_not_rare`: the tier is now
`"calibrated"` rather than `"unknown"`, though the probability assertion is
unchanged.

- [ ] **Step 5: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k "calibrat or shape_erases or priors or predicate_is_treated or platform_check" -v`
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add sinkline/data/guard_priors.json sinkline/priors.py sinkline/test_sinkline.py
git commit -m "feat: calibrated guard priors from an inspectable table

Shapes erase literals, because the literal is what varies between
attacks. sample_count is 0 until measured against a real benign corpus,
which states outright that these are reasoned seeds, not evidence."
```

---

### Task 6: Combine priors into surprisal, with dormancy split out

**Files:**
- Create: `sinkline/trigger_rarity.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `GuardedSink`, `extract_guards` (Task 3); `prior_for`, `Prior` (Tasks 4–5).
- Produces:
  - `Surprisal(bits: float, tiers: dict, degraded: bool, dormant: bool)`
  - `score(gs: GuardedSink) -> Surprisal`
  - `TRIGGER_BITS_THRESHOLD: float = 8.0`

- [ ] **Step 1: Write the failing tests**

```python
def test_unguarded_sink_has_zero_bits():
    from guards import extract_guards
    from trigger_rarity import score
    gs = extract_guards("import os\nos.system('ls')\n")[0]
    assert score(gs).bits == 0.0


def test_rare_trigger_yields_high_surprisal():
    from guards import extract_guards
    from trigger_rarity import score, TRIGGER_BITS_THRESHOLD
    code = ("import os, random, socket\n"
            "if random.random() < 0.005:\n"
            "    if socket.gethostname() == 'build-07':\n"
            "        os.system('curl evil')\n")
    s = score(extract_guards(code)[0])
    # -log2(0.005) ~ 7.6 bits, -log2(0.02) ~ 5.6 bits
    assert s.bits > TRIGGER_BITS_THRESHOLD
    assert s.tiers["analytic"] == 1 and s.tiers["calibrated"] == 1


def test_opaque_guards_stay_below_threshold():
    """Benign code full of unrecognised conditions must not trip the detector."""
    from guards import extract_guards
    from trigger_rarity import score, TRIGGER_BITS_THRESHOLD
    code = ("import os\n"
            "if cfg.enabled:\n"
            "    if cfg.mode == helper():\n"
            "        if other(x):\n"
            "            os.system('ls')\n")
    s = score(extract_guards(code)[0])
    assert s.bits < TRIGGER_BITS_THRESHOLD
    assert s.tiers["unknown"] == 3


def test_time_guard_is_dormancy_not_probability():
    from guards import extract_guards
    from trigger_rarity import score
    code = ("import os, datetime\n"
            "if datetime.date.today() > datetime.date(2027, 1, 1):\n"
            "    os.system('rm -rf /')\n")
    s = score(extract_guards(code)[0])
    assert s.dormant is True


def test_surprisal_is_monotone_in_guard_count():
    """Spec 6: adding an independent guard can never reduce the bit count."""
    from guards import GuardedSink, GuardPredicate
    from trigger_rarity import score
    rare = GuardPredicate("random_lt", "random.random() < 0.01", 1,
                          operands=(0.01,))
    previous = -1.0
    for n in range(1, 5):
        bits = score(GuardedSink("os.system", 1, tuple([rare] * n))).bits
        assert bits > previous, f"{n} guards scored {bits}, not above {previous}"
        previous = bits
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "surprisal or zero_bits or opaque_guards or dormancy" -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'trigger_rarity'`

- [ ] **Step 3: Implement `trigger_rarity.py`**

```python
"""
trigger_rarity.py — how many bits of trigger guard a dangerous sink
===================================================================
The discriminator is not severity. A pattern matcher scores an unguarded
os.system and one behind `random() < 0.005 and gethostname() == 'build-07'`
identically. The distinguishing property is severity *conditioned on
improbability*, reported as bits: -log2 P(reach).

Time-based guards are reported as dormancy rather than folded into a
probability, because a date is not a coin flip and conflating the two is the
easiest thing here to argue against.
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
        p = prior_for(pred)
        out.tiers[p.tier] = out.tiers.get(p.tier, 0) + 1
        total += -math.log2(p.probability)
    out.bits = round(total, 2)
    # Independence is assumed here; Task 7 replaces this with model counting
    # when z3 is available, and marks the result degraded when it is not.
    out.degraded = True
    return out
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest test_sinkline.py -k "surprisal or zero_bits or opaque_guards or dormancy" -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add sinkline/trigger_rarity.py sinkline/test_sinkline.py
git commit -m "feat: score guard surprisal in bits

Independence is assumed for now and every result is marked degraded
until model counting lands. Time guards are reported as dormancy, not
folded into a probability."
```

---

### Task 7: Model counting so correlated guards do not fabricate rarity

Two conditions on the same variable are not independent. `if x > 5: if x > 3:` multiplied naively invents surprisal that is not there. This is the most attackable part of the method, so it gets its own task and its own test.

**Files:**
- Modify: `sinkline/trigger_rarity.py`
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `Surprisal`, `score` from Task 6.
- Produces: `HAS_Z3: bool`, and `score()` sets `degraded=False` when z3 is present.

- [ ] **Step 1: Write the failing tests**

```python
def test_correlated_guards_do_not_multiply():
    """`x > 5` then `x > 3` is one constraint, not two independent ones."""
    from unittest import SkipTest
    try:
        import z3  # noqa: F401
    except ImportError:
        raise SkipTest("z3-solver not installed")
    from guards import extract_guards
    from trigger_rarity import score
    code = ("import os, random\n"
            "x = random.randint(0, 9)\n"
            "if x > 5:\n"
            "    if x > 3:\n"
            "        os.system('ls')\n")
    s = score(extract_guards(code)[0])
    assert s.bits < 2.0, f"correlated guards inflated to {s.bits} bits"


def test_degraded_flag_tracks_z3_availability():
    from guards import extract_guards
    from trigger_rarity import score, HAS_Z3
    gs = extract_guards("import os\nos.system('ls')\n")[0]
    assert score(gs).degraded is (not HAS_Z3)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "correlated_guards or degraded_flag" -v`
Expected: `test_correlated_guards_do_not_multiply` SKIPS (no z3 here); `test_degraded_flag_tracks_z3_availability` FAILS on `ImportError: cannot import name 'HAS_Z3'`.

- [ ] **Step 3: Add the z3 path**

Add near the top of `trigger_rarity.py`:

```python
try:
    import z3
    HAS_Z3 = True
except ImportError:                         # optional dependency
    HAS_Z3 = False

SOLVER_TIMEOUT_MS = 2000
```

Replace the last two lines of `score()` (`out.degraded = True` / `return out`) with:

```python
    if HAS_Z3 and gs.guards:
        counted = _model_count_bits(gs)
        if counted is not None:
            out.bits = round(counted, 2)
        out.degraded = False
    else:
        # No solver: independence is assumed, so the number is an upper bound.
        out.degraded = True
    return out


def _model_count_bits(gs: GuardedSink):
    """Bits from the joint constraint, so correlated guards count once.

    Returns None when the constraint cannot be expressed, leaving the
    independence estimate in place. Never raises: a solver problem must not
    fail the scan.
    """
    try:
        solver = z3.Solver()
        solver.set("timeout", SOLVER_TIMEOUT_MS)
        env, constraints = {}, []
        for pred in gs.guards:
            if pred.kind != "unknown":
                continue
            # Correlated integer comparisons are the case worth solving; a
            # bare `x > 5` arrives as "unknown" from guards.py.
            import ast as _ast
            node = _ast.parse(pred.source, mode="eval").body
            if not (isinstance(node, _ast.Compare) and len(node.ops) == 1):
                continue
            left, right = node.left, node.comparators[0]
            if not (isinstance(left, _ast.Name) and isinstance(right, _ast.Constant)):
                continue
            var = env.setdefault(left.id, z3.Int(left.id))
            op = node.ops[0]
            if isinstance(op, _ast.Gt):
                constraints.append(var > right.value)
            elif isinstance(op, _ast.Lt):
                constraints.append(var < right.value)
            elif isinstance(op, _ast.Eq):
                constraints.append(var == right.value)
        if not constraints:
            return None
        # Count satisfying assignments over a bounded domain; the bound keeps
        # this cheap and matches the randint ranges these guards come from.
        LO, HI = 0, 9
        for v in env.values():
            solver.add(v >= LO, v <= HI)
        solver.add(z3.And(*constraints))
        sat_count = 0
        total = (HI - LO + 1) ** max(len(env), 1)
        while solver.check() == z3.sat and sat_count < total:
            model = solver.model()
            sat_count += 1
            solver.add(z3.Or(*[v != model[v] for v in env.values()]))
        if sat_count == 0:
            return None
        return -math.log2(sat_count / total)
    except Exception:
        return None
```

- [ ] **Step 4: Run to verify**

Run: `python -m pytest test_sinkline.py -k "correlated_guards or degraded_flag" -v`
Expected: 1 passed (`degraded_flag`), 1 skipped (`correlated_guards`, no z3).

- [ ] **Step 5: Verify the z3 path actually works before trusting it**

z3 is not installed in this environment, so the correlated-guard test never runs and the code above is unexercised. Install it and run once:

Run: `pip install z3-solver && python -m pytest test_sinkline.py -k "correlated_guards" -v`
Expected: PASS. If it fails, fix `_model_count_bits` before committing — an unexercised solver path is not done.

- [ ] **Step 6: Commit**

```bash
git add sinkline/trigger_rarity.py sinkline/test_sinkline.py
git commit -m "feat: model-count correlated guards instead of multiplying

Two conditions on one variable are not independent; multiplying them
invents rarity. Falls back to the independence estimate and marks the
result degraded when z3 is absent."
```

---

### Task 8: Emit findings and wire into the analyzer

**Files:**
- Modify: `sinkline/findings.py` (two CATALOG entries)
- Modify: `sinkline/trigger_rarity.py` (add `analyze_triggers`)
- Modify: `sinkline/analyzer.py:375-420` (call it from `analyze`)
- Test: `sinkline/test_sinkline.py`

**Interfaces:**
- Consumes: `score`, `TRIGGER_BITS_THRESHOLD` (Tasks 6–7); `Finding`, `get_meta` from `findings.py`.
- Produces: `analyze_triggers(code: str) -> list[Finding]`; categories `TRIGGERED_PAYLOAD`, `DORMANT_PAYLOAD`.

- [ ] **Step 1: Write the failing tests**

```python
def test_triggered_payload_finding_reports_bits_as_evidence():
    from trigger_rarity import analyze_triggers
    code = ("import os, random, socket\n"
            "if random.random() < 0.005:\n"
            "    if socket.gethostname() == 'build-07':\n"
            "        os.system('curl evil')\n")
    fs = analyze_triggers(code)
    assert any(f.pattern == "TRIGGERED_PAYLOAD" for f in fs)
    ev = " ".join(fs[0].evidence)
    assert "bits" in ev and "random.random() < 0.005" in ev


def test_benign_code_produces_no_trigger_finding():
    from trigger_rarity import analyze_triggers
    code = ("import os\n"
            "if config.debug:\n"
            "    os.system('ls')\n")
    assert analyze_triggers(code) == []


def test_dormant_payload_reported_separately():
    from trigger_rarity import analyze_triggers
    code = ("import os, datetime\n"
            "if datetime.date.today() > datetime.date(2027, 1, 1):\n"
            "    os.system('rm -rf /')\n")
    assert any(f.pattern == "DORMANT_PAYLOAD" for f in analyze_triggers(code))


def test_analyze_surfaces_trigger_findings():
    from analyzer import analyze
    code = ("import os, random, socket\n"
            "if random.random() < 0.005:\n"
            "    if socket.gethostname() == 'build-07':\n"
            "        os.system('curl evil')\n")
    res = analyze(code, use_cache=False)
    assert any(f.pattern == "TRIGGERED_PAYLOAD" for f in res.findings)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest test_sinkline.py -k "triggered_payload or dormant_payload or benign_code_produces or analyze_surfaces" -v`
Expected: FAIL, `ImportError: cannot import name 'analyze_triggers'`

- [ ] **Step 3: Add the two CATALOG entries**

In `sinkline/findings.py`, inside `CATALOG`, after the `"DANGEROUS_SINK"` entry:

```python
    "TRIGGERED_PAYLOAD": ThreatMeta(
        rule_id="QT.TRIGGERED_PAYLOAD",
        title="Dangerous Sink Behind an Improbable Trigger",
        cwe="CWE-506", cwe_name="Embedded Malicious Code",
        severity="Critical", base_confidence="High",
        description=(
            "A dangerous sink is reachable only when conditions hold that are "
            "very unlikely in ordinary execution. Benign code reaches such "
            "sinks under common conditions; a payload hidden behind a rare "
            "trigger is the structure of a logic bomb."),
        remediation=(
            "Establish why this code path exists and what condition activates "
            "it. Rare, environment-specific triggers around an execution sink "
            "rarely have a legitimate purpose."),
    ),
    "DORMANT_PAYLOAD": ThreatMeta(
        rule_id="QT.DORMANT_PAYLOAD",
        title="Dangerous Sink Behind a Date Condition",
        cwe="CWE-511", cwe_name="Logic/Time Bomb",
        severity="High", base_confidence="Medium",
        description=(
            "A dangerous sink executes only after (or before) a specific date, "
            "so the code behaves differently over time and can pass review "
            "while remaining inert."),
        remediation=(
            "Confirm the date condition is intentional scheduling. Time-gated "
            "execution sinks are the classic time-bomb pattern."),
    ),
```

- [ ] **Step 4: Add `analyze_triggers` to `trigger_rarity.py`**

```python
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
```

- [ ] **Step 5: Call it from `analyze`**

In `sinkline/analyzer.py`, find where per-engine findings are collected in `analyze` (after the pattern-matcher block, before findings are deduped). Add:

```python
    # Guard surprisal: sinks reachable only under improbable conditions.
    try:
        from trigger_rarity import analyze_triggers
        findings.extend(analyze_triggers(code))
    except Exception:
        pass    # never let a new engine break the audit
```

Match the surrounding code's variable name for the accumulating list — read the function before editing; it may not be called `findings`.

- [ ] **Step 6: Run the new tests and the full suite**

Run: `python -m pytest test_sinkline.py -q`
Expected: all pass, 2 skipped (z3), no regressions in the existing 94.

- [ ] **Step 7: Commit**

```bash
git add sinkline/findings.py sinkline/trigger_rarity.py sinkline/analyzer.py sinkline/test_sinkline.py
git commit -m "feat: report sinks hidden behind improbable triggers

TRIGGERED_PAYLOAD carries the bit count and the guard chain as evidence
so a reviewer can check the arithmetic. Confidence drops to Low when the
score is an independence estimate rather than model-counted."
```

---

### Task 9: Confirm no regression on the existing corpus

Adding a Critical-severity category to a tool advertising a 0% false-positive rate is exactly how that rate stops being true. The 34 benign samples are the guard.

**Files:**
- Test: `sinkline/test_sinkline.py`
- Modify: `sinkline/BENCHMARK.md` (regenerated)

- [ ] **Step 1: Write the failing test**

`benchmark.BENIGN` is a list of `(name, kind, payload)` tuples, where `kind` is
`"code"` for Python source. Filter on that — the manifest entries are not source.

```python
def test_trigger_detector_adds_no_false_positives_on_benign_corpus():
    """The benign half of the corpus must stay clean after adding a Critical rule."""
    import benchmark
    from trigger_rarity import analyze_triggers
    offenders = [name for name, kind, payload in benchmark.BENIGN
                 if kind == "code" and analyze_triggers(payload)]
    assert not offenders, f"new trigger rule fires on benign samples: {offenders}"
```

- [ ] **Step 2: Run it**

Run: `python -m pytest test_sinkline.py -k trigger_detector_adds_no -v`

Expected: PASS. If it FAILS, that is a real defect in the priors, not a bad test.
Note that `random_sampling` in the benign corpus contains `random.random()` — if
it trips the rule, the cause is the guard extractor treating a non-guard use of
randomness as a trigger, and the fix belongs in `guards.py`.

Fix by correcting the offending predicate's tier or the extractor — **never by
weakening the benign sample, and never by raising the threshold until the cause
is understood.**

- [ ] **Step 3: Regenerate the benchmark**

Run: `python benchmark.py && git diff --stat sinkline/BENCHMARK.md`
Expected: malicious recall same or better; false positives still 0/34.

- [ ] **Step 4: Full suite**

Run: `python -m pytest test_sinkline.py -q`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add sinkline/test_sinkline.py sinkline/BENCHMARK.md
git commit -m "test: pin the benign corpus against the new trigger rule

A Critical-severity category is the most likely way to lose the 0%
false-positive rate, so the benign half of the corpus gates it."
```

---

## Next plan

The evaluation harness (spec §4) — corpus loaders for Backstabber's and DataDog, Bandit/Semgrep baselines, added-detections metric, frozen-artefact hashing, and the quarantine rules for handling live malware — is a separate plan, written once these interfaces are stable. It is what turns `sample_count: 0` in the calibration table into measured evidence, and it is where the actual research claim gets tested.
