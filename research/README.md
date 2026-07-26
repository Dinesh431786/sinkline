# Evaluation harness

**These corpora are live malware.** Nothing here executes a sample: archives are
unzipped entry by entry and read as text. Do not run, import, or `pip install`
anything under `quarantine/` or `corpora/`. Expect antivirus to react to the
download.

Fetching is deliberate and manual. **Nothing downloads automatically**, because
pulling thousands of malicious packages onto a machine is a decision a person
makes, not a build step.

## What this measures

Guard surprisal detects payloads hidden behind improbable trigger conditions.
Most real supply-chain malware has **no trigger at all** — it exfiltrates on
import or in `setup.py` — and scores zero here, correctly. So the claim being
tested is narrow:

> Added detections over a Bandit/Semgrep baseline on the conditionally-triggered
> tail, at a measured false-positive cost.

`evaluate()` reports `unconditional` and `conditional_fraction` alongside the
detections so that scope is visible in the output, not just asserted in prose.

## Corpora

```bash
# Held-out test set — ~17k human-vetted samples, several GB
git clone https://github.com/DataDog/malicious-software-packages-dataset \
    research/corpora/datadog

# Development set — 174 samples from real attacks (DIMVA'20)
# https://dasfreak.github.io/Backstabbers-Knife-Collection/
```

## Two-stage protocol

1. **Develop** against the development set only.
2. **Freeze** the method:
   ```bash
   python -c "from research.freeze import write_freeze; write_freeze('research/freeze.json')"
   ```
3. **Run once** on the held-out set:
   ```bash
   python -m research.run_evaluation research/corpora/datadog --freeze research/freeze.json
   ```

Step 3 refuses to report if `guards.py`, `priors.py`, `trigger_rarity.py` or
`data/guard_priors.json` changed after the freeze. That is the entire point: it
makes tuning on the test set detectable instead of a promise.

Running without `--freeze` is allowed and prints a notice that the results are
development results, not held-out ones.

## Try it offline

`fixtures/` is a tiny synthetic corpus in the real DataDog layout, so the whole
harness can be exercised without downloading anything:

```bash
python -m research.run_evaluation research/fixtures --no-baselines
```

## Known provisional numbers

- `sinkline/data/guard_priors.json` ships with `sample_count: 0`. Its values are
  reasoned estimates, **not measurements**. Every calibrated-tier result is
  provisional until it is regenerated from a real benign corpus.
- `TRIGGER_BITS_THRESHOLD` was tuned on the 65-sample self-authored corpus,
  which is not independent evidence.

Neither should be quoted as a result.
