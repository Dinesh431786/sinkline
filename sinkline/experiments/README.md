# Experiments — advanced-maths detection metrics (A/B study)

This folder preserves the evidence behind a design decision. **Nothing here is
imported by the analyzer or any production code path** — it exists so the
methodology is auditable and reproducible.

## Question

Can advanced mathematics (complex dynamics / fractals) add a *real* detection
capability to Sinkline, or is it decoration? Two ideas were prototyped and
A/B-tested against a trivial baseline over a labelled corpus (8 malicious,
8 benign snippets covering probabilistic/chained/cross-function bombs,
environment keying, anti-debug, and base64/XOR-encoded payloads).

Separation is reported as **AUC** = probability a random malicious sample scores
above a random benign one (1.0 = perfect, 0.5 = coin flip).

## Result (reproduce with `python experiments/fractal_ab_experiment.py`)

| Metric | AUC | Decision |
|---|---|---|
| Combined (baseline OR obfuscation) | **0.969** | shipped together |
| Baseline (`rareness × severity`) | 0.812 | already implicit in the analyzer |
| **Mandelbrot trigger-fragility** (escape-time sensitivity) | **0.750** | ❌ **REJECTED** |
| **Obfuscation-Index** (entropy + Higuchi fractal dimension) | 0.672* | ✅ **SHIPPED** |

\* The Obfuscation-Index intentionally fires *only* on encoded payloads (it
scores ~0 on rare-trigger bombs, which are the analyzer's job). On its own
subset (encoded vs benign) it is near-perfect; its value is being
**complementary** to the baseline — hence the combined AUC of 0.969.

## Conclusions

1. **Mandelbrot escape-time "trigger-fragility" was rejected.** It scored no
   higher than a plain `rareness × severity` baseline (0.75 vs 0.81). The
   escape-time machinery is just a nonlinear transform of those same two
   features — it adds production complexity with zero detection lift. Shipping it
   would have been hand-wavy fractal decoration.

2. **Entropy + Higuchi fractal dimension was shipped** as
   [`../obfuscation.py`](../obfuscation.py). The fractal dimension of the
   byte-entropy curve is a genuine, well-grounded signal (from binary-malware
   entropy analysis) that, combined with literal entropy and decode/exec
   context, catches the encoded-payload attack class (W4SP, telnyx-WAV,
   apicolor) that control-flow analysis alone misses.

The honest takeaway: the advanced-math win was **fractal dimension as an
obfuscation signal**, not a modified Mandelbrot equation.
