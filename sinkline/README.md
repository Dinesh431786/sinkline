# Sinkline — Deterministic, Local Python Security Scanner

> **On the name:** a *sink* is where dangerous data lands — `os.system`, `requests.post`,
> `exec`. Sinkline draws the line from the **source** (a secret, an env var, user input)
> to that sink, across files. That line is the product.
>
> One *auxiliary* risk-scoring channel is quantum-*inspired* (a tiny pure-NumPy
> state-vector sim + information entropy). It does **not** drive detection and needs no
> quantum hardware. The real work is taint, OWASP/CWE rules, secrets, and obfuscation.

**Local-native, air-gapped Python source-code security scanner** that hunts the
threats ordinary SAST tools miss: probabilistic logic bombs, chained/stateful
triggers, cross-function backdoors, covert/steganographic channels, and
anti-analysis evasion — the exact techniques seen in 2024–2026 PyPI supply-chain
attacks (aiocpa, W4SP, Hades/Shai-Hulud, LiteLLM/TeamPCP, telnyx).

Everything runs **entirely on your hardware**. No code ever leaves the machine.

```bash
pip install -r requirements.txt
python webapp.py        # web UI on http://127.0.0.1:8000  (stdlib only)
# or:  python cli.py scan path/to/code
```

---

## Why it's different

| Capability | How Sinkline does it |
|---|---|
| **Accurate, low false positives** | Sink-aware confidence scoring. A `random.random() < x` check is only high-confidence when a real execution/exfiltration **sink** sits in the guarded branch — benign sampling drops to *Low*. Two independent axes (severity × confidence), per Bandit/OWASP guidance. |
| **Lightweight & fast** | Custom **pure-NumPy quantum-inspired simulator** (`qsim.py`) replaces the heavyweight `cirq` dependency — ~10× faster import, a few KB instead of hundreds of MB, identical math (validated against cirq). Content-hash caching skips re-analysis. Typical audit: tens of milliseconds. |
| **Provably sound** | Z3 **symbolic reachability** proves whether a sink is actually reachable. Stateful counters are modelled as accumulators of optional increments, so `if k == 99` with one `k += 1` is correctly proven *unreachable* (no false "proof"). |
| **Self-healing** | Every engine runs behind `@resilient` / circuit breakers. A failing or missing engine degrades and is recorded in a health panel — the audit never crashes. Input is validated/sanitised (size limits, NUL stripping). |
| **Industry standard output** | **SARIF 2.1.0** with a proper CWE `taxonomies` block + rule `relationships` + `partialFingerprints` for dedup (consumable by GitHub Code Scanning, DefectDojo, SonarQube), plus a flat JSON report. Every finding is CWE-mapped with a CVSS-style score. |

---

## Architecture

```
                    +------------------------------+
   Python source -> |        analyzer.py           |  <- unified orchestrator
                    |  validate -> detect -> score  |     (self-healing)
                    +------+-----------+-----------+
        +------------------+-----------+--------------------+
        v                  v           v                    v
 pattern_matcher    sink scanner   quantum_engine      symbolic_engine
  (taint/AST)       (AST sinks +   (qsim.py: NumPy     (Z3 reachability,
                    line numbers)   state-vector,       sound counters)
                                    Von Neumann entropy)
        +------------------+-----------+--------------------+
                                v
                  findings.py  (CWE + severity + confidence)
                                v
                  report.py  ->  SARIF 2.1.0  /  JSON
                                v
              webapp.py (web UI)  /  cli.py (CLI)
```

### Module map
- **`cli.py`** — command-line scanner (file/dir → text/JSON/SARIF, CI exit codes).
- **`taint.py`** — cross-file interprocedural taint (secret source → sink across modules).
- **`dependency_audit.py`** — typosquat / slopsquat / dependency-confusion checks on manifests.
- **`secrets_scanner.py`** — offline secrets detection (provider patterns + import correlation, redacted).
- **`autofix.py`** — deterministic, no-LLM auto-fix (unified diff for unambiguous issues).
- **`ledger.py`** — tamper-evident, hash-chained audit ledger (optional HMAC signing).
- **`classic_rules.py`** — classic OWASP/CWE SAST rules (SQLi, command injection, etc.).
- **`tool_comparison.py`** — head-to-head harness vs. Bandit & Semgrep on the same corpus (`benchmark.py --compare`).
- **`obfuscation.py`** — encoded-payload detector (entropy + Higuchi fractal dimension).
- **`qsim.py`** — lightweight pure-NumPy quantum simulator (RY/H/X/CNOT + sampling).
- **`quantum_engine.py`** — pattern->circuit mapping, Von Neumann entropy, physics metrics, risk scoring.
- **`pattern_matcher.py`** — taint-based AST pattern detection.
- **`analyzer.py`** — sink-aware orchestrator; the custom detection algorithm.
- **`symbolic_engine.py`** — Z3 symbolic reachability with sound counter modelling.
- **`self_healing.py`** — `@resilient`, `CircuitBreaker`, `retry`, `HealthMonitor`, input validation.
- **`findings.py`** — threat catalog: CWE IDs, severities, confidence, remediation.
- **`report.py`** — SARIF 2.1.0 + JSON serialization (NumPy-safe encoder).
- **`gemini_explainer.py`** — optional AI explanations (modern `google-genai`, local fallback).
- **`webapp.py` + `web/index.html`** — lightweight web UI (stdlib `http.server`, vanilla HTML/CSS/JS).

## Detection coverage (CWE-mapped)

**Classic (OWASP/CWE):** SQL injection (CWE-89), command injection (CWE-78),
insecure deserialization (CWE-502), hard-coded credentials (CWE-798), disabled
TLS validation (CWE-295), SSRF (CWE-918), path traversal (CWE-22), weak hash /
cipher (CWE-327), insecure randomness (CWE-330), XXE (CWE-611), insecure temp
file (CWE-377), debug mode (CWE-489), cleartext transmission (CWE-319).

**Advanced / stealth:**

| Pattern | CWE | Severity |
|---|---|---|
| Probabilistic logic bomb | CWE-511 | High |
| Entangled (multi-condition) bomb | CWE-511 | High |
| Chained / stateful bomb | CWE-511 | High |
| Cross-function embedded malicious code | CWE-506 | Critical |
| Credential / data exfiltration (env / secret → network) | CWE-200 | Critical |
| Exposed secret / API key (offline, import-correlated) | CWE-798 | High–Critical |
| AI-scanner evasion (prompt injection in code) | CWE-506 | High |
| Environment-keyed trigger (CI/cloud-gated payload) | CWE-506 | High |
| Typosquat / slopsquat dependency (requirements/pyproject) | CWE-829 | High |
| Install / import-time code execution (setup.py hooks) | CWE-506 | Critical |
| Steganographic / covert channel | CWE-515 | Critical |
| Encoded / obfuscated payload (base64/XOR → exec) | CWE-506 | Critical |
| Anti-analysis / anti-debug | CWE-489 | Medium |
| Dangerous execution sink (receiver-aware: os/subprocess/exec/eval) | CWE-78 | High |

## Command-line usage

```bash
python cli.py scan app.py                              # text output
python cli.py scan src/ --format sarif -o out.sarif    # SARIF 2.1.0
python cli.py scan . --min-severity Medium --fail-on High   # CI gate (exit 2 on hit)
python cli.py fix app.py --write                       # apply deterministic auto-fixes
```

## Testing

```bash
python test_sinkline.py     # standalone runner (no pytest needed) — 89 tests
pytest test_sinkline.py     # or via pytest
python benchmark.py       # measured benchmark (recall + false-positive rate) -> BENCHMARK.md
pip install bandit semgrep && python benchmark.py --compare   # head-to-head vs. Bandit & Semgrep
```

The `--compare` run executes **Bandit** and **Semgrep** on the exact same corpus
(each at its own recommended CI gate) and appends a per-sample coverage matrix to
`BENCHMARK.md`. Measured result: **Sinkline 94% recall / 0% FP** vs Semgrep 66% / 3%
and Bandit 52% / 6%. Semgrep runs against `tools/semgrep-python-security.yaml`
(standard offline rules) because its registry is unreachable in air-gapped/CI
environments — see `tool_comparison.py` for the honest methodology.

---

*Sinkline — Local-first security, quantum-inspired analysis, zero trust.*
