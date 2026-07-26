"""
qsim.py — Sinkline Lightweight Quantum-Inspired Simulator
=============================================================

A tiny, dependency-free (pure NumPy) state-vector simulator that replaces the
heavyweight `cirq` dependency. Sinkline only needs a handful of single- and
two-qubit gates (RY, H, X, CNOT) plus measurement, so shipping the full cirq
stack (hundreds of MB, slow import) was wasteful.

Design goals:
  * Lightweight   — only NumPy, ~10x faster import than cirq.
  * Faster        — direct tensor contraction, no symbolic overhead.
  * Compatible    — matches cirq's big-endian state-vector ordering so the
                    Von Neumann entropy math downstream is unchanged.
  * Deterministic — same circuit -> same state vector, every time.

The public surface intentionally mirrors the slice of the cirq API that
Sinkline used, so the rest of the codebase changed minimally.
"""
from __future__ import annotations

import numpy as np
from typing import Dict, List, Tuple

# --- Gate matrices (complex128 for numerical accuracy) ---
_H = (1.0 / np.sqrt(2.0)) * np.array([[1, 1], [1, -1]], dtype=np.complex128)
_X = np.array([[0, 1], [1, 0]], dtype=np.complex128)


def _ry_matrix(theta: float) -> np.ndarray:
    c = np.cos(theta / 2.0)
    s = np.sin(theta / 2.0)
    return np.array([[c, -s], [s, c]], dtype=np.complex128)


class Circuit:
    """A minimal quantum circuit over ``n_qubits`` line qubits (indexed 0..n-1).

    Qubit 0 is the most-significant qubit in the resulting state vector, which
    matches cirq's convention so that reduced-density-matrix / entropy
    computations are identical to the original implementation.
    """

    def __init__(self, n_qubits: int):
        if n_qubits < 1:
            raise ValueError("Circuit requires at least one qubit")
        self.n_qubits = n_qubits
        # Each op: (kind, payload). Measurements are recorded separately so the
        # state-vector simulation can ignore them (they are non-unitary).
        self.ops: List[Tuple[str, tuple]] = []
        self.measurements: List[Tuple[int, str]] = []  # (qubit, key)

    # --- circuit construction (chainable) ---
    def ry(self, qubit: int, theta: float) -> "Circuit":
        self.ops.append(("1q", (qubit, _ry_matrix(theta))))
        return self

    def h(self, qubit: int) -> "Circuit":
        self.ops.append(("1q", (qubit, _H)))
        return self

    def x(self, qubit: int) -> "Circuit":
        self.ops.append(("1q", (qubit, _X)))
        return self

    def cnot(self, control: int, target: int) -> "Circuit":
        self.ops.append(("cnot", (control, target)))
        return self

    def measure(self, qubit: int, key: str) -> "Circuit":
        self.measurements.append((qubit, key))
        return self

    @property
    def depth(self) -> int:
        """Number of unitary moments (used as a proxy for logical depth)."""
        return len(self.ops)

    def __len__(self) -> int:
        return self.depth

    # --- simulation ---
    def final_state_vector(self) -> np.ndarray:
        """Return the final state vector as a flat complex128 array of size 2^n."""
        state = np.zeros((2,) * self.n_qubits, dtype=np.complex128)
        state[(0,) * self.n_qubits] = 1.0  # |00...0>

        for kind, payload in self.ops:
            if kind == "1q":
                qubit, matrix = payload
                state = self._apply_1q(state, matrix, qubit)
            elif kind == "cnot":
                control, target = payload
                state = self._apply_cnot(state, control, target)

        return state.reshape(-1)

    def _apply_1q(self, state: np.ndarray, matrix: np.ndarray, qubit: int) -> np.ndarray:
        # Contract the gate's input index with the qubit axis, then move the new
        # output axis back into place.
        out = np.tensordot(matrix, state, axes=([1], [qubit]))
        return np.moveaxis(out, 0, qubit)

    def _apply_cnot(self, state: np.ndarray, control: int, target: int) -> np.ndarray:
        # Flip the target axis only on the slice where the control qubit is |1>.
        state = state.copy()
        ctrl_one = [slice(None)] * self.n_qubits
        ctrl_one[control] = 1
        sub = state[tuple(ctrl_one)]
        state[tuple(ctrl_one)] = np.flip(sub, axis=target if target < control else target - 1)
        return state

    def sample(self, repetitions: int = 1024, seed: int | None = None) -> Dict[str, np.ndarray]:
        """Sample measurement outcomes, returning {key: array_of_bits}.

        Mirrors the shape of cirq's ``run(...).measurements`` closely enough for
        the UI, but is fully deterministic when ``seed`` is provided.
        """
        rng = np.random.default_rng(seed)
        probs = np.abs(self.final_state_vector()) ** 2
        probs = probs / probs.sum() if probs.sum() > 0 else probs
        outcomes = rng.choice(len(probs), size=repetitions, p=probs)

        results: Dict[str, np.ndarray] = {}
        for qubit, key in self.measurements:
            shift = self.n_qubits - 1 - qubit  # big-endian bit position
            bits = (outcomes >> shift) & 1
            results[key] = bits.reshape(-1, 1)
        return results

    def to_text(self) -> str:
        """Human-readable rendering of the circuit (for the UI)."""
        lines = [f"Qubits: {self.n_qubits}"]
        for kind, payload in self.ops:
            if kind == "1q":
                qubit, matrix = payload
                gate = "H" if np.allclose(matrix, _H) else "X" if np.allclose(matrix, _X) else "RY"
                lines.append(f"  q{qubit}: {gate}")
            elif kind == "cnot":
                c, t = payload
                lines.append(f"  q{c} ──●── q{t} (CNOT)")
        for qubit, key in self.measurements:
            lines.append(f"  q{qubit}: measure('{key}')")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_text()
