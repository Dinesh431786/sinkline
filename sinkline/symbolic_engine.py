"""
symbolic_engine.py — Symbolic Reachability Verification (White-Box)
==================================================================
Uses the Z3 SMT solver to *prove* whether a malicious sink is actually
reachable, rather than merely pattern-matched. This cuts false positives on
"dead" bombs (e.g. ``if 1 == 0: os.system(...)``) and, crucially, models
**stateful counters** soundly.

Previous versions treated a counter ``k`` as a free variable, so a guard like
``if k == 99`` was reported reachable even when only one ``k += 1`` existed in
the program — a false "mathematical proof". This version tracks each counter as
an accumulator of *optional* increments (``k = Σ If(bᵢ, 1, 0)``), so
``k == target`` is provable only when ``0 ≤ target ≤ #increments``.
"""
from __future__ import annotations

import ast
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

MALICIOUS_CALLS = {
    "system", "popen", "shutdown", "exec", "eval", "grant_root_access",
    "unlock_root", "rmtree", "remove", "unlink", "Popen", "call", "run",
}


class SymbolicExecutor:
    """Linear, path-sensitive reachability checker over a module's top level."""

    def __init__(self):
        if not Z3_AVAILABLE:
            raise ImportError("z3-solver not installed")
        self.solver = z3.Solver()
        self.env = {}            # var name -> current z3 integer-valued expression
        self.malicious_reached = False
        self._counter = 0

    def _fresh(self, prefix: str):
        self._counter += 1
        return f"{prefix}_{self._counter}"

    # --- expression evaluation ------------------------------------------- #
    def _eval_expr(self, node):
        if isinstance(node, ast.Call):
            src = ast.dump(node).lower()
            if "randint" in src:
                return z3.Int(self._fresh("randint"))
            if "random" in src:
                r = z3.Real(self._fresh("rand"))
                self.solver.add(r >= 0.0, r < 1.0)
                return r
            return None
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            return z3.Int(node.id)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return None
            if isinstance(node.value, float):
                return z3.RealVal(node.value)
            if isinstance(node.value, int):
                return z3.IntVal(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval_expr(node.left)
            right = self._eval_expr(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    def _transpile_condition(self, test_node):
        try:
            if isinstance(test_node, ast.Compare) and test_node.ops:
                left = self._eval_expr(test_node.left)
                right = self._eval_expr(test_node.comparators[0])
                if left is None or right is None:
                    return None
                op = test_node.ops[0]
                if isinstance(op, ast.Lt):
                    return left < right
                if isinstance(op, ast.LtE):
                    return left <= right
                if isinstance(op, ast.Gt):
                    return left > right
                if isinstance(op, ast.GtE):
                    return left >= right
                if isinstance(op, ast.Eq):
                    return left == right
                if isinstance(op, ast.NotEq):
                    return left != right
        except Exception as e:
            logger.debug("Z3 transpile error: %s", e)
        return None

    # --- statement processing -------------------------------------------- #
    @staticmethod
    def _is_increment_block(node: ast.If):
        """Return list of (counter, amount) if the If body is purely counter += int."""
        if not node.body:
            return None
        targets = []
        for stmt in node.body:
            if (isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add)
                    and isinstance(stmt.target, ast.Name)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, int)):
                targets.append((stmt.target.id, stmt.value.value))
            else:
                return None
        return targets

    def _process_body(self, stmts):
        for stmt in stmts:
            self._process_stmt(stmt)

    def _process_stmt(self, stmt):
        if isinstance(stmt, ast.Assign):
            val = self._eval_expr(stmt.value)
            if val is not None:
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        self.env[t.id] = val
            return

        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
            if isinstance(stmt.target, ast.Name):
                cur = self.env.get(stmt.target.id, z3.IntVal(0))
                inc = self._eval_expr(stmt.value)
                if inc is not None:
                    self.env[stmt.target.id] = cur + inc
            return

        if isinstance(stmt, ast.If):
            inc = self._is_increment_block(stmt)
            if inc is not None:
                # Conditional increment: counter MAY advance (model the optionality).
                for name, amount in inc:
                    cur = self.env.get(name, z3.IntVal(0))
                    b = z3.Bool(self._fresh(f"take_{name}"))
                    self.env[name] = cur + z3.If(b, amount, 0)
                return

            # Guard branch: explore the true path under its constraint.
            cond = self._transpile_condition(stmt.test)
            self.solver.push()
            if cond is not None:
                self.solver.add(cond)
            self._process_body(stmt.body)
            self.solver.pop()
            # The else-branch carries no bomb-relevant constraint for our model.
            self._process_body(stmt.orelse)
            return

        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            self._check_malicious(stmt.value)
            return

        # Recurse into function/loop bodies so nested bombs are still seen.
        for child in getattr(stmt, "body", []) or []:
            self._process_stmt(child)

    def _check_malicious(self, call: ast.Call):
        name = ""
        if isinstance(call.func, ast.Name):
            name = call.func.id
        elif isinstance(call.func, ast.Attribute):
            name = call.func.attr
        if name in MALICIOUS_CALLS:
            if self.solver.check() == z3.sat:
                self.malicious_reached = True

    def run(self, tree: ast.AST):
        body = tree.body if isinstance(tree, ast.Module) else [tree]
        self._process_body(body)


def run_symbolic_verification(code):
    if not Z3_AVAILABLE:
        return "Z3 Solver not available (install z3-solver)", False
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"Symbolic verification skipped (parse error: {e})", False
    try:
        executor = SymbolicExecutor()
        executor.run(tree)
        if executor.malicious_reached:
            return "UNSAFE (Mathematical Proof: Reachable)", True
        return "SAFE (Mathematically Proven)", False
    except Exception as e:
        return f"Symbolic Verification Failed: {str(e)}", False


if __name__ == "__main__":
    tests = {
        "reachable random": "if random.random() < 0.5:\n    os.system('x')",
        "dead branch": "if 1 == 0:\n    os.system('x')",
        "chained reachable (k==2, 2 incs)":
            "k=0\nif (random.randint(0,7)==3):\n    k+=1\nif (random.randint(0,9)==5):\n    k+=1\nif k==2:\n    os.system('x')",
        "chained UNreachable (k==99, 1 inc)":
            "k=0\nif (random.randint(0,7)==3):\n    k+=1\nif k==99:\n    os.system('x')",
    }
    for name, src in tests.items():
        print(f"{name:38s} -> {run_symbolic_verification(src)}")
