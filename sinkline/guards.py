"""
guards.py — what conditions must hold for a dangerous sink to run
=================================================================
Sinkline already records whether a sink sits inside a guarded branch, but only
as a boolean. A boolean cannot distinguish `if debug:` from
`if random.random() < 0.005 and gethostname() == 'build-07':`, and that
distinction is the whole signal. This module recovers the actual conjunction of
conditions dominating each sink so it can be quantified by trigger_rarity.

Predicate kinds emitted: random_lt, random_gt, randint_eq, env_eq, hostname_eq,
platform_eq, date_gt, unknown. Anything unrecognised is `unknown` and is scored
as common — an opaque condition must never be mistaken for a rare one.
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
    kind: str          # see module docstring; "unknown" when unrecognised
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
        for value in test.values:
            out.extend(_classify(value, negated))
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
    walker = _Walker()
    walker.visit(tree)
    return walker.found
