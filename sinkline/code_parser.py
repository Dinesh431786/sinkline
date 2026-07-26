import ast
import logging
import math
from collections import Counter
from typing import List, Dict, Any, Tuple, Set

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def _safe_unparse(node: ast.AST) -> str:
    """Return a readable representation of an AST node.

    Prefer `ast.unparse` if available (Python >= 3.9), otherwise use
    a small fallback that handles Name and Attribute nodes and falls
    back to ast.dump for other node types.
    """
    if hasattr(ast, "unparse"):
        try:
            return ast.unparse(node)
        except Exception:
            return ast.dump(node)
    # Fallback:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = _safe_unparse(node.value)
        return f"{value}.{node.attr}"
    if isinstance(node, ast.Call):
        func = _safe_unparse(node.func)
        args = ", ".join(_safe_unparse(a) for a in node.args)
        return f"{func}({args})"
    return ast.dump(node)

def _get_call_name(call_node: ast.Call) -> str:
    """Get the textual callable name from a Call node, if possible."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return _safe_unparse(func)
    return _safe_unparse(func)

def extract_logic_blocks(code: str, language: str = "python", max_inline_depth: int = 4) -> List[Dict[str, Any]]:
    """
    Returns a list of logic blocks:
    Each block is: {"condition": "...", "body": [lines...], "calls": [funcs...]}
    Inlines helper functions where possible for deeper analysis.

    Notes:
    - Non-Python languages raise ValueError.
    - For unparsable code, returns [] and logs a debug message.
    """
    if language != "python":
        raise ValueError(f"[code_parser] Unsupported language: {language}")

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        logger.debug("[code_parser] AST parse failed: %s", e)
        # Fallback for non-Python or broken code: Return one big block to allow regex scanning
        return [{
            "condition": "UNKNOWN_SYNTAX",
            "body": [line.strip() for line in code.splitlines() if line.strip()],
            "calls": []
        }]

    # Map function name to ast.FunctionDef
    func_map: Dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            func_map[node.name] = node

    # Caches to avoid repeated expansion (prevents exponential blowup)
    _cond_cache: Dict[Tuple[str, int, Tuple[str, ...]], List[str]] = {}
    _body_cache: Dict[Tuple[str, int, Tuple[str, ...]], Tuple[List[str], List[str]]] = {}

    # Cache now stores (inlined_strings, found_calls)
    _cond_cache: Dict[Tuple[str, int, Tuple[str, ...]], Tuple[List[str], List[str]]] = {}

    def inline_condition(cond_node: ast.AST, inline_depth: int, seen_funcs: Set[str]) -> Tuple[List[str], List[str]]:
        key = (ast.dump(cond_node), inline_depth, tuple(sorted(seen_funcs)))
        if key in _cond_cache:
            cached_res, cached_calls = _cond_cache[key]
            return cached_res.copy(), cached_calls.copy()

        conds: List[str] = []
        calls: List[str] = []

        if isinstance(cond_node, ast.BoolOp):
            for v in cond_node.values:
                c_strs, c_calls = inline_condition(v, inline_depth, seen_funcs)
                conds.extend(c_strs)
                calls.extend(c_calls)
        elif isinstance(cond_node, ast.Call):
            func_name = _get_call_name(cond_node)
            calls.append(func_name)
            
            # Try to inline only when we have a direct function definition by simple name
            base_name = func_name.split(".")[0]
            if base_name in func_map and inline_depth < max_inline_depth and base_name not in seen_funcs:
                seen = set(seen_funcs)
                seen.add(base_name)
                for stmt in func_map[base_name].body:
                    if isinstance(stmt, ast.If):
                        c_strs, c_calls = inline_condition(stmt.test, inline_depth + 1, set(seen))
                        conds.extend(c_strs)
                        calls.extend(c_calls)
                    else:
                        conds.append(_safe_unparse(stmt))
                        # Also scan body stmts for calls
                        for subnode in ast.walk(stmt):
                            if isinstance(subnode, ast.Call):
                                calls.append(_get_call_name(subnode))
            else:
                conds.append(_safe_unparse(cond_node))
        else:
            conds.append(_safe_unparse(cond_node))
            # Scan for calls in other node types (e.g. comparisons)
            for subnode in ast.walk(cond_node):
                if isinstance(subnode, ast.Call):
                     calls.append(_get_call_name(subnode))

        _cond_cache[key] = (conds.copy(), calls.copy())
        return conds, calls

    def inline_body(stmts: List[ast.stmt], inline_depth: int, seen_funcs: Set[str]) -> Tuple[List[str], List[str]]:
        key = (ast.dump(ast.Module(body=stmts)), inline_depth, tuple(sorted(seen_funcs)))
        if key in _body_cache:
            cached_inlined, cached_calls = _body_cache[key]
            return cached_inlined.copy(), cached_calls.copy()

        result: List[str] = []
        calls: List[str] = []

        for stmt in stmts:
            # Inline top-level expression calls when they match a defined function
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                func_name = _get_call_name(stmt.value)
                base_name = func_name.split(".")[0]
                if base_name in func_map and inline_depth < max_inline_depth and base_name not in seen_funcs:
                    seen = set(seen_funcs)
                    seen.add(base_name)
                    inlined, subcalls = inline_body(func_map[base_name].body, inline_depth + 1, seen)
                    result.extend(inlined)
                    calls.extend(subcalls)
                else:
                    src = _safe_unparse(stmt).strip()
                    result.append(src or f"[CALL] {func_name}()")
                    if func_name:
                        calls.append(func_name)
            else:
                src = _safe_unparse(stmt).strip()
                result.append(src)
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Call):
                        calls.append(_get_call_name(node))

        _body_cache[key] = (result.copy(), calls.copy())
        return result, calls

    blocks: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            try:
                cond_lines, cond_calls = inline_condition(node.test, 1, set())
                cond = " and ".join([c for c in cond_lines if c])
                body_lines, body_calls = inline_body(node.body, 1, set())
                
                # Combine calls from condition and body
                all_calls = sorted(set(body_calls + cond_calls))
                
                if cond and body_lines:
                    blocks.append({
                        "condition": cond,
                        "body": body_lines,
                        "calls": all_calls
                    })
            except Exception as e:
                logger.debug("[code_parser] Failed to extract block: %s", e)

    return blocks

def calculate_ast_entropy(code: str) -> float:
    """
    Calculates Shannon Entropy of the AST structure.
    High entropy may indicate obfuscation or complex malicious logic.
    H(X) = - sum(p_i * log2(p_i)) where i is node type.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return 0.0
        
    node_types = [type(node).__name__ for node in ast.walk(tree)]
    total = len(node_types)
    if total == 0:
        return 0.0
        
    counts = Counter(node_types)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
        
    return entropy


# --- DEMO (safe) ---
if __name__ == "__main__":
    sample_code = '''
def check_1():
    return True

def check_2():
    return True

if check_1() and check_2():
    # Be safe in demos — avoid side effects like shutdowns or deleting files.
    print("Demo: condition met")
'''
    blocks = extract_logic_blocks(sample_code)
    for b in blocks:
        print(b)
