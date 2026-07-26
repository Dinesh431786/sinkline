import ast
import re
from typing import List, Dict, Set, Any

class TaintPatternMatcher(ast.NodeVisitor):
    def __init__(self):
        self.taint_map: Dict[str, str] = {}  # var_name -> taint_type
        self.detected_patterns: Set[str] = set()
        # Steganography evidence flags (require genuine char-code manipulation,
        # not a bare .encode()/.decode() which is ubiquitous benign code).
        self._has_chr = False
        self._has_ord = False
        self._has_xor = False

    def analyze(self, code: str) -> List[str]:
        # Heuristic: Try AST parse. If fail, use C-token mode.
        try:
            tree = ast.parse(code)
            self.visit(tree)
        except SyntaxError:
            self._analyze_c_tokens(code)

        return self._finalize_results()

    def visit_Assign(self, node):
        # Basic taint propagation
        # Helper to check if a value node contains randomness or danger
        rhs_taint = None
        
        # Simple heuristic for RHS
        rhs_str = ast.dump(node.value).lower()
        if "random" in rhs_str or "secret" in rhs_str:
            rhs_taint = "PROBABILISTIC"
        elif "call" in rhs_str:
             # Check for dangerous calls
             if any(x in rhs_str for x in ["system", "popen", "subprocess", "exec", "eval"]):
                 rhs_taint = "DANGER"
        
        # Propagate
        if rhs_taint:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.taint_map[target.id] = rhs_taint
        else:
             # Check if assigning from an existing tainted var (Linear Chain)
             # e.g. x = y (where y is tainted)
             if isinstance(node.value, ast.Name) and node.value.id in self.taint_map:
                 for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Inherit taint
                        self.taint_map[target.id] = self.taint_map[node.value.id]

        self.generic_visit(node)
        
    def visit_Call(self, node):
        # Check for Stego indicators in calls
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr # rough

        # Record char-code stego evidence; only finalize as STEGANOGRAPHY when
        # we see chr+ord together or an XOR transform (see _finalize_results).
        if call_name == 'chr':
            self._has_chr = True
        elif call_name == 'ord':
            self._has_ord = True
        elif call_name == 'xor':
            self._has_xor = True

        # Check for Anti-Debug
        if call_name == "sleep" or "debug" in call_name:
             self.detected_patterns.add("QUANTUM_ANTIDEBUG")
             
        # Check for Cross-Function Bomb
        # If we call a known tainted function (that isn't just a helper)
        if call_name in self.taint_map:
             self.detected_patterns.add("CROSS_FUNCTION_QUANTUM_BOMB")

        self.generic_visit(node)

    def visit_BinOp(self, node):
        # XOR byte-transform is a strong steganography/obfuscation signal.
        if isinstance(node.op, ast.BitXor):
            self._has_xor = True
        self.generic_visit(node)

    def visit_If(self, node):
        # USER PROVIDED LOGIC
        condition_vars = [n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)]
        unique_taints = {self.taint_map.get(var) for var in condition_vars if var in self.taint_map}

        # If the condition depends on DIFFERENT source types or multiple entangled vars
        if "CROSS_FUNCTION_QUANTUM_BOMB" in unique_taints:
             self.detected_patterns.add("CROSS_FUNCTION_QUANTUM_BOMB")
        elif len(unique_taints) > 1 or "ENTANGLED" in unique_taints:
            self.detected_patterns.add("ENTANGLED_BOMB")
        elif "PROBABILISTIC" in unique_taints:
            self.detected_patterns.add("PROBABILISTIC_BOMB")
        elif "CHAINED" in unique_taints: # Explicit check for linear chain
            self.detected_patterns.add("CHAINED_QUANTUM_BOMB")
            
        # Also check for direct randomness in condition if not captured by variables
        cond_str = ast.dump(node.test).lower()
        if "random" in cond_str:
             self.detected_patterns.add("PROBABILISTIC_BOMB")
             
        # Check body for Stego/AntiDebug implicitly
        # (generic_visit handles recursion)
            
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        # Handle k += 1 etc.
        # If inside a probabilistic block, taint the target?
        # Use simple heuristic: if we are visiting this, we are in the flow.
        # If we have detected PROBABILISTIC_BOMB recently?
        # Hard to know context without state stack.
        # But if the variable is already tainted, keep it tainted.
        # If RHS has random, taint it.
        rhs_str = ast.dump(node.value).lower()
        taint = None
        if "random" in rhs_str:
            taint = "PROBABILISTIC"
        
        target = node.target
        if isinstance(target, ast.Name):
            if taint:
                self.taint_map[target.id] = taint
            elif target.id in self.taint_map:
                pass # Already tainted, stays tainted
            else:
                # If we encounter k+=1 and k is unknown, but we are running analysis...
                # Maybe assume it's a state var?
                # For C-style bomb: if (random) k+=1.
                # AST doesn't tell us we are in an If block easily without stack.
                # Hack: If we have seen PROBABILISTIC_BOMB, assume subsequent assigns are related?
                if "PROBABILISTIC_BOMB" in self.detected_patterns:
                    self.taint_map[target.id] = "CHAINED"
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Heuristic: If function body has random, taint the function name
        # Optimized string construction
        body_parts = [ast.dump(stmt).lower() for stmt in node.body]
        body_str = "".join(body_parts)
        
        # Check for Entanglement (mixing random + tainted calls)
        has_random = "random" in body_str
        has_tainted_call = False
        for known_taint in self.taint_map:
             if known_taint in body_str: # Rough string check for call
                  has_tainted_call = True
                  break
        
        if has_random and has_tainted_call:
             # Check what kind of call it is
             call_taint = "UNKNOWN"
             for known_taint in self.taint_map:
                 if known_taint in body_str:
                     call_taint = self.taint_map[known_taint]
                     break
            
             if call_taint == "PROBABILISTIC":
                 # Mixing random + probabilistic call = ENTANGLED (Coupled Probabilities)
                 self.taint_map[node.name] = "ENTANGLED"
             else:
                 # Mixing random + other call = CROSS_FUNCTION (Interprocedural)
                 self.taint_map[node.name] = "CROSS_FUNCTION_QUANTUM_BOMB"
                 
        elif has_random:
             self.taint_map[node.name] = "PROBABILISTIC"
        elif "system" in body_str or "exec" in body_str:
             self.taint_map[node.name] = "DANGER"
             
        self.generic_visit(node)

    def _analyze_c_tokens(self, code):
        lines = code.split('\n')
        for line in lines:
            line = line.strip()
            
            # 1. Assignment Logic (Infer Taint)
            # k = 0
            if "=" in line and not line.startswith("if"):
                parts = line.split("=")
                lhs = parts[0].strip()
                rhs = parts[1].strip() if len(parts) > 1 else ""
                
                # Check RHS for randomness
                if "random" in rhs or "rand" in rhs:
                     self.taint_map[lhs] = "PROBABILISTIC"
                # Check RHS for simple increment of tracked var -> Chain
                # k += 1 is handled below as it's usually in a body, but k = k + 1
                elif any(v in rhs for v in self.taint_map):
                     self.taint_map[lhs] = "CHAINED" # Propagation

            # 2. Control Flow Logic (User Provided)
            if line.startswith("if") and "(" in line:
                # Count how many known tainted variables are in this condition
                tainted_vars_found = set()
                for known_var, taint in self.taint_map.items():
                    # Strict boundary match to avoid partial string matches
                    if re.search(r'\b' + re.escape(known_var) + r'\b', line):
                        tainted_vars_found.add(taint)

                # DECISION MATRIX
                if len(tainted_vars_found) > 1:
                    # Multiple distinct taint sources interacting = ENTANGLEMENT
                    self.detected_patterns.add("ENTANGLED_BOMB")
                    self.detected_patterns.discard("CHAINED_QUANTUM_BOMB")
                elif len(tainted_vars_found) == 1:
                    # Single taint source checking in = CHAINED (or Probabilistic)
                    taint_type = list(tainted_vars_found)[0]
                    if taint_type == "PROBABILISTIC":
                        self.detected_patterns.add("PROBABILISTIC_BOMB")
                    elif taint_type == "CHAINED":
                        self.detected_patterns.add("CHAINED_QUANTUM_BOMB")
                    else:
                        # If we just see a variable, default to Chained if it's being checked
                        self.detected_patterns.add("CHAINED_QUANTUM_BOMB")
                
                # Direct check for random in C-style condition
                if "random" in line or "rand" in line:
                    # If body modifies a variable, taint it as PROBABILISTIC/CHAINED?
                    # The C-style bomb: if (random) k += 1.
                    # This line detects Probabilistic.
                    # But we want to detect CHAINED eventually.
                    # Heuristic: If we see random, mark Probabilistic.
                    # The Chained bomb has `if k==2`. `k` needs to be tainted.
                    pass 
            
            # 3. Body modification (Hack for C-style bomb k+=1)
            # If line is inside an if block (indentation or simple check), and modifies a var
            # we assume it's state dependent.
            if "+=" in line or "++" in line:
                # Extract var
                var = line.split("+")[0].strip()
                if var in self.taint_map:
                     pass # Already tracked
                else:
                     self.taint_map[var] = "CHAINED" # Start tracking as state var

    def _finalize_results(self):
        # 0. Decide steganography from accumulated evidence: char-code encoding
        #    (chr AND ord) or an XOR transform. Bare .encode()/.decode() no longer
        #    triggers this (it caused false positives on ordinary code).
        if (self._has_chr and self._has_ord) or self._has_xor:
            self.detected_patterns.add("QUANTUM_STEGANOGRAPHY")

        # 1. Steganography is a complex chain by definition.
        # If Stego is found, it hides the lower-level "Chain" alert.
        if "QUANTUM_STEGANOGRAPHY" in self.detected_patterns:
            self.detected_patterns.discard("CHAINED_QUANTUM_BOMB")

        # 2. Entanglement is a specific type of logic state.
        # If we found Entanglement, ignore generic noise.
        # We allow CROSS_FUNCTION to coexist or take precedence if specific interprocedural logic was found.
        if "ENTANGLED_BOMB" in self.detected_patterns:
            self.detected_patterns.discard("PROBABILISTIC_BOMB")

        # 3. Cross-Function is the fallback for distributed logic.
        # If we have Cross-Function AND Chained, usually Cross-Function is the 'Headline'.
        if "CROSS_FUNCTION_QUANTUM_BOMB" in self.detected_patterns:
            self.detected_patterns.discard("CHAINED_QUANTUM_BOMB")
            
        # User feedback says: "If Stego... detected correct... Chained remains false positive."
        # My rule 1 fixes this.
        
        # User feedback: "Entangled... flags Cross-Function instead of Entangled".
        # My logic in visit_If for Entangled should catch it now.
        
        # Additional cleanup for Probabilistic vs Cross-Function
        if "CROSS_FUNCTION_QUANTUM_BOMB" in self.detected_patterns:
             self.detected_patterns.discard("PROBABILISTIC_BOMB")
             
        # Cleanup: If Chained is detected (structure), discard generic Probabilistic (randomness)
        if "CHAINED_QUANTUM_BOMB" in self.detected_patterns:
             self.detected_patterns.discard("PROBABILISTIC_BOMB")
             
        # Cleanup: Anti-Debug often uses random delays; prioritize the specific threat
        if "QUANTUM_ANTIDEBUG" in self.detected_patterns:
             self.detected_patterns.discard("PROBABILISTIC_BOMB")

        # Fallback
        if not self.detected_patterns:
            return ["UNKNOWN"]
            
        return list(self.detected_patterns)

# Standalone wrapper
def detect_patterns(code_input):
    """
    New signature: accepts raw code string, not logic blocks.
    """
    matcher = TaintPatternMatcher()
    return matcher.analyze(code_input)
