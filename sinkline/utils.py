def format_score(score):
    """
    Convert quantum risk score (0.0-1.0) to percentage and label.
    """
    pct = f"{score * 100:.1f}%"
    if score > 0.8:
        return pct, "HIGH RISK"
    elif score > 0.5:
        return pct, "MODERATE RISK"
    elif score > 0.25:
        return pct, "LOW RISK"
    return pct, "SAFE"

def safe_get(d, key, default=None):
    """
    Safely get a value from a dict, with fallback.
    """
    try:
        return d[key]
    except (KeyError, TypeError):
        return default

def flatten_probs(prob_vector, max_len=8):
    """
    Flatten or pad probability vectors for ML input.
    """
    flat = list(prob_vector)
    if len(flat) < max_len:
        flat += [0.0] * (max_len - len(flat))
    return flat[:max_len]

def normalize_name(name):
    """
    Normalize function/var names for graphing and ML.
    """
    return "".join([c if c.isalnum() else "_" for c in name])

def is_quantum_pattern(pattern):
    """
    Check if a pattern is quantum-native (advanced mode).
    """
    return pattern in [
        "PROBABILISTIC_BOMB",
        "ENTANGLED_BOMB",
        "CHAINED_BOMB",
        "QUANTUM_STEGANOGRAPHY",
        "QUANTUM_ANTIDEBUG",
        "CROSS_FUNCTION_QUANTUM_BOMB"
    ]
