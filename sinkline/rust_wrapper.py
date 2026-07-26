import logging
import time

logger = logging.getLogger(__name__)

RUST_AVAILABLE = False
try:
    # Try importing the compiled Rust extension
    # It would usually be named sinkline_core (if installed via maturin/pip)
    import sinkline_core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

def scan_code_fast(code: str):
    """
    Scans code using the High-Performance Rust Core if available.
    Falls back to a fast Python heuristic if not.
    """
    if RUST_AVAILABLE:
        start = time.time()
        result = sinkline_core.scan_code_fast(code)
        duration = (time.time() - start) * 1000
        logger.info(f"Rust Core scan completed in {duration:.2f}ms")
        return result
    else:
        logger.debug("Rust Core not found. Using Python fallback.")
        # Minimal fallback or just return None to let the main engine handle it
        return None

def is_rust_active():
    return RUST_AVAILABLE
