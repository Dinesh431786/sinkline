"""
self_healing.py — Sinkline Resilience & Self-Healing Layer
=============================================================

Security tooling is judged as much on *never crashing* as on what it detects.
A single bad input, a missing optional dependency, or one flaky engine should
never take the whole audit down. This module gives Sinkline industry-standard
resilience patterns:

  * ``@resilient``      — decorator that runs a function, and on any failure
                          returns a safe fallback while recording the fault.
  * ``CircuitBreaker``  — stops hammering an engine that keeps failing, then
                          probes for recovery (closed -> open -> half-open).
  * ``retry``           — bounded retry with exponential backoff for transient
                          failures (network, I/O).
  * ``HealthMonitor``   — central registry of engine health for the UI/health
                          endpoint, plus a ``self_heal`` routine that re-probes
                          degraded engines.
  * ``validate_code``   — input sanitization/limits (size, type, null bytes).

Everything is dependency-free (stdlib only) so the resilience layer itself can
never be the thing that fails to import.
"""
from __future__ import annotations

import functools
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("sinkline.self_healing")
logger.addHandler(logging.NullHandler())

# Hard limit: refuse pathologically large inputs that could OOM the analyzers.
MAX_CODE_BYTES = 1_000_000  # 1 MB of source is already enormous for a snippet


# --------------------------------------------------------------------------- #
# Health registry
# --------------------------------------------------------------------------- #
class EngineState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"      # running on a fallback / reduced capability
    UNAVAILABLE = "unavailable"  # optional dependency missing
    FAILED = "failed"          # crashed at runtime


@dataclass
class EngineHealth:
    name: str
    state: EngineState = EngineState.HEALTHY
    detail: str = ""
    failures: int = 0
    last_error: str = ""
    last_update: float = field(default_factory=time.time)

    def emoji(self) -> str:
        return {
            EngineState.HEALTHY: "✅",
            EngineState.DEGRADED: "🟡",
            EngineState.UNAVAILABLE: "⚪",
            EngineState.FAILED: "🔴",
        }[self.state]


class HealthMonitor:
    """Thread-safe registry of engine health, used by the UI health panel."""

    def __init__(self) -> None:
        self._engines: Dict[str, EngineHealth] = {}
        self._lock = threading.Lock()
        self._heal_hooks: Dict[str, Callable[[], bool]] = {}

    def register(self, name: str, state: EngineState = EngineState.HEALTHY,
                 detail: str = "", heal_hook: Optional[Callable[[], bool]] = None) -> None:
        with self._lock:
            self._engines[name] = EngineHealth(name=name, state=state, detail=detail)
            if heal_hook is not None:
                self._heal_hooks[name] = heal_hook

    def mark(self, name: str, state: EngineState, detail: str = "", error: str = "") -> None:
        with self._lock:
            eng = self._engines.setdefault(name, EngineHealth(name=name))
            eng.state = state
            if detail:
                eng.detail = detail
            if error:
                eng.last_error = error
                eng.failures += 1
            eng.last_update = time.time()

    def get(self, name: str) -> Optional[EngineHealth]:
        with self._lock:
            return self._engines.get(name)

    def snapshot(self) -> List[EngineHealth]:
        with self._lock:
            return list(self._engines.values())

    def overall(self) -> EngineState:
        states = [e.state for e in self.snapshot()]
        if any(s == EngineState.FAILED for s in states):
            return EngineState.FAILED
        if any(s == EngineState.DEGRADED for s in states):
            return EngineState.DEGRADED
        if states and all(s == EngineState.UNAVAILABLE for s in states):
            return EngineState.UNAVAILABLE
        return EngineState.HEALTHY

    def self_heal(self) -> Dict[str, bool]:
        """Re-probe degraded/failed engines via their heal hooks.

        Returns a map of engine -> recovered? Engines without a hook or that
        are merely UNAVAILABLE (missing dependency) are skipped.
        """
        results: Dict[str, bool] = {}
        for name, hook in list(self._heal_hooks.items()):
            eng = self.get(name)
            if eng is None or eng.state in (EngineState.HEALTHY, EngineState.UNAVAILABLE):
                continue
            try:
                ok = bool(hook())
            except Exception as exc:  # a heal probe must never crash healing
                logger.debug("Heal hook for %s raised: %s", name, exc)
                ok = False
            results[name] = ok
            if ok:
                self.mark(name, EngineState.HEALTHY, detail="recovered after self-heal")
        return results


# A process-wide default monitor most callers can share.
health = HealthMonitor()


# --------------------------------------------------------------------------- #
# Circuit breaker
# --------------------------------------------------------------------------- #
class CircuitBreaker:
    """Classic 3-state breaker: closed -> open (after N fails) -> half-open."""

    def __init__(self, name: str, failure_threshold: int = 3, reset_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._opened_at = 0.0
        self._state = "closed"
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._state == "open":
                if time.time() - self._opened_at >= self.reset_timeout:
                    self._state = "half-open"  # allow a single probe through
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = "closed"

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.time()

    @property
    def state(self) -> str:
        return self._state


# --------------------------------------------------------------------------- #
# Decorators
# --------------------------------------------------------------------------- #
def resilient(fallback: Any = None, engine: Optional[str] = None,
              monitor: Optional[HealthMonitor] = None):
    """Run the wrapped function; on *any* exception return ``fallback``.

    ``fallback`` may be a value or a zero-arg callable. The failure is logged
    and (if ``engine`` is given) recorded against the health monitor so the UI
    can show a degraded state instead of a stack trace.
    """
    mon = monitor or health

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                logger.warning("[resilient] %s failed: %s", func.__name__, exc)
                if engine:
                    mon.mark(engine, EngineState.DEGRADED,
                             detail=f"{func.__name__} fell back", error=str(exc))
                return fallback() if callable(fallback) else fallback
        return wrapper
    return decorator


def retry(attempts: int = 3, base_delay: float = 0.5, max_delay: float = 8.0,
          exceptions: tuple = (Exception,)):
    """Retry with exponential backoff (0.5s, 1s, 2s, ...). Re-raises on exhaustion."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            last_exc: Optional[BaseException] = None
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == attempts:
                        break
                    logger.debug("[retry] %s attempt %d failed: %s; sleeping %.1fs",
                                 func.__name__, attempt, exc, delay)
                    time.sleep(delay)
                    delay = min(delay * 2, max_delay)
            raise last_exc  # type: ignore[misc]
        return wrapper
    return decorator


def guarded(breaker: CircuitBreaker, fallback: Any = None):
    """Gate a call through a circuit breaker; short-circuit to fallback when open."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not breaker.allow():
                logger.debug("[breaker:%s] open — using fallback", breaker.name)
                return fallback() if callable(fallback) else fallback
            try:
                result = func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception as exc:
                breaker.record_failure()
                logger.warning("[breaker:%s] failure: %s", breaker.name, exc)
                return fallback() if callable(fallback) else fallback
        return wrapper
    return decorator


# --------------------------------------------------------------------------- #
# Input validation / sanitization
# --------------------------------------------------------------------------- #
class ValidationError(ValueError):
    pass


def validate_code(code: Any) -> str:
    """Validate and normalize untrusted source input.

    Raises ``ValidationError`` for clearly invalid input; otherwise returns a
    cleaned string safe to hand to the analyzers.
    """
    if code is None:
        raise ValidationError("No code provided.")
    if isinstance(code, bytes):
        code = code.decode("utf-8", errors="replace")
    if not isinstance(code, str):
        raise ValidationError(f"Expected source text, got {type(code).__name__}.")

    raw = code.encode("utf-8", errors="replace")
    if len(raw) > MAX_CODE_BYTES:
        raise ValidationError(
            f"Input too large ({len(raw)} bytes); limit is {MAX_CODE_BYTES} bytes."
        )

    # Strip NUL bytes which break ast.parse and many tokenizers.
    cleaned = code.replace("\x00", "")
    # Normalize newlines so line-based fallbacks behave consistently.
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    return cleaned


def probe_dependency(module_name: str) -> bool:
    """Best-effort check whether an optional dependency is importable."""
    import importlib
    try:
        importlib.import_module(module_name)
        return True
    except Exception:
        return False
