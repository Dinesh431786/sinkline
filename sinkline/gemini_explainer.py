"""
gemini_explainer.py — Optional AI Explanation Layer
===================================================
Produces a short, human-readable explanation for a finding. Uses Google Gemini
when an API key is configured, and *always* degrades to a deterministic local
explanation otherwise — Sinkline is local-first and air-gapped by default, so AI
is a bonus, never a requirement.

Import resilience: tries the current ``google-genai`` SDK first, then the legacy
``google-generativeai`` package, then falls back to fully local generation. The
old package emits a deprecation warning and is no longer the default.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")

# Detect an available SDK without importing the deprecated one eagerly.
_SDK = None  # "genai" (new) | "legacy" | None
try:  # preferred modern SDK
    from google import genai as _genai_new  # type: ignore
    _SDK = "genai"
except Exception:
    _genai_new = None

if _SDK is None:
    try:  # legacy fallback (deprecated)
        import google.generativeai as _genai_legacy  # type: ignore
        _SDK = "legacy"
    except Exception:
        _genai_legacy = None

_legacy_configured = False


def _local_fallback_explanation(score: float, pattern: str, code_snippet: str) -> str:
    severity = "high" if score >= 0.7 else "medium" if score >= 0.4 else "low"
    return (
        f"Detected pattern: {pattern}. Risk score ~{score:.2f} ({severity}). "
        f"This indicates a potentially malicious construct (e.g. a probabilistic "
        f"trigger, chained state machine, or hidden/encoded payload). Trace every "
        f"condition guarding privileged side effects and confirm no hidden trigger "
        f"unlocks code execution or data exfiltration.\n"
        f"Snippet preview:\n{code_snippet.strip()[:400]}"
    )


def _gemini_prompt(score: float, pattern: str, code_snippet: str) -> str:
    return (
        "You are a cybersecurity expert auditing Python code for hidden malicious "
        "logic (logic bombs, covert channels, anti-analysis). In 4-8 sentences, "
        "explain the concrete risk of the snippet below and what to verify.\n\n"
        f"Pattern: {pattern}\nRisk score: {score:.2f}\n\nCode:\n{code_snippet}"
    )


def explain_result(score: float, pattern: str, code_snippet: str) -> str:
    """Return a concise explanation; never raises."""
    if not GOOGLE_API_KEY or _SDK is None:
        return _local_fallback_explanation(score, pattern, code_snippet)

    prompt = _gemini_prompt(score, pattern, code_snippet)
    try:
        if _SDK == "genai":
            client = _genai_new.Client(api_key=GOOGLE_API_KEY)
            resp = client.models.generate_content(
                model="gemini-2.0-flash", contents=prompt
            )
            return (resp.text or "").strip() or _local_fallback_explanation(score, pattern, code_snippet)
        else:  # legacy
            global _legacy_configured
            if not _legacy_configured:
                _genai_legacy.configure(api_key=GOOGLE_API_KEY)
                _legacy_configured = True
            model = _genai_legacy.GenerativeModel("gemini-1.5-flash-latest")
            return model.generate_content(prompt).text.strip()
    except Exception as e:
        logger.debug("Gemini call failed, using local fallback: %s", e)
        return _local_fallback_explanation(score, pattern, code_snippet)


if __name__ == "__main__":
    print(explain_result(0.93, "PROBABILISTIC_BOMB",
                         'if random.random() < 0.12: os.system("rm -rf /")'))
