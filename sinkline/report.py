"""
report.py — Sinkline Industry-Standard Reporting
===================================================

Serializes audit findings into:

  * **SARIF 2.1.0** — the OASIS standard consumed by GitHub Code Scanning,
    DefectDojo, SonarQube and VS Code. CWE linkage is done the *correct* way
    via a ``taxonomies`` block + rule ``relationships`` (not ``properties.tags``,
    which the spec discourages), and cross-run deduplication is enabled via
    ``partialFingerprints``.
  * **JSON** — a flat, human/script-friendly summary.

A NumPy-aware encoder guarantees we never hit the ``float32 is not JSON
serializable`` crash that previously broke report downloads.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from findings import CATALOG, Finding, SEVERITY_TO_SARIF, get_meta

TOOL_NAME = "Sinkline"
TOOL_VERSION = "2.1.0"
INFO_URI = "https://github.com/dinesh431786/-sinkline-pro"


class SafeJSONEncoder(json.JSONEncoder):
    """Encoder that tolerates NumPy scalars/arrays and arbitrary objects.

    This is the definitive fix for the production crash where a ``numpy.float32``
    reached ``json.dumps``. We degrade unknown objects to ``str`` rather than
    raising, so a report is *always* producible.
    """

    def default(self, obj: Any):
        # NumPy is optional at serialization time; import lazily.
        try:
            import numpy as np
            if isinstance(obj, np.integer):
                return int(obj)
            if isinstance(obj, np.floating):
                return float(obj)
            if isinstance(obj, np.bool_):
                return bool(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
        except Exception:
            pass
        if hasattr(obj, "to_dict"):
            try:
                return obj.to_dict()
            except Exception:
                pass
        return str(obj)


def safe_json_dumps(obj: Any, indent: int = 2) -> str:
    return json.dumps(obj, indent=indent, cls=SafeJSONEncoder)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #
def _build_rules() -> List[dict]:
    """One SARIF reporting descriptor per catalog rule, linked to its CWE taxon."""
    rules = []
    for meta in CATALOG.values():
        rules.append({
            "id": meta.rule_id,
            "name": meta.title.replace(" ", ""),
            "shortDescription": {"text": meta.title},
            "fullDescription": {"text": meta.description},
            "helpUri": meta.cwe_uri(),
            "help": {"text": meta.remediation},
            "defaultConfiguration": {
                "level": SEVERITY_TO_SARIF.get(meta.severity, "warning")
            },
            "relationships": [{
                "target": {
                    "id": meta.cwe,
                    "toolComponent": {"name": "CWE"},
                },
                "kinds": ["superset"],
            }],
            "properties": {
                "security-severity": str(_cvss_for(meta.severity)),
                "sinkline-severity": meta.severity,
            },
        })
    return rules


def _cvss_for(severity: str) -> float:
    from findings import SEVERITY_TO_CVSS
    return SEVERITY_TO_CVSS.get(severity, 0.0)


def _build_cwe_taxonomy() -> dict:
    """A taxonomies[] component enumerating every CWE referenced by our rules."""
    seen: Dict[str, dict] = {}
    for meta in CATALOG.values():
        if meta.cwe not in seen:
            seen[meta.cwe] = {
                "id": meta.cwe,
                "name": meta.cwe_name,
                "shortDescription": {"text": meta.cwe_name},
                "helpUri": meta.cwe_uri(),
            }
    return {
        "name": "CWE",
        "organization": "MITRE",
        "shortDescription": {"text": "Common Weakness Enumeration"},
        "informationUri": "https://cwe.mitre.org/",
        "isComprehensive": False,
        "taxa": list(seen.values()),
    }


def _result_for(finding: Finding, artifact_uri: str) -> dict:
    meta = finding.meta
    uri = finding.artifact_uri or artifact_uri
    return {
        "ruleId": meta.rule_id,
        "level": SEVERITY_TO_SARIF.get(meta.severity, "warning"),
        "message": {
            "text": f"{meta.title}: {meta.description} "
                    f"(severity={meta.severity}, confidence={finding.confidence})"
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {
                    "startLine": max(1, int(finding.line)),
                    "startColumn": max(1, int(finding.column)),
                    "snippet": {"text": finding.snippet[:400]} if finding.snippet else {},
                },
            }
        }],
        "partialFingerprints": {"sinkline/v1": finding.fingerprint()},
        "taxa": [{
            "id": meta.cwe,
            "toolComponent": {"name": "CWE"},
        }],
        "properties": {
            "confidence": finding.confidence,
            "risk_score": round(float(finding.risk_score), 4),
            "cwe": meta.cwe,
        },
    }


def to_sarif(findings: List[Finding], artifact_uri: str = "analyzed_snippet.py") -> dict:
    """Build a complete, schema-valid SARIF 2.1.0 document."""
    results = [_result_for(f, artifact_uri) for f in findings]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": INFO_URI,
                    "rules": _build_rules(),
                    "supportedTaxonomies": [{"name": "CWE"}],
                }
            },
            "taxonomies": [_build_cwe_taxonomy()],
            "results": results,
            "properties": {
                "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "findingCount": len(results),
            },
        }],
    }


def sarif_string(findings: List[Finding], artifact_uri: str = "analyzed_snippet.py") -> str:
    return safe_json_dumps(to_sarif(findings, artifact_uri))


# --------------------------------------------------------------------------- #
# Flat JSON audit report
# --------------------------------------------------------------------------- #
def to_json_report(findings: List[Finding], extra: Dict[str, Any] | None = None) -> dict:
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    report = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_findings": len(findings),
            "by_severity": sev_counts,
            "max_cvss": max((f.cvss for f in findings), default=0.0),
        },
        "findings": [f.to_dict() for f in findings],
    }
    if extra:
        report.update(extra)
    return report


def json_report_string(findings: List[Finding], extra: Dict[str, Any] | None = None) -> str:
    return safe_json_dumps(to_json_report(findings, extra))
