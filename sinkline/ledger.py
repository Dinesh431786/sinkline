"""
ledger.py — Tamper-Evident Audit Ledger for Scan Results
========================================================
A lightweight, **hash-chained append-only log** of Sinkline scans. Each record
commits to the SHA-256 of the previous record (Merkle/blockchain-style hash
chaining), so any later edit or deletion of a past result breaks the chain and
is detected by :func:`verify_ledger`.

This is the genuinely useful primitive behind "put it on a blockchain" — it
gives integrity and non-repudiation of an audit trail — *without* a distributed
ledger, consensus, tokens, or proof-of-work, none of which a local security
scanner needs. It aligns with how real supply-chain security attests artifacts
(SLSA provenance / in-toto / Sigstore): commit to a content hash, chain it, and
optionally sign it.

Format: newline-delimited JSON (JSONL); one record per line. Stdlib only.

Optional signing: if the ``SINKLINE_LEDGER_KEY`` environment variable is set, each
record is HMAC-SHA256 signed with it, so only a holder of the key can append a
record that verifies — a simple non-repudiation layer for a team/CI.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

GENESIS_PREV = "0" * 64
_KEY_ENV = "SINKLINE_LEDGER_KEY"


def _canonical(d: dict) -> bytes:
    """Deterministic JSON encoding for hashing (sorted keys, no whitespace)."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_hash(body: dict) -> str:
    return hashlib.sha256(_canonical(body)).hexdigest()


def _sign(body_hash: str, key: Optional[str]) -> str:
    if not key:
        return ""
    return hmac.new(key.encode("utf-8"), body_hash.encode("utf-8"),
                    hashlib.sha256).hexdigest()


@dataclass
class LedgerRecord:
    index: int
    timestamp: str
    target: str
    tool_version: str
    summary: Dict[str, int]        # finding counts by severity
    finding_count: int
    report_sha256: str             # hash of the exact report this record attests
    prev_hash: str
    record_hash: str = ""          # sha256 over the body (everything above)
    signature: str = ""            # optional HMAC-SHA256 over record_hash

    def body(self) -> dict:
        d = asdict(self)
        d.pop("record_hash")
        d.pop("signature")
        return d


def _read_records(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def append_scan(ledger_path: str, target: str, summary: Dict[str, int],
                finding_count: int, report_text: str, tool_version: str = "2.1.0",
                key: Optional[str] = None) -> LedgerRecord:
    """Append a tamper-evident record attesting a scan, return the new record."""
    if key is None:
        key = os.getenv(_KEY_ENV)
    existing = _read_records(ledger_path)
    prev_hash = existing[-1]["record_hash"] if existing else GENESIS_PREV
    rec = LedgerRecord(
        index=len(existing),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        target=target,
        tool_version=tool_version,
        summary=summary,
        finding_count=finding_count,
        report_sha256=hashlib.sha256(report_text.encode("utf-8", "replace")).hexdigest(),
        prev_hash=prev_hash,
    )
    rec.record_hash = _record_hash(rec.body())
    rec.signature = _sign(rec.record_hash, key)
    with open(ledger_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(rec), sort_keys=True) + "\n")
    return rec


def verify_ledger(ledger_path: str, key: Optional[str] = None) -> Tuple[bool, List[str]]:
    """Verify chain integrity. Returns (ok, problems[])."""
    if key is None:
        key = os.getenv(_KEY_ENV)
    records = _read_records(ledger_path)
    problems: List[str] = []
    prev_hash = GENESIS_PREV
    for i, raw in enumerate(records):
        # Rebuild the record to recompute its hash from the body.
        try:
            rec = LedgerRecord(**raw)
        except TypeError as e:
            problems.append(f"record {i}: malformed ({e})")
            continue
        if rec.index != i:
            problems.append(f"record {i}: index mismatch (got {rec.index})")
        if rec.prev_hash != prev_hash:
            problems.append(f"record {i}: broken chain — prev_hash does not match "
                            f"record {i-1} (deletion/reorder/tamper)")
        expected = _record_hash(rec.body())
        if rec.record_hash != expected:
            problems.append(f"record {i}: content tampered (hash mismatch)")
        if key:
            if rec.signature != _sign(rec.record_hash, key):
                problems.append(f"record {i}: bad/missing HMAC signature")
        prev_hash = rec.record_hash
    return (len(problems) == 0, problems)


def ledger_summary(ledger_path: str) -> str:
    records = _read_records(ledger_path)
    ok, problems = verify_ledger(ledger_path)
    lines = [f"Ledger: {ledger_path}", f"Records: {len(records)}",
             f"Integrity: {'OK (chain intact)' if ok else 'FAILED'}"]
    for p in problems:
        lines.append(f"  ! {p}")
    if records:
        last = records[-1]
        lines.append(f"Head hash: {last['record_hash'][:16]}…  "
                     f"({last['finding_count']} findings, {last['timestamp']})")
    return "\n".join(lines)


if __name__ == "__main__":
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "audit.ledger")
    append_scan(p, "pkg-a/", {"High": 2}, 2, "report-a")
    append_scan(p, "pkg-b/", {"Critical": 1}, 1, "report-b")
    print(ledger_summary(p)); print()
    # Tamper with the first record and show detection.
    lines = open(p).read().splitlines()
    rec0 = json.loads(lines[0]); rec0["finding_count"] = 0
    lines[0] = json.dumps(rec0, sort_keys=True)
    open(p, "w").write("\n".join(lines) + "\n")
    ok, problems = verify_ledger(p)
    print("After tampering -> integrity ok?", ok)
    for pr in problems:
        print("  detected:", pr)
