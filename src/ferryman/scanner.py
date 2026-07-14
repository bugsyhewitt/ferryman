"""Scan orchestration: run the selected checks over a file's bytes."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from ferryman import __version__
from ferryman.checks.anomaly import check_anomaly
from ferryman.checks.malformed import check_malformed
from ferryman.checks.pii import check_pii
from ferryman.findings import Finding

CHECKS = {
    "malformed": check_malformed,
    "pii": check_pii,
    "anomaly": check_anomaly,
}
CHECK_CHOICES = ("malformed", "pii", "anomaly", "all")


def scan_bytes(raw: bytes, check: str) -> list[Finding]:
    """Run the selected check (or all checks) over raw OFX bytes."""
    if check == "all":
        findings: list[Finding] = []
        for fn in CHECKS.values():
            findings.extend(fn(raw))
        return findings
    if check not in CHECKS:
        raise ValueError(f"unknown check: {check!r}")
    return CHECKS[check](raw)


def scan_file(path: str | Path, check: str) -> dict[str, Any]:
    """Scan a file and return a structured result dict.

    The result is the canonical JSON shape ferryman emits:
        {
          "tool": "ferryman",
          "version": "...",
          "file": "<path>",
          "check": "<check>",
          "summary": {"total": N, "by_severity": {...}, "by_type": {...}},
          "findings": [ {finding}, ... ]
        }
    """
    path = Path(path)
    raw = path.read_bytes()
    findings = scan_bytes(raw, check)

    by_severity = Counter(f.severity for f in findings)
    by_type = Counter(f.type for f in findings)

    return {
        "tool": "ferryman",
        "version": __version__,
        "file": str(path),
        "check": check,
        "summary": {
            "total": len(findings),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
        },
        "findings": [f.to_dict() for f in findings],
    }
