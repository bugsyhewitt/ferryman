"""Structured finding model for ferryman.

A Finding is the single unit of output produced by every check. Findings
serialise cleanly to JSON (for HackerOne report generation) and render to a
compact human-readable line for the ``--format text`` path.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

# Severity ordering, lowest to highest. Used for sorting and text rendering.
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(slots=True)
class Finding:
    """A single security finding emitted by a check.

    Attributes:
        check: Which check produced this finding -- one of
            ``malformed``, ``pii``, ``anomaly``.
        type: The specific finding class within a check, e.g. ``xxe`` for a
            malformed check or ``account_number`` for a pii check.
        severity: One of :data:`SEVERITIES`.
        message: Human-readable description of what was found.
        location: Where in the file the issue lives (line number, field path,
            transaction id, etc.). Free-form, may be ``None``.
        evidence: A short snippet of the offending content, truncated so we
            never echo a full PII payload back into a report.
        metadata: Arbitrary extra structured data for downstream tooling.
    """

    check: str
    type: str
    severity: str = "medium"
    message: str = ""
    location: str | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this finding."""
        return dataclasses.asdict(self)

    def to_text(self) -> str:
        """Return a single compact human-readable line."""
        sev = self.severity.upper()
        loc = f" @ {self.location}" if self.location else ""
        return f"[{sev}] {self.check}/{self.type}{loc}: {self.message}"


def truncate_evidence(value: str, limit: int = 80) -> str:
    """Truncate an evidence snippet so reports never carry a full payload.

    We deliberately keep evidence short: ferryman is a scanner, not an
    exfiltration tool. A truncated snippet is enough to triage a finding.
    """
    value = value.replace("\n", "\\n").replace("\r", "\\r")
    if len(value) <= limit:
        return value
    return value[:limit] + "..."
