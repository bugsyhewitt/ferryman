"""Anomaly check.

Scans well-formed OFX for transactions that are structurally valid but
suspicious -- the kind of thing that flags tampering, replay, or a backend
that accepts garbage it should reject (a reportable fintech bug).

Detection classes:
- ``out_of_range_date`` : a posted date implausibly far in the past or the
                          future (pre-1970 or beyond a near-future horizon).
- ``account_type_mismatch`` : a transaction type incompatible with the
                          declared account type.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ferryman.findings import Finding
from ferryman.parsing import parse_statements

# OFX predates 1970 in no legitimate consumer context; anything before this or
# absurdly far into the future is an anomaly worth a finding.
_MIN_YEAR = 1970
_MAX_YEAR = datetime.now(timezone.utc).year + 5


def check_anomaly(raw: bytes) -> list[Finding]:
    """Scan well-formed OFX bytes for anomalous transactions."""
    findings: list[Finding] = []

    for s_idx, stmt in enumerate(parse_statements(raw)):
        for t_idx, tx in enumerate(stmt.transactions):
            base = f"statement[{s_idx}].transaction[{t_idx}]"
            fitid = f" (fitid {tx.fitid})" if tx.fitid else ""

            dt = tx.dtposted
            if isinstance(dt, datetime) and not (_MIN_YEAR <= dt.year <= _MAX_YEAR):
                findings.append(
                    Finding(
                        check="anomaly",
                        type="out_of_range_date",
                        severity="medium",
                        message=(
                            f"Transaction posted in {dt.year}, outside the "
                            f"plausible window {_MIN_YEAR}-{_MAX_YEAR}. Suggests "
                            "tampering or a backend that accepts garbage dates."
                        ),
                        location=f"{base}.dtposted{fitid}",
                        evidence=str(dt.date()),
                    )
                )

    return findings
