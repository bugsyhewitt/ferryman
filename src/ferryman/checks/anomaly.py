"""Anomaly check.

Scans well-formed OFX for transactions that are structurally valid but
suspicious -- the kind of thing that flags tampering, replay, or a backend
that accepts garbage it should reject (a reportable fintech bug).

Detection classes:
- ``out_of_range_date`` : a posted date implausibly far in the past or the
                          future (pre-1970 or beyond a near-future horizon).
- ``negative_unit_price`` : an investment transaction with a negative unit
                          price -- a security cannot trade below zero, so a
                          negative ``UNITPRICE`` is tampering or a backend that
                          accepts garbage.
- ``negative_units`` : an investment transaction with negative quantity on a
                          transaction type that is not a sell/redeem -- only
                          sells legitimately reduce a holding.
- ``implausible_unit_price`` : an investment unit price above a sane ceiling,
                          a classic out-of-range / overflow probe.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from ferryman.findings import Finding
from ferryman.parsing import Transaction, parse_statements

# OFX predates 1970 in no legitimate consumer context; anything before this or
# absurdly far into the future is an anomaly worth a finding.
_MIN_YEAR = 1970
_MAX_YEAR = datetime.now(timezone.utc).year + 5

# No publicly traded security trades above this per-unit price; a value beyond
# it is an out-of-range / overflow probe rather than a real quote. (Berkshire
# Hathaway Class A, the most expensive listed share, is comfortably under $1M.)
_MAX_UNIT_PRICE = Decimal("1000000")

# Investment transaction types whose name signals a reduction of a holding --
# only these may legitimately carry a negative quantity.
_SELL_TYPE_KEYWORDS = ("SELL", "REDEEM")


def _decimal_or_none(value: str | None) -> Decimal | None:
    """Parse a finite decimal defensively; return ``None`` otherwise.

    ``Decimal("NaN")`` / ``Decimal("Inf")`` parse without error but raise
    ``InvalidOperation`` on comparison, so we reject any non-finite value here
    and let the malformed check own the "this field is garbage" verdict.
    """
    if value is None:
        return None
    try:
        d = Decimal(value)
    except (InvalidOperation, ValueError):
        return None
    if not d.is_finite():
        return None
    return d


def _check_investment_amounts(
    tx: Transaction, base: str, fitid: str
) -> list[Finding]:
    """Flag implausible price/quantity on a single investment transaction."""
    findings: list[Finding] = []

    unitprice = _decimal_or_none(tx.unitprice)
    if unitprice is not None:
        if unitprice < 0:
            findings.append(
                Finding(
                    check="anomaly",
                    type="negative_unit_price",
                    severity="high",
                    message=(
                        "Investment transaction has a negative unit price. A "
                        "security cannot trade below zero -- this signals "
                        "tampering or a backend that accepts garbage prices."
                    ),
                    location=f"{base}.unitprice{fitid}",
                    evidence=str(unitprice),
                )
            )
        elif unitprice > _MAX_UNIT_PRICE:
            findings.append(
                Finding(
                    check="anomaly",
                    type="implausible_unit_price",
                    severity="medium",
                    message=(
                        f"Investment unit price {unitprice} exceeds the "
                        f"plausible ceiling {_MAX_UNIT_PRICE}. Likely an "
                        "out-of-range or overflow probe."
                    ),
                    location=f"{base}.unitprice{fitid}",
                    evidence=str(unitprice),
                )
            )

    units = _decimal_or_none(tx.units)
    if units is not None and units < 0:
        trntype = tx.trntype or ""
        is_sell = any(kw in trntype for kw in _SELL_TYPE_KEYWORDS)
        if not is_sell:
            findings.append(
                Finding(
                    check="anomaly",
                    type="negative_units",
                    severity="high",
                    message=(
                        f"Investment transaction of type {trntype or 'unknown'} "
                        "has a negative quantity but is not a sell/redeem. Only "
                        "a sale legitimately reduces a holding."
                    ),
                    location=f"{base}.units{fitid}",
                    evidence=str(units),
                )
            )

    return findings


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

            if tx.is_investment:
                findings.extend(_check_investment_amounts(tx, base, fitid))

    return findings
