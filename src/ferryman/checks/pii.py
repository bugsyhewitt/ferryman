"""PII-exposure check.

Scans well-formed OFX for personally-identifiable / sensitive information
leaking into fields where it does not belong -- the bug-bounty fintech angle
is free-text memos and names echoing SSNs, full account numbers, and routing
numbers that should never travel in a statement export.

Detection classes:
- ``ssn``                     : SSN-shaped strings (NNN-NN-NNNN) in free text.
- ``account_number``          : a long account-number-shaped digit run leaking
                                into a transaction name/memo.
- ``routing_number``          : a 9-digit run that passes the ABA weighted
                                checksum -- a near-certain routing-number leak.
- ``probable_routing_number`` : a 9-digit run that fails the ABA checksum. Most
                                likely a coincidental digit run (zip+4, EIN-like
                                value, order/phone number). Emitted at ``info``
                                severity to preserve visibility without raising a
                                high-severity false positive.

All evidence is redacted before it leaves the scanner -- ferryman reports the
presence of a leak, not the secret itself.
"""

from __future__ import annotations

import re

from ferryman.findings import Finding
from ferryman.parsing import parse_statements

# SSN: NNN-NN-NNNN, optionally with spaces. Word-bounded to avoid matching
# inside longer digit runs.
_SSN_RE = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")
# Routing/ABA number: exactly 9 digits, word-bounded.
_ROUTING_RE = re.compile(r"\b\d{9}\b")
# Account-number-shaped run: 8+ consecutive digits in free text.
_ACCT_RE = re.compile(r"\b\d{8,}\b")

# ABA weighted-checksum coefficients, applied positionally to the 9 digits.
_ABA_WEIGHTS = (3, 7, 1, 3, 7, 1, 3, 7, 1)


def _aba_checksum_valid(digits: str) -> bool:
    """Return ``True`` if a 9-digit string passes the ABA routing checksum.

    The ABA (American Bankers Association) routing number checksum is a public,
    dependency-free weighted sum over the nine digits using the repeating
    ``3-7-1`` weighting::

        (3*d1 + 7*d2 + d3 + 3*d4 + 7*d5 + d6 + 3*d7 + 7*d8 + d9) mod 10 == 0

    A 9-digit run that passes this is a near-certain real routing number; one
    that fails is almost always a coincidental digit run (zip+4, phone number,
    order number, EIN-shaped value). Non-numeric or wrong-length input returns
    ``False`` -- the caller has already matched exactly nine digits, but we stay
    defensive so the helper is safe to reuse.
    """
    if len(digits) != 9 or not digits.isdigit():
        return False
    total = sum(w * int(d) for w, d in zip(_ABA_WEIGHTS, digits))
    return total % 10 == 0


def _redact_ssn(text: str) -> str:
    return _SSN_RE.sub("XXX-XX-XXXX", text)


def _redact_digits(text: str) -> str:
    return re.sub(r"\d", "X", text)


def _scan_text(
    text: str | None,
    *,
    location: str,
    findings: list[Finding],
    seen: set[tuple[str, str]],
) -> None:
    """Scan a single free-text field for leaked secrets."""
    if not text:
        return

    for m in _SSN_RE.finditer(text):
        key = ("ssn", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="ssn",
                severity="critical",
                message="SSN-shaped value found in a free-text field.",
                location=location,
                evidence=_redact_ssn(m.group(0)),
            )
        )

    # Routing numbers (exactly 9 digits) -- check before generic account runs.
    # Gate the high-severity finding behind the ABA weighted checksum: a run
    # that passes is a near-certain routing-number leak; one that fails is most
    # likely a coincidental 9-digit value (zip+4, phone, order/EIN-shaped) and
    # is downgraded to an informational ``probable_routing_number`` so we keep
    # visibility without flooding reports with high-severity false positives.
    for m in _ROUTING_RE.finditer(text):
        digits = m.group(0)
        # Use a single dedupe namespace so the same 9-digit run is never both
        # classified as a routing/probable finding and an account-number run.
        key = ("routing_number", digits)
        if key in seen:
            continue
        seen.add(key)
        if _aba_checksum_valid(digits):
            findings.append(
                Finding(
                    check="pii",
                    type="routing_number",
                    severity="high",
                    message="9-digit ABA routing number (valid checksum) "
                    "leaking into free text.",
                    location=location,
                    evidence=_redact_digits(digits),
                )
            )
        else:
            findings.append(
                Finding(
                    check="pii",
                    type="probable_routing_number",
                    severity="info",
                    message="9-digit value shaped like a routing number but "
                    "failing the ABA checksum (likely a coincidental run).",
                    location=location,
                    evidence=_redact_digits(digits),
                )
            )

    # Account-number-shaped runs (8+ digits), excluding ones already counted
    # as a 9-digit routing number.
    for m in _ACCT_RE.finditer(text):
        if len(m.group(0)) == 9:
            continue  # already classified as routing above
        key = ("account_number", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="account_number",
                severity="high",
                message="Account-number-shaped digit run leaking into free text.",
                location=location,
                evidence=_redact_digits(m.group(0)),
            )
        )


def check_pii(raw: bytes) -> list[Finding]:
    """Scan well-formed OFX bytes for PII exposure in free-text fields."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for s_idx, stmt in enumerate(parse_statements(raw)):
        for t_idx, tx in enumerate(stmt.transactions):
            base = f"statement[{s_idx}].transaction[{t_idx}]"
            fitid = f" (fitid {tx.fitid})" if tx.fitid else ""
            _scan_text(
                tx.name,
                location=f"{base}.name{fitid}",
                findings=findings,
                seen=seen,
            )
            _scan_text(
                tx.memo,
                location=f"{base}.memo{fitid}",
                findings=findings,
                seen=seen,
            )

    return findings
