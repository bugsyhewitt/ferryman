"""PII-exposure check.

Scans well-formed OFX for personally-identifiable / sensitive information
leaking into fields where it does not belong -- the bug-bounty fintech angle
is free-text memos and names echoing SSNs, full account numbers, and routing
numbers that should never travel in a statement export.

Detection classes:
- ``ssn``                     : SSN-shaped strings (NNN-NN-NNNN) in free text.
- ``credit_card``             : a 13-19 digit run (allowing the conventional
                                space/dash grouping) that passes the Luhn
                                checksum -- a near-certain payment-card (PAN)
                                leak, PCI-DSS sensitive.
- ``account_number``          : a long account-number-shaped digit run leaking
                                into a transaction name/memo.
- ``routing_number``          : a 9-digit run that passes the ABA weighted
                                checksum -- a near-certain routing-number leak.
- ``probable_routing_number`` : a 9-digit run that fails the ABA checksum. Most
                                likely a coincidental digit run (zip+4, EIN-like
                                value, order/phone number). Emitted at ``info``
                                severity to preserve visibility without raising a
                                high-severity false positive.

For investment (INVSTMTRS) statements the same free-text scan runs over the
transaction memo, and the security identifier (``UNIQUEID`` / CUSIP) is scanned
with a narrower rule -- SSN-shaped values and over-long digit runs only -- so a
legitimate 9-digit numeric CUSIP is never mistaken for a routing number.

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

# Credit-card / PAN candidate: a 13-19 digit number, optionally written in the
# conventional groups of digits separated by a single space or hyphen
# (e.g. "4111 1111 1111 1111" or "4111-1111-1111-1111"). We bound the run with a
# non-digit lookaround so a card embedded in a longer digit blob is not partially
# matched. The full match may contain separators; the caller strips them before
# validating with Luhn.
_CARD_RE = re.compile(
    r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"
)
# Valid PAN lengths after stripping separators. Real card networks issue
# 13-19 digit numbers; we accept that whole range and let Luhn do the gating.
_CARD_MIN_LEN = 13
_CARD_MAX_LEN = 19

# ABA weighted-checksum coefficients, applied positionally to the 9 digits.
_ABA_WEIGHTS = (3, 7, 1, 3, 7, 1, 3, 7, 1)


def _luhn_valid(digits: str) -> bool:
    """Return ``True`` if a digit string passes the Luhn (mod-10) checksum.

    Luhn is the public, dependency-free check digit algorithm used by every
    major payment-card network (Visa, Mastercard, Amex, Discover, ...). Starting
    from the rightmost digit and moving left, every second digit is doubled
    (subtracting 9 if the result exceeds 9); the total of all digits must be a
    multiple of ten::

        sum(luhn_transform(d_i)) mod 10 == 0

    A 13-19 digit run that passes Luhn is a near-certain real PAN; one that fails
    is almost always a coincidental digit run (an order number, a long account
    id). Non-numeric input returns ``False`` so the helper is safe to reuse.
    """
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


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

    # Credit-card / PAN numbers -- check before the generic account-number run
    # so a Luhn-valid card is reported as the (critical) PCI-DSS leak it is, not
    # downgraded to a plain account-number finding. A card may be written with
    # the conventional space/dash grouping, so we strip separators before
    # validating the Luhn checksum and recording the run for dedupe. Runs that
    # fail Luhn are left untouched here and fall through to the account-number /
    # routing-number scanners below.
    for m in _CARD_RE.finditer(text):
        compact = re.sub(r"[ -]", "", m.group(0))
        if not (_CARD_MIN_LEN <= len(compact) <= _CARD_MAX_LEN):
            continue
        if not _luhn_valid(compact):
            continue
        # Dedupe on the compact digits so the same card written two different
        # ways (spaced vs unspaced) is reported once, and so the account-number
        # scanner below skips a run it has already claimed.
        key = ("credit_card", compact)
        if key in seen:
            continue
        seen.add(key)
        # Also reserve the compact digits under the account_number namespace so
        # the 8+-digit scanner never re-reports the same run as an account
        # number (it matches on contiguous digits, which the card may contain
        # when written without separators).
        seen.add(("account_number", compact))
        findings.append(
            Finding(
                check="pii",
                type="credit_card",
                severity="critical",
                message="Payment-card number (passing the Luhn checksum) "
                "leaking into a free-text field -- PCI-DSS sensitive.",
                location=location,
                evidence=_redact_digits(m.group(0)),
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


def _scan_secid(
    secid: str | None,
    *,
    location: str,
    findings: list[Finding],
    seen: set[tuple[str, str]],
) -> None:
    """Scan an investment security id for leaked PII.

    A security identifier is a CUSIP (9 alphanumeric chars) or ISIN (12 chars).
    Both are *expected* to be short, fixed-length codes, so we deliberately do
    NOT run the generic free-text scanner here -- a perfectly normal 9-digit
    numeric CUSIP would otherwise trip the routing-number heuristic on every
    investment statement. Instead we only flag the two patterns that are
    unambiguous leaks in this field:

    - an SSN-shaped value (``NNN-NN-NNNN``) -- structurally impossible for a real
      security id, so any match is a leak; and
    - a digit run of 10 or more characters -- longer than any CUSIP/ISIN, so it
      is an account-number-shaped value smuggled into the security id.
    """
    if not secid:
        return

    for m in _SSN_RE.finditer(secid):
        key = ("ssn", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="ssn",
                severity="critical",
                message="SSN-shaped value found in an investment security id.",
                location=location,
                evidence=_redact_ssn(m.group(0)),
            )
        )

    for m in re.finditer(r"\b\d{10,}\b", secid):
        key = ("account_number", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="account_number",
                severity="high",
                message="Account-number-shaped digit run leaking into an "
                "investment security id.",
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
            # Investment transactions expose a security identifier (CUSIP/ISIN
            # via UNIQUEID). A legitimate CUSIP is a 9-character alphanumeric
            # code, but a backend that echoes an SSN- or account-shaped value
            # into the security id is leaking PII through a field a bank/credit
            # statement does not even have -- so we scan it too.
            if tx.is_investment and tx.secid:
                _scan_secid(
                    tx.secid,
                    location=f"{base}.secid{fitid}",
                    findings=findings,
                    seen=seen,
                )

    return findings
