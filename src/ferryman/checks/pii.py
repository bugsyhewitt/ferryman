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
- ``iban``                    : an International Bank Account Number (ISO 13616)
                                whose country code, length, and mod-97 check
                                digits all validate -- a near-certain
                                international bank-account leak.
- ``isin``                    : an International Securities Identification Number
                                (ISO 6166) -- a 12-char country-code + NSIN +
                                Luhn check digit -- whose check digit validates,
                                a near-certain securities-holding leak.
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

# IBAN (ISO 13616) candidate. Two presentations are accepted:
#   - contiguous: a single 15-34 char run (e.g. DE89370400440532013000); and
#   - grouped:    space-separated blocks of up to four alphanumerics, the
#                 human-readable form (e.g. DE89 3704 0044 0532 0130 00).
# Both start with two letters (country code) and two digits (check digits). The
# run is bounded by a non-alphanumeric lookaround so an IBAN embedded in a longer
# blob is not partially matched. The grouped form requires each space to be
# *inside* a block sequence -- a trailing space followed by a normal word will
# not be swallowed, because a group is a run of alnum, not a single char. The
# caller strips spaces and validates country/length/mod-97 before reporting.
_IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z]{2}\d{2}"
    r"(?:"
    r"[A-Za-z0-9]{11,30}"            # contiguous BBAN
    r"|"
    r"[A-Za-z0-9]{0,2}(?: [A-Za-z0-9]{1,4}){2,8}"  # grouped (blocks of <=4)
    r")"
    r"(?![A-Za-z0-9])"
)
# Per-country total IBAN length (ISO 13616 registry). The mod-97 checksum alone
# does not prove an IBAN is real; pairing it with the registered length for the
# declared country code makes a coincidental alphanumeric run vanishingly
# unlikely to validate. Countries omitted here are simply not length-checked
# beyond the generic 15-34 range, so the registry can grow without code changes
# while still gating on country + checksum.
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
    "XK": 20,
}
# Generic ISO 13616 bounds for country codes not in the registry table.
_IBAN_MIN_LEN = 15
_IBAN_MAX_LEN = 34

# ISIN (ISO 6166) candidate: a 12-character run of two letters (country / "XS"
# for international issues), nine alphanumeric NSIN characters, and one trailing
# Luhn check digit. The run is bounded by a non-alphanumeric lookaround so an
# ISIN embedded in a longer alphanumeric blob is not partially matched. The
# caller validates the ISO 6166 check digit before reporting.
_ISIN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}[A-Z0-9]{9}\d(?![A-Za-z0-9])")
# ISINs are always exactly 12 characters.
_ISIN_LEN = 12


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


def _iban_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid IBAN (ISO 13616).

    Three independent gates, all public and dependency-free:

    1. **Shape** -- after stripping spaces, the value is 15-34 characters: two
       letters (country code), two digits (check digits), then an alphanumeric
       BBAN.
    2. **Country length** -- if the declared country code is in the ISO 13616
       registry, the total length must match exactly (e.g. a ``DE`` IBAN is
       always 22 characters). Unknown country codes fall back to the generic
       15-34 bound, so the registry can grow without code changes.
    3. **Mod-97 checksum** -- move the first four characters to the end, map each
       letter to a two-digit number (``A``=10 ... ``Z``=35), and the resulting
       integer must be ``== 1 (mod 97)``.

    A run that clears all three is a near-certain real IBAN; a coincidental
    alphanumeric blob fails one of them with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    iban = candidate.replace(" ", "").upper()
    if not (_IBAN_MIN_LEN <= len(iban) <= _IBAN_MAX_LEN):
        return False
    if not (iban[:2].isalpha() and iban[2:4].isdigit()):
        return False
    if not iban[4:].isalnum():
        return False
    country = iban[:2]
    expected = _IBAN_LENGTHS.get(country)
    if expected is not None and len(iban) != expected:
        return False
    # Rearrange: move the first four chars (country code + check digits) to the
    # end, then translate letters to numbers and take the value mod 97.
    rearranged = iban[4:] + iban[:4]
    digits = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged
    )
    return int(digits) % 97 == 1


def _trim_to_valid_iban(candidate: str) -> str | None:
    """Return the longest valid IBAN prefix of a captured run, or ``None``.

    The grouped-IBAN regex can over-capture trailing space-separated words
    (``"DE89 3704 ... 0130 00 on file"``) because short words look like IBAN
    blocks. We resolve the ambiguity at validation time: try the whole run, then
    progressively drop trailing space-separated tokens until the remainder
    validates (country code + registered length + mod-97). The first length-aware
    validating prefix is the real IBAN. Contiguous (space-free) candidates are
    validated directly. Returns the validating string (original spacing kept) or
    ``None`` if no prefix is a valid IBAN.
    """
    if " " not in candidate:
        return candidate if _iban_valid(candidate) else None
    tokens = candidate.split(" ")
    for end in range(len(tokens), 0, -1):
        prefix = " ".join(tokens[:end])
        if _iban_valid(prefix):
            return prefix
    return None


def _isin_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid ISIN (ISO 6166).

    An ISIN (International Securities Identification Number) is the global
    identifier for a security -- the value that legitimately lives in an OFX
    investment ``SECID``. Its public, dependency-free check is::

        1. Shape  -- exactly 12 characters: two letters (ISO 3166 country code,
           or ``XS`` for international issues), nine alphanumeric NSIN
           characters, and one trailing decimal check digit.
        2. Check digit -- expand every letter to its two-digit value
           (``A``=10 ... ``Z``=35), concatenate to a pure digit string, then
           verify the whole string (check digit included) passes the Luhn
           (mod-10) checksum.

    A run that clears both gates is a near-certain real ISIN; a coincidental
    alphanumeric blob fails the check digit with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    isin = candidate.strip().upper()
    if len(isin) != _ISIN_LEN:
        return False
    if not (isin[:2].isalpha() and isin[2:11].isalnum() and isin[11].isdigit()):
        return False
    # Expand letters to numbers, then Luhn over the whole (including check digit).
    digits = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in isin
    )
    return _luhn_valid(digits)


def _redact_isin(isin: str) -> str:
    """Redact an ISIN, preserving only the two-letter country/issuer prefix.

    The leading two letters identify the jurisdiction (useful for a report)
    while the NSIN body and check digit -- the part that pins the holding to a
    specific security -- are masked.
    """
    isin = isin.upper()
    return isin[:2] + "X" * (len(isin) - 2)


def _redact_ssn(text: str) -> str:
    return _SSN_RE.sub("XXX-XX-XXXX", text)


def _redact_digits(text: str) -> str:
    return re.sub(r"\d", "X", text)


def _redact_iban(iban: str) -> str:
    """Redact an IBAN, preserving only the country code for triage.

    The two-letter country code identifies the jurisdiction (useful for a
    report) while the check digits and the entire BBAN -- the part that is the
    actual account secret -- are masked. Spaces in the original presentation are
    preserved so the masked shape still reads as an IBAN.
    """
    out = []
    seen_alnum = 0
    for ch in iban:
        if ch == " ":
            out.append(" ")
        elif ch.isalnum():
            seen_alnum += 1
            out.append(ch if seen_alnum <= 2 else "X")
        else:
            out.append(ch)
    return "".join(out)


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

    # IBANs (ISO 13616) -- check before the credit-card and account-number runs.
    # An IBAN is an alphanumeric run, so it can embed long digit sequences that
    # the card / account / routing scanners would otherwise misclassify. We gate
    # on the country code, the registered length, AND the mod-97 checksum, so a
    # coincidental alphanumeric blob is vanishingly unlikely to be reported.
    for m in _IBAN_RE.finditer(text):
        candidate = _trim_to_valid_iban(m.group(0))
        if candidate is None:
            continue
        compact = candidate.replace(" ", "").upper()
        key = ("iban", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve every digit run inside the IBAN under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # leak as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="iban",
                severity="high",
                message="International Bank Account Number (IBAN, valid "
                "country/length/mod-97 checksum) leaking into a free-text field.",
                location=location,
                evidence=_redact_iban(candidate),
            )
        )

    # ISINs (ISO 6166) -- check before the credit-card and account-number runs.
    # An ISIN is a 12-char alphanumeric run that can embed a long digit tail the
    # account / card scanners would otherwise misclassify. We gate on the exact
    # 12-char shape AND the ISO 6166 Luhn check digit, so a coincidental
    # alphanumeric blob is vanishingly unlikely to be reported.
    for m in _ISIN_RE.finditer(text):
        candidate = m.group(0)
        if not _isin_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("isin", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the ISIN under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="isin",
                severity="high",
                message="International Securities Identification Number (ISIN, "
                "valid ISO 6166 check digit) leaking into a free-text field.",
                location=location,
                evidence=_redact_isin(compact),
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
