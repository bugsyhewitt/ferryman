"""Tests for the PII-exposure check.

The PII check runs against well-formed OFX (parsed via ofxtools) and inspects
transaction free-text and account fields for leaked secrets.
"""

from __future__ import annotations

import pytest

from ferryman.checks.pii import (
    _aba_checksum_valid,
    _iban_valid,
    _isin_valid,
    _luhn_valid,
    check_pii,
)

# Real, in-circulation ABA routing numbers (public information). Each must
# pass the weighted 3-7-1 checksum.
VALID_ABA = [
    "121000248",  # Wells Fargo (CA)
    "021000021",  # JPMorgan Chase (NY)
    "011401533",  # KeyBank
    "322271627",  # Chase (CA)
    "111000025",  # Bank of America (TX)
    "026009593",  # Bank of America (NY)
    "091000019",  # Wells Fargo (MN)
    "063100277",  # Bank of America (FL)
]

# 9-digit strings that are NOT valid routing numbers -- coincidental runs a
# memo might contain (zip+4, phone digits, order numbers, off-by-one ABA).
INVALID_NINE_DIGIT = [
    "123456789",  # sequential -- classic non-ABA collision
    "111111111",  # repeated digit
    "999999999",  # repeated digit
    "121000247",  # one off from a real ABA number -- checksum must catch it
    "867530912",  # phone-shaped run
    "100200304",  # arbitrary
]


@pytest.mark.parametrize("digits", VALID_ABA)
def test_aba_checksum_accepts_real_routing_numbers(digits):
    assert _aba_checksum_valid(digits) is True


@pytest.mark.parametrize("digits", INVALID_NINE_DIGIT)
def test_aba_checksum_rejects_non_routing_runs(digits):
    assert _aba_checksum_valid(digits) is False


@pytest.mark.parametrize(
    "bad",
    ["", "12345678", "1234567890", "12345678a", "abcdefghi", "12 345678"],
)
def test_aba_checksum_rejects_wrong_shape(bad):
    # Defensive: non-9-digit / non-numeric input is never "valid".
    assert _aba_checksum_valid(bad) is False


def test_ssn_in_memo_is_detected(pii_file):
    findings = check_pii(pii_file.read_bytes())
    types = {f.type for f in findings}
    assert "ssn" in types, f"expected an ssn finding, got: {types}"
    ssn = next(f for f in findings if f.type == "ssn")
    assert ssn.check == "pii"
    # Evidence must be redacted -- never echo a full SSN back.
    assert "123-45-6789" not in (ssn.evidence or "")


def test_account_number_leak_in_freetext_detected(pii_file):
    findings = check_pii(pii_file.read_bytes())
    types = {f.type for f in findings}
    assert "account_number" in types, f"expected account_number, got: {types}"


def test_routing_number_leak_detected(pii_file):
    # The shipped fixture leaks 121000248, a real ABA number (valid checksum),
    # so it must surface as a high-severity routing_number finding.
    findings = check_pii(pii_file.read_bytes())
    types = {f.type for f in findings}
    assert "routing_number" in types, f"expected routing_number, got: {types}"
    routing = next(f for f in findings if f.type == "routing_number")
    assert routing.severity == "high"
    assert "probable_routing_number" not in types


def _scan(text):
    """Run the free-text scanner over a single string and return findings."""
    from ferryman.checks.pii import _scan_text

    findings = []
    _scan_text(text, location="t", findings=findings, seen=set())
    return findings


def test_valid_aba_emits_high_severity_routing_number():
    findings = _scan("wire to routing 021000021 today")
    routing = [f for f in findings if f.type == "routing_number"]
    assert len(routing) == 1
    assert routing[0].severity == "high"
    # Evidence is redacted -- the raw digits never leave the scanner.
    assert "021000021" not in (routing[0].evidence or "")


def test_failing_checksum_downgrades_to_probable_info():
    # 123456789 is a 9-digit run that fails the ABA checksum.
    findings = _scan("order number 123456789 confirmed")
    types = {f.type for f in findings}
    assert "routing_number" not in types
    probable = [f for f in findings if f.type == "probable_routing_number"]
    assert len(probable) == 1
    assert probable[0].severity == "info"
    assert "123456789" not in (probable[0].evidence or "")


def test_nine_digit_run_not_double_counted_as_account_number():
    # A 9-digit run must be classified exactly once -- as routing/probable --
    # and never also as an account_number, regardless of checksum result.
    valid = _scan("121000248")
    assert {f.type for f in valid} == {"routing_number"}

    invalid = _scan("123456789")
    assert {f.type for f in invalid} == {"probable_routing_number"}


def test_clean_file_no_pii(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert findings == [], f"clean file should have no PII findings, got: {findings}"


# --- Credit-card / PAN detection (Luhn-gated) ---

# Well-known network test PANs -- all pass the Luhn checksum.
VALID_PANS = [
    "4111111111111111",  # Visa test number (16)
    "4012888888881881",  # Visa test number (16)
    "5500005555555559",  # Mastercard test number (16)
    "5105105105105100",  # Mastercard test number (16)
    "340000000000009",   # Amex test number (15)
    "6011000000000004",  # Discover test number (16)
    "4222222222222",     # Visa test number (13)
]

# 13-19 digit runs that FAIL Luhn -- coincidental long digit blobs a memo might
# carry (order ids, padded account numbers) that must not be called a card.
INVALID_PANS = [
    "4111111111111112",  # one off a real Visa test PAN
    "1234567890123456",  # sequential 16-digit run
    "0000000000000001",  # arbitrary 16-digit run
]


@pytest.mark.parametrize("pan", VALID_PANS)
def test_luhn_accepts_real_card_numbers(pan):
    assert _luhn_valid(pan) is True


@pytest.mark.parametrize("pan", INVALID_PANS)
def test_luhn_rejects_non_card_runs(pan):
    assert _luhn_valid(pan) is False


@pytest.mark.parametrize("bad", ["", "abc", "41111111111111a", "4111 1111"])
def test_luhn_rejects_non_numeric(bad):
    # Defensive: separators / letters are never valid -- the caller strips
    # separators before calling, so this guards reuse of the helper.
    assert _luhn_valid(bad) is False


def test_credit_card_unspaced_detected():
    findings = _scan("refund to card 4111111111111111 today")
    cards = [f for f in findings if f.type == "credit_card"]
    assert len(cards) == 1
    assert cards[0].severity == "critical"
    assert cards[0].check == "pii"
    # The raw PAN never leaves the scanner.
    assert "4111111111111111" not in (cards[0].evidence or "")
    # A Luhn-valid card must NOT also be reported as a plain account number.
    assert "account_number" not in {f.type for f in findings}


def test_credit_card_spaced_and_dashed_detected():
    for text in (
        "card 4111 1111 1111 1111 on file",
        "card 4111-1111-1111-1111 on file",
    ):
        cards = [f for f in _scan(text) if f.type == "credit_card"]
        assert len(cards) == 1, f"expected one card for {text!r}"
        assert cards[0].severity == "critical"
        # Evidence keeps the separators visible but redacts the digits.
        assert "1111" not in (cards[0].evidence or "")


def test_same_card_two_formats_deduped_per_field():
    # The same PAN written spaced and unspaced in one field is one finding.
    findings = _scan("card 4111 1111 1111 1111 aka 4111111111111111")
    cards = [f for f in findings if f.type == "credit_card"]
    assert len(cards) == 1


def test_luhn_failing_run_falls_through_to_account_number():
    # A 16-digit run that fails Luhn is not a card; it still surfaces as an
    # account-number-shaped leak (the existing 8+-digit heuristic).
    findings = _scan("ref 1234567890123456 logged")
    types = {f.type for f in findings}
    assert "credit_card" not in types
    assert "account_number" in types


def test_short_run_not_treated_as_card():
    # A 12-digit run is below the 13-digit card floor -- account number only.
    findings = _scan("order 123456789012 confirmed")
    types = {f.type for f in findings}
    assert "credit_card" not in types
    assert "account_number" in types


def test_credit_card_leak_fixture(credit_card_file):
    findings = check_pii(credit_card_file.read_bytes())
    types = {f.type for f in findings}
    assert "credit_card" in types, f"expected credit_card, got: {types}"
    cards = [f for f in findings if f.type == "credit_card"]
    # Two transactions leak Luhn-valid PANs (one spaced+dashed across name/memo
    # that dedupes to one, plus the Mastercard test number in the second tx).
    assert all(c.severity == "critical" for c in cards)
    for c in cards:
        # No raw card digits anywhere in the evidence.
        assert not any(ch.isdigit() for ch in (c.evidence or "")) or "X" in (
            c.evidence or ""
        )


def test_clean_file_no_credit_card(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "credit_card" not in {f.type for f in findings}


# --- IBAN detection (mod-97, country/length gated) ---

# Published example / test IBANs from the ISO 13616 registry. All valid.
VALID_IBANS = [
    "DE89370400440532013000",         # Germany (22)
    "GB82WEST12345698765432",         # United Kingdom (22)
    "FR1420041010050500013M02606",    # France (27, alphanumeric BBAN)
    "NL91ABNA0417164300",             # Netherlands (18)
    "BE68539007547034",               # Belgium (16)
    "CH9300762011623852957",          # Switzerland (21)
    "NO9386011117947",                # Norway (15, shortest)
    "MT84MALT011000012345MTLCAST001S",  # Malta (31, near longest)
]

# Strings shaped like an IBAN but failing one of the three gates -- they must
# NOT be reported as IBANs.
INVALID_IBANS = [
    "DE89370400440532013001",   # valid shape/length, wrong mod-97 check digit
    "GB00WEST12345698765432",   # check digits 00 -- fails mod-97
    "DE8937040044053201300",    # one char short for DE -- length gate
    "DE893704004405320130000",  # one char long for DE -- length gate
    "XX001234567890123456",     # unknown country + bad checksum
    "1234567890123456789",      # no country code at all
]


@pytest.mark.parametrize("iban", VALID_IBANS)
def test_iban_accepts_real_ibans(iban):
    assert _iban_valid(iban) is True


@pytest.mark.parametrize("iban", INVALID_IBANS)
def test_iban_rejects_invalid(iban):
    assert _iban_valid(iban) is False


@pytest.mark.parametrize("bad", ["", "DE", "DE89", "  ", "DE89ABC", "de89!!!!"])
def test_iban_rejects_garbage(bad):
    # Defensive: malformed / too-short input is never a valid IBAN.
    assert _iban_valid(bad) is False


def test_iban_lowercase_and_spaced_accepted():
    # IBANs are case-insensitive and often presented in groups of four.
    assert _iban_valid("de89 3704 0044 0532 0130 00") is True


def test_iban_unspaced_detected():
    findings = _scan("wire to DE89370400440532013000 please")
    ibans = [f for f in findings if f.type == "iban"]
    assert len(ibans) == 1
    assert ibans[0].severity == "high"
    assert ibans[0].check == "pii"
    # The raw account portion never leaves the scanner.
    assert "370400440532013000" not in (ibans[0].evidence or "")
    # The country code survives for triage.
    assert (ibans[0].evidence or "").startswith("DE")


def test_iban_spaced_detected():
    findings = _scan("counterparty DE89 3704 0044 0532 0130 00 on file")
    ibans = [f for f in findings if f.type == "iban"]
    assert len(ibans) == 1
    assert ibans[0].severity == "high"
    # Spaced presentation keeps its grouping but redacts the digits.
    assert "3704" not in (ibans[0].evidence or "")


def test_iban_not_double_counted_as_account_number():
    # A valid IBAN embeds long digit runs; they must NOT also surface as a
    # separate account_number / routing_number / credit_card finding.
    findings = _scan("IBAN DE89370400440532013000 here")
    types = [f.type for f in findings]
    assert types.count("iban") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_invalid_iban_not_reported():
    # A bad-checksum IBAN-shaped run must NOT be reported as an IBAN. (Its digit
    # run is glued to the country-code letters, so it is not a word-bounded
    # account-number run either -- the existing account heuristic is unaffected.)
    findings = _scan("ref DE89370400440532013001 logged")
    types = {f.type for f in findings}
    assert "iban" not in types


def test_iban_does_not_swallow_following_account_number():
    # A spaced IBAN followed by a separate account-number run: the trailing run
    # is not absorbed into the IBAN and still surfaces on its own.
    findings = _scan("DE89 3704 0044 0532 0130 00 then acct 12345678 ok")
    types = [f.type for f in findings]
    assert types.count("iban") == 1
    assert "account_number" in types


def test_same_iban_deduped_per_field():
    findings = _scan("DE89370400440532013000 aka de89 3704 0044 0532 0130 00")
    ibans = [f for f in findings if f.type == "iban"]
    assert len(ibans) == 1


def test_iban_leak_fixture(iban_file):
    findings = check_pii(iban_file.read_bytes())
    ibans = [f for f in findings if f.type == "iban"]
    types = {f.type for f in findings}
    assert "iban" in types, f"expected iban, got: {types}"
    # The fixture leaks a German IBAN (spaced) and a UK IBAN; the XX value is a
    # bad-checksum decoy that must NOT be reported as an IBAN.
    assert len(ibans) == 2
    assert all(i.severity == "high" for i in ibans)
    for i in ibans:
        # No raw account digits remain in the evidence.
        assert "X" in (i.evidence or "")


def test_clean_file_no_iban(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "iban" not in {f.type for f in findings}


# --- ISIN detection (ISO 6166 Luhn-check-digit gated) ---

# Real, published ISINs. All carry a valid ISO 6166 check digit.
VALID_ISINS = [
    "US0378331005",  # Apple Inc.
    "US5949181045",  # Microsoft Corp.
    "GB0002634946",  # BAE Systems
    "DE000BAY0017",  # Bayer AG
    "FR0000131104",  # BNP Paribas
    "AU0000XVGZA3",  # an Australian ISIN with letters in the NSIN
]

# Strings shaped like an ISIN but failing the ISO 6166 check digit, or the
# 12-char shape -- they must NOT be reported as ISINs.
INVALID_ISINS = [
    "US0378331004",  # Apple ISIN with the wrong check digit
    "GB0002634945",  # BAE ISIN with the wrong check digit
    "XX0378331004",  # unknown country + wrong check digit
    "US037833100",   # 11 chars -- too short
    "US03783310059",  # 13 chars -- too long
    "0378331005AB",  # no leading country-code letters
]


@pytest.mark.parametrize("isin", VALID_ISINS)
def test_isin_accepts_real_isins(isin):
    assert _isin_valid(isin) is True


@pytest.mark.parametrize("isin", INVALID_ISINS)
def test_isin_rejects_invalid(isin):
    assert _isin_valid(isin) is False


@pytest.mark.parametrize("bad", ["", "US", "US0378", "  ", "US0378331!05"])
def test_isin_rejects_garbage(bad):
    # Defensive: malformed / too-short input is never a valid ISIN.
    assert _isin_valid(bad) is False


def test_isin_lowercase_accepted():
    # ISINs are case-insensitive; a lowercased value still validates.
    assert _isin_valid("us0378331005") is True


def test_isin_in_memo_detected():
    findings = _scan("sold security US0378331005 today")
    isins = [f for f in findings if f.type == "isin"]
    assert len(isins) == 1
    assert isins[0].severity == "high"
    assert isins[0].check == "pii"
    # The NSIN body / check digit never leave the scanner; only the country
    # prefix survives for triage.
    assert "0378331005" not in (isins[0].evidence or "")
    assert (isins[0].evidence or "").startswith("US")


def test_isin_not_double_counted_as_account_number():
    # An ISIN embeds a long digit tail; it must NOT also surface as a separate
    # account_number / routing_number / credit_card finding.
    findings = _scan("holding US0378331005 in the account")
    types = [f.type for f in findings]
    assert types.count("isin") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_invalid_isin_not_reported():
    # A wrong-check-digit ISIN-shaped run must NOT be reported as an ISIN.
    findings = _scan("ref US0378331004 logged")
    assert "isin" not in {f.type for f in findings}


def test_same_isin_deduped_per_field():
    findings = _scan("US0378331005 aka us0378331005 in two casings")
    isins = [f for f in findings if f.type == "isin"]
    assert len(isins) == 1


def test_isin_leak_fixture(isin_file):
    findings = check_pii(isin_file.read_bytes())
    isins = [f for f in findings if f.type == "isin"]
    types = {f.type for f in findings}
    assert "isin" in types, f"expected isin, got: {types}"
    # The fixture leaks a US ISIN and a GB ISIN in two memos; the XX value is a
    # wrong-check-digit decoy that must NOT be reported as an ISIN.
    assert len(isins) == 2
    assert all(i.severity == "high" for i in isins)
    for i in isins:
        # No raw NSIN digits remain in the evidence.
        assert "X" in (i.evidence or "")


def test_clean_file_no_isin(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "isin" not in {f.type for f in findings}
