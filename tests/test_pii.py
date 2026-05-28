"""Tests for the PII-exposure check.

The PII check runs against well-formed OFX (parsed via ofxtools) and inspects
transaction free-text and account fields for leaked secrets.
"""

from __future__ import annotations

import pytest

from ferryman.checks.pii import _aba_checksum_valid, _luhn_valid, check_pii

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
