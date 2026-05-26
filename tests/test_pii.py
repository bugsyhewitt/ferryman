"""Tests for the PII-exposure check.

The PII check runs against well-formed OFX (parsed via ofxtools) and inspects
transaction free-text and account fields for leaked secrets.
"""

from __future__ import annotations

import pytest

from ferryman.checks.pii import _aba_checksum_valid, check_pii

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
