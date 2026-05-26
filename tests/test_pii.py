"""Tests for the PII-exposure check.

The PII check runs against well-formed OFX (parsed via ofxtools) and inspects
transaction free-text and account fields for leaked secrets.
"""

from __future__ import annotations

from ferryman.checks.pii import check_pii


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
    findings = check_pii(pii_file.read_bytes())
    types = {f.type for f in findings}
    assert "routing_number" in types, f"expected routing_number, got: {types}"


def test_clean_file_no_pii(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert findings == [], f"clean file should have no PII findings, got: {findings}"
