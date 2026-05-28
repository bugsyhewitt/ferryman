"""Tests for the anomaly check (out-of-range dates, suspicious metadata)."""

from __future__ import annotations

from ferryman.checks.anomaly import _check_transaction_amount, check_anomaly
from ferryman.parsing import Transaction


def test_out_of_range_date_detected(anomaly_file):
    findings = check_anomaly(anomaly_file.read_bytes())
    types = {f.type for f in findings}
    assert "out_of_range_date" in types, f"expected out_of_range_date, got: {types}"


def test_clean_file_no_anomaly(clean_file):
    findings = check_anomaly(clean_file.read_bytes())
    assert findings == [], f"clean file should have no anomalies, got: {findings}"


# --- amount anomaly detection (POST_V01 Rank 6) ----------------------------


def test_anomalous_amount_fixture_flags_all_cases(anomalous_amount_file):
    findings = check_anomaly(anomalous_amount_file.read_bytes())
    amount_findings = [f for f in findings if f.type == "anomalous_amount"]
    # zero DEBIT, positive DEBIT, negative CREDIT, out-of-range DEBIT.
    assert len(amount_findings) == 4, (
        f"expected four anomalous_amount findings, got: "
        f"{[(f.severity, f.evidence) for f in amount_findings]}"
    )


def test_zero_amount_is_high_severity():
    tx = Transaction(
        trntype="DEBIT", dtposted=None, name=None, memo=None, fitid="z",
        amount="0.00",
    )
    findings = _check_transaction_amount(tx, "stmt", "")
    assert len(findings) == 1
    assert findings[0].type == "anomalous_amount"
    assert findings[0].severity == "high"


def test_negative_zero_amount_flagged():
    tx = Transaction(
        trntype="CREDIT", dtposted=None, name=None, memo=None, fitid="nz",
        amount="-0.00",
    )
    findings = _check_transaction_amount(tx, "stmt", "")
    assert len(findings) == 1
    assert findings[0].type == "anomalous_amount"
    assert findings[0].severity == "high"


def test_positive_debit_is_sign_contradiction():
    tx = Transaction(
        trntype="DEBIT", dtposted=None, name=None, memo=None, fitid="d",
        amount="42.00",
    )
    findings = _check_transaction_amount(tx, "stmt", "")
    assert [f.type for f in findings] == ["anomalous_amount"]
    assert findings[0].severity == "medium"


def test_negative_credit_is_sign_contradiction():
    tx = Transaction(
        trntype="CREDIT", dtposted=None, name=None, memo=None, fitid="c",
        amount="-42.00",
    )
    findings = _check_transaction_amount(tx, "stmt", "")
    assert [f.type for f in findings] == ["anomalous_amount"]
    assert findings[0].severity == "medium"


def test_normal_debit_and_credit_not_flagged():
    # OFX sign convention: a debit is negative, a credit is positive.
    debit = Transaction(
        trntype="DEBIT", dtposted=None, name=None, memo=None, fitid="ok1",
        amount="-42.00",
    )
    credit = Transaction(
        trntype="CREDIT", dtposted=None, name=None, memo=None, fitid="ok2",
        amount="1500.00",
    )
    assert _check_transaction_amount(debit, "stmt", "") == []
    assert _check_transaction_amount(credit, "stmt", "") == []


def test_out_of_range_amount_flagged():
    tx = Transaction(
        trntype="DEBIT", dtposted=None, name=None, memo=None, fitid="big",
        amount="-99999999.99",
    )
    findings = _check_transaction_amount(tx, "stmt", "")
    assert [f.type for f in findings] == ["anomalous_amount"]
    assert findings[0].severity == "medium"


def test_unknown_type_only_flagged_for_zero_or_range():
    # A type not in the debit/credit sets has no sign convention to violate,
    # so a normal-magnitude amount of either sign is left alone.
    tx = Transaction(
        trntype="XFER", dtposted=None, name=None, memo=None, fitid="x",
        amount="250.00",
    )
    assert _check_transaction_amount(tx, "stmt", "") == []


def test_nonfinite_amount_left_to_malformed_check():
    # NaN / Inf are deliberately not flagged here -- the malformed check owns
    # "this field is garbage". _decimal_or_none rejects them to None.
    for bad in ("NaN", "Inf", "-Inf", "not-a-number"):
        tx = Transaction(
            trntype="DEBIT", dtposted=None, name=None, memo=None, fitid="g",
            amount=bad,
        )
        assert _check_transaction_amount(tx, "stmt", "") == []


def test_missing_amount_not_flagged():
    tx = Transaction(
        trntype="DEBIT", dtposted=None, name=None, memo=None, fitid="m",
        amount=None,
    )
    assert _check_transaction_amount(tx, "stmt", "") == []
