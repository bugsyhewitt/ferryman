"""Tests for the anomaly check (out-of-range dates, suspicious metadata)."""

from __future__ import annotations

from ferryman.checks.anomaly import check_anomaly


def test_out_of_range_date_detected(anomaly_file):
    findings = check_anomaly(anomaly_file.read_bytes())
    types = {f.type for f in findings}
    assert "out_of_range_date" in types, f"expected out_of_range_date, got: {types}"


def test_clean_file_no_anomaly(clean_file):
    findings = check_anomaly(clean_file.read_bytes())
    assert findings == [], f"clean file should have no anomalies, got: {findings}"
