"""Tests for investment (INVSTMTRS) statement support.

ferryman v0.1 only iterated bank and credit statements. Phase 2 extends the
parsing layer to also flatten investment statements, and extends the pii and
anomaly checks to inspect investment-only surface (security ids, unit prices,
quantities). These tests exercise that path end to end against fixtures that
parse through ofxtools.
"""

from __future__ import annotations

from ferryman.checks.anomaly import check_anomaly
from ferryman.checks.pii import check_pii
from ferryman.parsing import parse_statements


# --- parsing ---------------------------------------------------------------


def test_investment_statement_is_parsed(investment_file):
    statements = parse_statements(investment_file.read_bytes())
    assert len(statements) == 1, "expected one investment statement"
    stmt = statements[0]
    assert stmt.is_investment is True
    # Investment accounts carry a broker id (mapped onto bankid) and acctid,
    # and have no bank account type.
    assert stmt.acctid == "987654321098"
    assert stmt.bankid == "fidelity.com"
    assert stmt.accttype is None


def test_investment_transactions_are_flattened(investment_file):
    stmt = parse_statements(investment_file.read_bytes())[0]
    assert len(stmt.transactions) == 2
    buy, sell = stmt.transactions
    # Class name becomes the transaction type; investment fields populate.
    assert buy.trntype == "BUYMF"
    assert buy.is_investment is True
    assert buy.units == "10.0"
    assert buy.unitprice == "100.00"
    assert buy.secid == "037833100"  # Apple CUSIP, fails ABA checksum
    assert buy.dtposted is not None and buy.dtposted.year == 2026
    assert sell.trntype == "SELLMF"
    assert sell.units == "-5.0"  # a sell legitimately carries negative units


def test_clean_investment_statement_has_no_findings(investment_file):
    raw = investment_file.read_bytes()
    assert check_pii(raw) == []
    assert check_anomaly(raw) == []


def test_bank_statements_still_parse_alongside_investment(pii_file):
    # Regression: the investment branch must not break bank statement parsing.
    stmt = parse_statements(pii_file.read_bytes())[0]
    assert stmt.is_investment is False
    assert stmt.accttype == "CHECKING"
    assert stmt.transactions and stmt.transactions[0].is_investment is False


# --- pii on investment surface --------------------------------------------


def test_ssn_in_investment_memo_detected(investment_pii_file):
    findings = check_pii(investment_pii_file.read_bytes())
    ssn = [f for f in findings if f.type == "ssn"]
    assert ssn, f"expected an ssn finding, got {[f.type for f in findings]}"
    assert ssn[0].severity == "critical"
    assert "123-45-6789" not in (ssn[0].evidence or "")


def test_ssn_in_security_id_detected(investment_secid_leak_file):
    findings = check_pii(investment_secid_leak_file.read_bytes())
    ssn = [f for f in findings if f.type == "ssn"]
    assert ssn, f"expected an ssn finding, got {[f.type for f in findings]}"
    assert "secid" in (ssn[0].location or "")
    assert "123-45-6789" not in (ssn[0].evidence or "")


def test_legitimate_numeric_cusip_is_not_a_false_positive(investment_file):
    # The clean fixture's CUSIP (037833100) is a 9-digit run. It must NOT be
    # mistaken for a routing/probable-routing number when seen in the secid.
    findings = check_pii(investment_file.read_bytes())
    types = {f.type for f in findings}
    assert "routing_number" not in types
    assert "probable_routing_number" not in types


# --- anomaly on investment surface ----------------------------------------


def test_negative_unit_price_detected(investment_pii_file):
    findings = check_anomaly(investment_pii_file.read_bytes())
    neg = [f for f in findings if f.type == "negative_unit_price"]
    assert neg, f"expected negative_unit_price, got {[f.type for f in findings]}"
    assert neg[0].severity == "high"


def test_negative_units_on_buy_detected(investment_pii_file):
    # The second transaction is a BUYMF with -3.0 units -- only a sell may
    # legitimately reduce a holding, so a negative-quantity buy is an anomaly.
    findings = check_anomaly(investment_pii_file.read_bytes())
    neg = [f for f in findings if f.type == "negative_units"]
    assert neg, f"expected negative_units, got {[f.type for f in findings]}"
    assert neg[0].severity == "high"


def test_negative_units_on_sell_is_not_flagged(investment_file):
    # The clean fixture's SELLMF has -5.0 units, which is legitimate for a sell.
    findings = check_anomaly(investment_file.read_bytes())
    assert not [f for f in findings if f.type == "negative_units"]


def test_implausible_unit_price_detected():
    raw = _build_investment_ofx(units="1.0", unitprice="5000000.00", total="5000000.00")
    findings = check_anomaly(raw)
    high = [f for f in findings if f.type == "implausible_unit_price"]
    assert high, f"expected implausible_unit_price, got {[f.type for f in findings]}"
    assert high[0].severity == "medium"


def test_garbage_unit_price_does_not_crash():
    # A non-decimal unit price must be parsed defensively and produce no finding
    # (the malformed check, not anomaly, is responsible for un-parseable data).
    raw = _build_investment_ofx(units="1.0", unitprice="NaN", total="0.00")
    findings = check_anomaly(raw)
    assert not [
        f
        for f in findings
        if f.type in {"negative_unit_price", "implausible_unit_price"}
    ]


def _build_investment_ofx(*, units: str, unitprice: str, total: str) -> bytes:
    """Build a minimal single-transaction investment OFX with given amounts."""
    return (
        "OFXHEADER:100\r\n"
        "DATA:OFXSGML\r\n"
        "VERSION:102\r\n"
        "SECURITY:NONE\r\n"
        "ENCODING:USASCII\r\n"
        "CHARSET:1252\r\n"
        "COMPRESSION:NONE\r\n"
        "OLDFILEUID:NONE\r\n"
        "NEWFILEUID:NONE\r\n"
        "\r\n"
        "<OFX>"
        "<SIGNONMSGSRSV1><SONRS><STATUS><CODE>0<SEVERITY>INFO</STATUS>"
        "<DTSERVER>20260101120000<LANGUAGE>ENG</SONRS></SIGNONMSGSRSV1>"
        "<INVSTMTMSGSRSV1><INVSTMTTRNRS><TRNUID>1001"
        "<STATUS><CODE>0<SEVERITY>INFO</STATUS>"
        "<INVSTMTRS><DTASOF>20260131000000<CURDEF>USD"
        "<INVACCTFROM><BROKERID>x.com<ACCTID>111222333444</INVACCTFROM>"
        "<INVTRANLIST><DTSTART>20260101000000<DTEND>20260131000000"
        "<BUYMF><INVBUY><INVTRAN><FITID>1<DTTRADE>20260105000000</INVTRAN>"
        "<SECID><UNIQUEID>037833100<UNIQUEIDTYPE>CUSIP</SECID>"
        f"<UNITS>{units}<UNITPRICE>{unitprice}<TOTAL>{total}"
        "<SUBACCTSEC>CASH<SUBACCTFUND>CASH</INVBUY><BUYTYPE>BUY</BUYMF>"
        "</INVTRANLIST></INVSTMTRS></INVSTMTTRNRS></INVSTMTMSGSRSV1></OFX>"
    ).encode()
