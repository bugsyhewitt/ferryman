"""Tests for the PII-exposure check.

The PII check runs against well-formed OFX (parsed via ofxtools) and inspects
transaction free-text and account fields for leaked secrets.
"""

from __future__ import annotations

import pytest

from ferryman.checks.pii import (
    _aba_checksum_valid,
    _au_bsb_valid,
    _bic_valid,
    _br_cpf_valid,
    _ca_routing_valid,
    _ch_ahv_valid,
    _clabe_valid,
    _curp_valid,
    _cusip_valid,
    _dk_cpr_valid,
    _fi_hetu_valid,
    _iban_valid,
    _ifsc_valid,
    _isin_valid,
    _itin_valid,
    _kr_giro_valid,
    _kr_rrn_valid,
    _lei_valid,
    _luhn_valid,
    _nl_bsn_valid,
    _no_fnr_valid,
    _redact_email,
    _se_pnr_valid,
    _sedol_valid,
    _th_natid_valid,
    _tr_tckn_valid,
    _uk_sort_code_valid,
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


# --- ITIN detection (US Individual Taxpayer Identification Number) ---

# Structurally valid ITINs: area 900-999, middle group in 50-65 / 70-88 /
# 90-92 / 94-99. These cover each assigned middle range and its boundaries.
VALID_ITINS = [
    "900-50-0000",  # lower bound of the 50-65 range
    "912-65-1234",  # upper bound of 50-65
    "999-70-9999",  # lower bound of 70-88, max area + serial
    "900-88-0001",  # upper bound of 70-88
    "934-90-4567",  # 90-92 range
    "956-92-1111",  # upper bound of 90-92
    "978-94-2222",  # lower bound of 94-99
    "999-99-9999",  # upper bound of everything
]

# 9XX-shaped values that are NOT valid ITINs -- the reserved middle-group gaps
# (66-69, 89, 93) the IRS never assigns to a live ITIN.
INVALID_ITIN_MIDDLE = [
    "900-66-0000",  # 66-69 gap
    "900-69-0000",  # 66-69 gap
    "900-89-0000",  # 89 reserved
    "900-93-0000",  # 93 is the ATIN range, not an ITIN
    "900-49-0000",  # below the 50-65 floor
]


@pytest.mark.parametrize("itin", VALID_ITINS)
def test_itin_validator_accepts_real_itins(itin):
    assert _itin_valid(itin) is True


@pytest.mark.parametrize("itin", INVALID_ITIN_MIDDLE)
def test_itin_validator_rejects_reserved_middle_groups(itin):
    assert _itin_valid(itin) is False


def test_itin_validator_rejects_non_nine_area():
    # A leading area below 900 is a real SSN's space, never an ITIN.
    assert _itin_valid("123-45-6789") is False
    assert _itin_valid("899-70-0000") is False


@pytest.mark.parametrize(
    "bad",
    ["", "900-7-0000", "9OO-70-0000", "12345678", "1234567890", "abc-de-fghi"],
)
def test_itin_validator_rejects_garbage(bad):
    # Wrong length (after stripping separators) or non-numeric is never valid.
    assert _itin_valid(bad) is False


def test_itin_validator_works_on_stripped_digits():
    # Like the ABA/Luhn helpers, the validator operates on the candidate's
    # digits: a contiguous valid run validates; the NNN-NN-NNNN *presentation*
    # is enforced by the scanning regex, not the validator.
    assert _itin_valid("900700000") is True
    assert _itin_valid("900 70 0000") is True
    assert _itin_valid("900-70-0000") is True


def test_itin_in_freetext_detected_as_itin_not_ssn():
    findings = _scan("payroll for ITIN 900-70-0000")
    types = {f.type for f in findings}
    assert "itin" in types, f"expected itin, got: {types}"
    # A valid ITIN must NOT also be reported as a generic SSN-shaped finding.
    assert "ssn" not in types
    itin = next(f for f in findings if f.type == "itin")
    assert itin.severity == "critical"
    # Evidence is redacted -- the raw number never leaves the scanner.
    assert "900-70-0000" not in (itin.evidence or "")


def test_real_ssn_still_reported_as_ssn_not_itin():
    # A genuine SSN (area not 9XX) must fall through to the SSN detector.
    findings = _scan("customer SSN 123-45-6789 on file")
    types = {f.type for f in findings}
    assert "ssn" in types
    assert "itin" not in types


def test_reserved_middle_group_not_reported_as_itin():
    # 900-89-0000 is 9XX-shaped but in the reserved 89 group -- it is neither a
    # valid ITIN nor a valid SSN (SSN areas never begin with 9), so it is
    # claimed by the SSN detector's plain shape match but never as an ITIN.
    findings = _scan("ref 900-89-0000")
    types = {f.type for f in findings}
    assert "itin" not in types


def test_itin_deduped_per_field():
    # The same ITIN in name and memo of one field-scan collapses to one finding.
    findings = _scan("ITIN 900-70-0000 and again 900-70-0000")
    itins = [f for f in findings if f.type == "itin"]
    assert len(itins) == 1


def test_itin_leak_fixture(itin_file):
    findings = check_pii(itin_file.read_bytes())
    types = {f.type for f in findings}
    # The fixture carries two valid ITINs (in two fields) and one real SSN.
    assert "itin" in types, f"expected itin, got: {types}"
    assert "ssn" in types, f"expected ssn (the 123-45-6789 leak), got: {types}"
    itins = [f for f in findings if f.type == "itin"]
    assert len(itins) == 2
    for f in itins:
        assert f.severity == "critical"
        assert "900-70-0000" not in (f.evidence or "")
        assert "999-88-9999" not in (f.evidence or "")


def test_clean_file_no_itin(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert not [f for f in findings if f.type == "itin"]


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


# --- CUSIP detection (modulus-10 check-digit gated) ---

# Real, published CUSIPs with a valid modulus-10 check digit. Several carry a
# letter in the base (so the free-text regex detects them); IBM's all-numeric
# CUSIP validates at the helper level too.
VALID_CUSIPS = [
    "17275R102",  # Cisco Systems
    "88160R101",  # Tesla Inc.
    "38259P508",  # Alphabet Inc. (Google) Class A
    "30303M102",  # Meta Platforms Inc.
    "02079K305",  # Alphabet Inc. Class C
    "459200101",  # IBM (all-numeric base -- validator-level only)
]

# Strings shaped like a CUSIP but failing the modulus-10 check digit or the
# 9-char shape -- they must NOT validate.
INVALID_CUSIPS = [
    "17275R103",  # Cisco CUSIP with the wrong check digit
    "88160R102",  # Tesla CUSIP with the wrong check digit
    "38259P509",  # Alphabet CUSIP with the wrong check digit
    "17275R10",   # 8 chars -- too short
    "17275R1023",  # 10 chars -- too long
]


@pytest.mark.parametrize("cusip", VALID_CUSIPS)
def test_cusip_accepts_real_cusips(cusip):
    assert _cusip_valid(cusip) is True


@pytest.mark.parametrize("cusip", INVALID_CUSIPS)
def test_cusip_rejects_invalid(cusip):
    assert _cusip_valid(cusip) is False


@pytest.mark.parametrize("bad", ["", "17275R", "  ", "17275R10A", "17275R!02"])
def test_cusip_rejects_garbage(bad):
    # Defensive: malformed / too-short input is never a valid CUSIP. A
    # non-numeric check digit ("...0A") and a bad base char are both rejected.
    assert _cusip_valid(bad) is False


def test_cusip_char_value_table():
    # The legacy specials (* @ #) carry fixed values 36/37/38; letters map
    # A=10 ... Z=35; digits map to themselves; anything else is None.
    from ferryman.checks.pii import _cusip_char_value

    assert _cusip_char_value("*") == 36
    assert _cusip_char_value("@") == 37
    assert _cusip_char_value("#") == 38
    assert _cusip_char_value("A") == 10
    assert _cusip_char_value("Z") == 35
    assert _cusip_char_value("7") == 7
    assert _cusip_char_value("!") is None


def test_cusip_in_memo_detected():
    findings = _scan("sold security 17275R102 today")
    cusips = [f for f in findings if f.type == "cusip"]
    assert len(cusips) == 1
    assert cusips[0].severity == "high"
    assert cusips[0].check == "pii"
    # The base / check digit never leave the scanner; only the leading two
    # characters survive for triage.
    assert "275R102" not in (cusips[0].evidence or "")
    assert (cusips[0].evidence or "").startswith("17")


def test_cusip_lowercase_detected():
    # CUSIPs are case-insensitive; a lowercased value still validates and is
    # reported (the regex matches the letter; the validator upper-cases).
    findings = _scan("ticker cusip 17275r102 on file")
    cusips = [f for f in findings if f.type == "cusip"]
    assert len(cusips) == 1


def test_numeric_cusip_not_matched_in_freetext():
    # A purely numeric 9-digit run (e.g. Apple's 037833100) lives in the ABA
    # routing-number space; the CUSIP regex requires a letter so it is NOT
    # reported as a cusip -- it falls through to the routing/probable path.
    findings = _scan("order 037833100 confirmed")
    types = {f.type for f in findings}
    assert "cusip" not in types
    assert types & {"routing_number", "probable_routing_number"}


def test_cusip_not_double_counted_as_account_number():
    # A CUSIP must be classified once -- as a cusip -- and never also as an
    # account_number / routing_number / credit_card finding.
    findings = _scan("holding 88160R101 in the account")
    types = [f.type for f in findings]
    assert types.count("cusip") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_invalid_cusip_not_reported():
    # A wrong-check-digit CUSIP-shaped run must NOT be reported as a cusip.
    findings = _scan("ref 17275R103 logged")
    assert "cusip" not in {f.type for f in findings}


def test_isin_wins_over_embedded_cusip():
    # A US ISIN embeds a CUSIP as positions 3-11; the longer 12-char ISIN match
    # claims the run, so a valid US ISIN reports as isin, not cusip.
    findings = _scan("US0378331005 holding")
    types = [f.type for f in findings]
    assert types.count("isin") == 1
    assert "cusip" not in types


def test_same_cusip_deduped_per_field():
    findings = _scan("17275R102 aka 17275r102 in two casings")
    cusips = [f for f in findings if f.type == "cusip"]
    assert len(cusips) == 1


def test_cusip_leak_fixture(cusip_file):
    findings = check_pii(cusip_file.read_bytes())
    cusips = [f for f in findings if f.type == "cusip"]
    types = {f.type for f in findings}
    assert "cusip" in types, f"expected cusip, got: {types}"
    # The fixture leaks two valid CUSIPs in memos; the wrong-check-digit decoy
    # must NOT be reported, and the CUSIPs sitting in their own SECID fields are
    # legitimate (not a leak) and must NOT be flagged from there.
    assert len(cusips) == 2
    assert all(c.severity == "high" for c in cusips)
    for c in cusips:
        # No raw base digits remain in the evidence.
        assert "X" in (c.evidence or "")


def test_clean_file_no_cusip(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "cusip" not in {f.type for f in findings}


# --- SEDOL detection (weighted modulus-10 check-digit gated) ---

# Real, published SEDOLs with a valid weighted check digit, each carrying a
# letter in the base (so the free-text regex detects them). Vowels are never
# present in a SEDOL base.
VALID_SEDOLS = [
    "B16GWD5",
    "B0YBKL9",
    "B1YW440",
    "BH4HKS3",
]

# All-numeric SEDOLs validate at the helper level (the check digit is correct)
# but are deliberately NOT matched in free text -- a pure 7-digit run lives in
# the coincidental-digit space, so the regex requires a letter in the base.
VALID_NUMERIC_SEDOLS = [
    "0263494",
    "0540528",
]

# Strings shaped like a SEDOL but failing the weighted check digit, carrying a
# vowel in the base, or the wrong length -- they must NOT validate.
INVALID_SEDOLS = [
    "B16GWD6",  # right base, wrong check digit
    "B0YBKL0",  # right base, wrong check digit
    "BA6GWD5",  # vowel (A) in the base -- structurally impossible
    "B16GWD",   # 6 chars -- too short
    "B16GWD53",  # 8 chars -- too long
]


@pytest.mark.parametrize("sedol", VALID_SEDOLS + VALID_NUMERIC_SEDOLS)
def test_sedol_accepts_real_sedols(sedol):
    assert _sedol_valid(sedol) is True


@pytest.mark.parametrize("sedol", INVALID_SEDOLS)
def test_sedol_rejects_invalid(sedol):
    assert _sedol_valid(sedol) is False


@pytest.mark.parametrize("bad", ["", "B16GW", "  ", "B16GWDA", "B16GW!5"])
def test_sedol_rejects_garbage(bad):
    # Defensive: malformed / too-short input is never a valid SEDOL. A
    # non-numeric check digit ("...DA") and a bad base char are both rejected.
    assert _sedol_valid(bad) is False


def test_sedol_in_memo_detected():
    findings = _scan("sold security B16GWD5 today")
    sedols = [f for f in findings if f.type == "sedol"]
    assert len(sedols) == 1
    assert sedols[0].severity == "high"
    assert sedols[0].check == "pii"
    # The base / check digit never leave the scanner; only the leading character
    # survives for triage.
    assert "16GWD5" not in (sedols[0].evidence or "")
    assert (sedols[0].evidence or "").startswith("B")


def test_sedol_lowercase_detected():
    # SEDOLs are case-insensitive; a lowercased value still validates and is
    # reported (the regex matches the letter; the validator upper-cases).
    findings = _scan("ticker sedol b16gwd5 on file")
    sedols = [f for f in findings if f.type == "sedol"]
    assert len(sedols) == 1


def test_numeric_sedol_not_matched_in_freetext():
    # A purely numeric 7-digit run validates at the helper level but the SEDOL
    # regex requires a letter, so it is NOT reported as a sedol. A 7-digit run is
    # too short for the account-number scanner (8+) and not 9 digits, so it
    # produces no pii finding at all -- which is the correct, quiet behaviour.
    findings = _scan("order 0263494 confirmed")
    types = {f.type for f in findings}
    assert "sedol" not in types


def test_sedol_not_double_counted_as_account_number():
    # A SEDOL must be classified once -- as a sedol -- and never also as an
    # account_number / routing_number / credit_card finding.
    findings = _scan("holding B0YBKL9 in the account")
    types = [f.type for f in findings]
    assert types.count("sedol") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_invalid_sedol_not_reported():
    # A wrong-check-digit SEDOL-shaped run must NOT be reported as a sedol.
    findings = _scan("ref B16GWD6 logged")
    assert "sedol" not in {f.type for f in findings}


def test_sedol_does_not_break_cusip_or_isin():
    # The 7-char SEDOL regex must not partially match inside a longer 9-char
    # CUSIP or 12-char ISIN run (the non-alphanumeric lookarounds prevent it).
    cusip_findings = _scan("sold security 17275R102 today")
    assert [f.type for f in cusip_findings] == ["cusip"]
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]


def test_same_sedol_deduped_per_field():
    findings = _scan("B16GWD5 aka b16gwd5 in two casings")
    sedols = [f for f in findings if f.type == "sedol"]
    assert len(sedols) == 1


def test_sedol_leak_fixture(sedol_file):
    findings = check_pii(sedol_file.read_bytes())
    sedols = [f for f in findings if f.type == "sedol"]
    types = {f.type for f in findings}
    assert "sedol" in types, f"expected sedol, got: {types}"
    # The fixture leaks two valid SEDOLs in memos; the wrong-check-digit decoy
    # must NOT be reported, and the SEDOLs sitting in their own SECID fields are
    # legitimate (not a leak) and must NOT be flagged from there.
    assert len(sedols) == 2
    assert all(s.severity == "high" for s in sedols)
    for s in sedols:
        # No raw base characters remain in the evidence.
        assert "X" in (s.evidence or "")


def test_clean_file_no_sedol(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "sedol" not in {f.type for f in findings}


# --- LEI detection (ISO 17442 / ISO 7064 mod-97-10 check-digit gated) ---

# Real, published Legal Entity Identifiers (GLEIF registry, public information).
# Each must pass the ISO 7064 mod-97-10 check over the whole 20-char value.
VALID_LEIS = [
    "529900T8BM49AURSDO55",  # Allianz SE
    "5493001KJTIIGC8Y1R12",  # Bloomberg Finance L.P.
    "7LTWFZYICNSX8D621K86",  # Deutsche Bank AG
    "F3JS33DEI6XQ4ZBPTN86",  # NASDAQ, Inc.
    "213800WSGIIZCXF1P572",  # an in-registry entity
]

# Strings shaped like an LEI but failing the mod-97-10 check digits, or the
# wrong length / wrong check-digit shape -- they must NOT validate.
INVALID_LEIS = [
    "529900T8BM49AURSDO56",  # right entity portion, wrong check digits
    "7LTWFZYICNSX8D621K87",  # right entity portion, wrong check digits
    "529900T8BM49AURSDO5",   # 19 chars -- too short
    "529900T8BM49AURSDO555",  # 21 chars -- too long
    "529900T8BM49AURSDOAA",  # non-numeric check positions
]


@pytest.mark.parametrize("lei", VALID_LEIS)
def test_lei_accepts_real_leis(lei):
    assert _lei_valid(lei) is True


@pytest.mark.parametrize("lei", INVALID_LEIS)
def test_lei_rejects_invalid(lei):
    assert _lei_valid(lei) is False


@pytest.mark.parametrize(
    "bad", ["", "529900", "  ", "529900T8BM49AURSDO5!", "X" * 20]
)
def test_lei_rejects_garbage(bad):
    # Defensive: malformed / too-short / non-alphanumeric input is never a valid
    # LEI. An all-letter run ("X"*20) fails the numeric check-digit shape.
    assert _lei_valid(bad) is False


def test_lei_lowercase_accepted_by_validator():
    # LEIs are case-insensitive; the validator upper-cases before checking.
    assert _lei_valid("529900t8bm49aursdo55") is True


def test_lei_in_memo_detected():
    findings = _scan("settled with counterparty 529900T8BM49AURSDO55 today")
    leis = [f for f in findings if f.type == "lei"]
    assert len(leis) == 1
    assert leis[0].severity == "high"
    assert leis[0].check == "pii"
    # Only the leading four-character LOU prefix survives for triage; the entity
    # portion and check digits never leave the scanner.
    assert "T8BM49AURSDO55" not in (leis[0].evidence or "")
    assert (leis[0].evidence or "").startswith("5299")
    assert "X" in (leis[0].evidence or "")


def test_lei_lowercase_detected_in_freetext():
    findings = _scan("issuer 529900t8bm49aursdo55 on the trade ticket")
    leis = [f for f in findings if f.type == "lei"]
    assert len(leis) == 1


def test_invalid_lei_not_reported():
    # A wrong-check-digit LEI-shaped run must NOT be reported as an lei.
    findings = _scan("ref 529900T8BM49AURSDO56 logged")
    assert "lei" not in {f.type for f in findings}


def test_lei_not_double_counted_as_account_number():
    # An LEI must be classified once -- as an lei -- and never also as an
    # account_number / routing_number / credit_card finding for the digit runs
    # embedded in its 20 characters.
    findings = _scan("counterparty 529900T8BM49AURSDO55 in the account")
    types = [f.type for f in findings]
    assert types.count("lei") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_lei_does_not_break_shorter_identifiers():
    # The 20-char LEI regex must not interfere with the shorter ISIN (12),
    # CUSIP (9), or SEDOL (7) detectors when those appear on their own.
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]
    cusip_findings = _scan("sold security 17275R102 today")
    assert [f.type for f in cusip_findings] == ["cusip"]
    sedol_findings = _scan("holding B16GWD5 noted")
    assert [f.type for f in sedol_findings] == ["sedol"]


def test_same_lei_deduped_per_field():
    findings = _scan("529900T8BM49AURSDO55 aka 529900t8bm49aursdo55 twice")
    leis = [f for f in findings if f.type == "lei"]
    assert len(leis) == 1


def test_lei_leak_fixture(lei_file):
    findings = check_pii(lei_file.read_bytes())
    leis = [f for f in findings if f.type == "lei"]
    types = {f.type for f in findings}
    assert "lei" in types, f"expected lei, got: {types}"
    # The fixture leaks two valid LEIs in memos; the wrong-check-digit decoy must
    # NOT be reported.
    assert len(leis) == 2
    assert all(le.severity == "high" for le in leis)
    for le in leis:
        # No raw entity portion remains in the evidence.
        assert "X" in (le.evidence or "")


def test_clean_file_no_lei(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "lei" not in {f.type for f in findings}


# --- BIC / SWIFT detection (ISO 9362 structure + country-code gated) ---

# Real, published BIC/SWIFT codes (public information). Each must pass the
# structure + country code + location-code rules. Both the 8-char (head office)
# and 11-char (with branch code) forms are represented.
VALID_BICS = [
    "DEUTDEFF",      # Deutsche Bank, Frankfurt (8-char)
    "DEUTDEFF500",   # Deutsche Bank, Frankfurt, branch 500 (11-char)
    "BOFAUS3N",      # Bank of America, US
    "CHASUS33",      # JPMorgan Chase, US
    "NWBKGB2L",      # NatWest, GB
    "BNPAFRPP",      # BNP Paribas, FR
    "UBSWCHZH80A",   # UBS, Zurich, branch 80A (11-char)
    "HBUKGB4B",      # HSBC, GB
]

# Strings shaped like a BIC but failing the structure, the country code, or the
# location-code rules -- they must NOT validate.
INVALID_BICS = [
    "DEUTXXFF",      # "XX" is not a registered ISO 3166-1 country code
    "DEUTDE0F",      # location code first char '0' is reserved
    "DEUTDE1F",      # location code first char '1' is reserved
    "DEUTDEFO",      # location code second char 'O' is forbidden
    "DEUT1EFF",      # country code contains a digit (not two letters)
    "DEUTDEF",       # 7 chars -- wrong length
    "DEUTDEFF50",    # 10 chars -- wrong length (branch must be 0 or 3 chars)
]


@pytest.mark.parametrize("bic", VALID_BICS)
def test_bic_accepts_real_bics(bic):
    assert _bic_valid(bic) is True


@pytest.mark.parametrize("bic", INVALID_BICS)
def test_bic_rejects_invalid(bic):
    assert _bic_valid(bic) is False


@pytest.mark.parametrize(
    "bad", ["", "DEUT", "  ", "DEUTDEF!", "12345678", "DEUTDEFF!00"]
)
def test_bic_rejects_garbage(bad):
    # Defensive: malformed / wrong-length / non-alphanumeric input is never a
    # valid BIC.
    assert _bic_valid(bad) is False


def test_bic_lowercase_accepted_by_validator():
    # BICs are case-insensitive; the validator upper-cases before checking.
    assert _bic_valid("deutdeff500") is True


def test_bic_8char_in_memo_detected():
    findings = _scan("settlement at BOFAUS3N this morning")
    bics = [f for f in findings if f.type == "bic"]
    assert len(bics) == 1
    assert bics[0].severity == "high"
    assert bics[0].check == "pii"
    # Only the bank + country prefix survives for triage; the location/branch
    # code is masked.
    assert (bics[0].evidence or "").startswith("BOFAUS")
    assert "X" in (bics[0].evidence or "")
    assert "3N" not in (bics[0].evidence or "")


def test_bic_11char_branch_code_detected():
    findings = _scan("wire routed via DEUTDEFF500 to the beneficiary")
    bics = [f for f in findings if f.type == "bic"]
    assert len(bics) == 1
    # The 11-char form keeps the 6-char prefix and masks the 5 trailing chars.
    assert bics[0].evidence == "DEUTDEXXXXX"


def test_bic_lowercase_not_detected_in_freetext():
    # Detection is upper-case only by design: a BIC is always transmitted in
    # upper case, and matching lower-case all-letter runs would flood reports
    # with ordinary English words (e.g. "beneficiary"). The validator helper
    # stays case-insensitive, but the free-text scan does not.
    findings = _scan("paid through deutdeff today")
    assert "bic" not in {f.type for f in findings}


def test_bic_lowercase_word_not_misdetected():
    # "beneficiary" is B-E-N-E-F-I-C-I-A-R-Y: 11 letters whose 5th-6th chars are
    # "FI" (Finland) -- a country-code collision the upper-case-only rule guards
    # against. It must NOT be reported as a BIC.
    findings = _scan("wire to the beneficiary bank today")
    assert "bic" not in {f.type for f in findings}


def test_invalid_bic_not_reported():
    # A BIC-shaped run with an unregistered country code must NOT be reported.
    findings = _scan("ref DEUTXXFF logged")
    assert "bic" not in {f.type for f in findings}


def test_bic_does_not_break_other_identifiers():
    # The BIC regex (mostly letters, 8/11 chars) must not interfere with the
    # numeric/check-digit identifiers when those appear on their own.
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]
    lei_findings = _scan("counterparty 529900T8BM49AURSDO55 noted")
    assert [f.type for f in lei_findings] == ["lei"]


def test_bic_not_double_counted():
    # A BIC must be classified once -- as a bic -- and never also as an
    # account_number / routing / credit_card finding for any digit run inside it.
    findings = _scan("via UBSWCHZH80A to the account")
    types = [f.type for f in findings]
    assert types.count("bic") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_same_bic_deduped_per_field():
    findings = _scan("BOFAUS3N aka bofaus3n twice")
    bics = [f for f in findings if f.type == "bic"]
    assert len(bics) == 1


def test_bic_leak_fixture(bic_file):
    findings = check_pii(bic_file.read_bytes())
    bics = [f for f in findings if f.type == "bic"]
    types = {f.type for f in findings}
    assert "bic" in types, f"expected bic, got: {types}"
    # The fixture leaks two valid BICs in memos; the bad-country decoy (DEUTXXFF)
    # must NOT be reported.
    assert len(bics) == 2
    assert all(b.severity == "high" for b in bics)
    for b in bics:
        # No raw location/branch code remains in the evidence.
        assert "X" in (b.evidence or "")


def test_clean_file_no_bic(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "bic" not in {f.type for f in findings}


# --- UK sort code detection (NN-NN-NN structure + clearing-range gated) ---

# Real, published UK clearing sort codes (public information). Each must pass the
# hyphenated NN-NN-NN structure and the assigned clearing-range leading-pair gate.
VALID_UK_SORT_CODES = [
    "20-00-00",  # Barclays
    "60-16-13",  # NatWest
    "40-02-50",  # HSBC
    "30-00-00",  # Lloyds
    "09-01-29",  # Santander (leading pair 09 -- low but assigned)
    "77-91-23",  # Lloyds / TSB family
    "01-02-03",  # minimum assigned leading pair
    "97-99-99",  # maximum assigned leading pair
]

# Strings shaped like a sort code but failing the structure or the assigned
# clearing-range leading pair -- they must NOT validate.
INVALID_UK_SORT_CODES = [
    "00-00-00",  # leading pair 00 is unassigned
    "00-12-34",  # leading pair 00 is unassigned
    "98-01-02",  # leading pair 98 is reserved (out of assigned range)
    "99-99-99",  # leading pair 99 is reserved (the classic test/decoy value)
    "1-23-45",   # first part not two digits
    "20-0-00",   # middle part not two digits
    "20-00-0",   # last part not two digits
    "200000",    # no hyphens (not the canonical shape)
    "20-00-00-1",  # four parts -- wrong structure
]


@pytest.mark.parametrize("code", VALID_UK_SORT_CODES)
def test_uk_sort_code_accepts_real_codes(code):
    assert _uk_sort_code_valid(code) is True


@pytest.mark.parametrize("code", INVALID_UK_SORT_CODES)
def test_uk_sort_code_rejects_invalid(code):
    assert _uk_sort_code_valid(code) is False


@pytest.mark.parametrize(
    "bad", ["", "  ", "ab-cd-ef", "20/00/00", "20-00-0X", "----", "20-00"]
)
def test_uk_sort_code_rejects_garbage(bad):
    # Defensive: malformed / non-numeric / wrong-shape input is never a valid
    # sort code.
    assert _uk_sort_code_valid(bad) is False


def test_uk_sort_code_in_memo_detected():
    findings = _scan("standing order to sort code 20-00-00 today")
    codes = [f for f in findings if f.type == "uk_sort_code"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the leading bank pair survives for triage; the branch pairs are masked.
    assert codes[0].evidence == "20-XX-XX"


def test_uk_sort_code_redaction_masks_branch():
    findings = _scan("beneficiary at 60-16-13 NatWest")
    codes = [f for f in findings if f.type == "uk_sort_code"]
    assert len(codes) == 1
    assert codes[0].evidence == "60-XX-XX"
    # The branch-identifying pairs never leave the tool.
    assert "16" not in codes[0].evidence
    assert "13" not in codes[0].evidence


def test_uk_sort_code_reserved_value_not_reported():
    # 99-99-99 is the reserved/test value: it has the right shape but an
    # out-of-range leading pair, so it must NOT be reported.
    findings = _scan("decoy reference 99-99-99 logged")
    assert "uk_sort_code" not in {f.type for f in findings}


def test_uk_sort_code_all_zero_not_reported():
    findings = _scan("placeholder 00-00-00 in the template")
    assert "uk_sort_code" not in {f.type for f in findings}


def test_contiguous_six_digits_not_a_sort_code():
    # The hyphenated NN-NN-NN shape is the defining feature: a plain six-digit
    # run is never reclassified as a sort code.
    findings = _scan("reference 200000 noted")
    assert "uk_sort_code" not in {f.type for f in findings}


def test_uk_sort_code_does_not_break_other_identifiers():
    # The hyphenated sort-code scan must not interfere with the other
    # identifiers when those appear on their own.
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]
    aba_findings = [f for f in _scan("routing 121000248 on file")
                    if f.type == "routing_number"]
    assert len(aba_findings) == 1


def test_uk_sort_code_does_not_collide_with_digit_scanners():
    # A sort code's hyphens break the run into three two-digit pieces, so the
    # 8+/9-digit account/routing scanners never also claim it.
    findings = _scan("paid via 20-00-00 to the account")
    types = [f.type for f in findings]
    assert types.count("uk_sort_code") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_ssn_not_misread_as_sort_code():
    # An SSN (NNN-NN-NNNN, a 3-2-4 split) is a different shape and must be
    # reported as an SSN, never as a sort code.
    findings = _scan("client ssn 123-45-6789 on file")
    types = {f.type for f in findings}
    assert "ssn" in types
    assert "uk_sort_code" not in types


def test_same_uk_sort_code_deduped_per_field():
    findings = _scan("20-00-00 and again 20-00-00 in one memo")
    codes = [f for f in findings if f.type == "uk_sort_code"]
    assert len(codes) == 1


def test_uk_sort_code_leak_fixture(uk_sort_code_file):
    findings = check_pii(uk_sort_code_file.read_bytes())
    codes = [f for f in findings if f.type == "uk_sort_code"]
    types = {f.type for f in findings}
    assert "uk_sort_code" in types, f"expected uk_sort_code, got: {types}"
    # The fixture leaks two valid sort codes in memos; the reserved 99-99-99
    # decoy must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # No raw branch pairs remain in the evidence.
        assert c.evidence.endswith("-XX-XX")


def test_clean_file_no_uk_sort_code(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "uk_sort_code" not in {f.type for f in findings}


# --- Canadian routing number detection (TTTTT-III MICR structure + assigned
# institution-number gated) ---

# Real-format Canadian routing numbers in the MICR TTTTT-III presentation: a
# five-digit branch transit number plus a three-digit Payments Canada institution
# number. Each must pass the hyphenated structure and the assigned
# institution-number gate. (Transit numbers are arbitrary five-digit branch ids;
# the institution numbers below are the published Payments Canada bank ids.)
VALID_CA_ROUTING = [
    "00012-003",  # RBC (institution 003)
    "12345-004",  # TD (institution 004)
    "00001-001",  # BMO (institution 001 -- minimum chartered-bank range)
    "98765-002",  # Scotiabank (institution 002)
    "55501-010",  # CIBC (institution 010)
    "00100-039",  # Laurentian (institution 039 -- top of chartered-bank range)
    "30000-260",  # a Schedule II/III foreign-bank institution (100-399 range)
    "44444-614",  # a trust/loan institution (600-699 range)
    "12121-815",  # Desjardins (institution 815 -- credit-union central range)
]

# Strings shaped like a Canadian routing number but failing the structure or the
# assigned institution-number gate -- they must NOT validate.
INVALID_CA_ROUTING = [
    "12345-000",  # institution 000 is never a live institution
    "12345-040",  # institution 040 falls in an unassigned gap (40-99)
    "12345-400",  # institution 400 falls in an unassigned gap (400-599)
    "12345-700",  # institution 700 falls in an unassigned gap (700-799)
    "12345-999",  # institution 999 is the classic decoy / out of range
    "1234-003",   # transit not five digits
    "123456-003", # transit too long
    "12345-03",   # institution not three digits
    "12345-0033", # institution too long
    "12345003",   # no hyphen (not the MICR shape)
    "12345-003-1",  # three parts -- wrong structure
]


@pytest.mark.parametrize("code", VALID_CA_ROUTING)
def test_ca_routing_accepts_real_codes(code):
    assert _ca_routing_valid(code) is True


@pytest.mark.parametrize("code", INVALID_CA_ROUTING)
def test_ca_routing_rejects_invalid(code):
    assert _ca_routing_valid(code) is False


@pytest.mark.parametrize(
    "bad", ["", "  ", "abcde-fgh", "12345/003", "12345-00X", "------", "12345"]
)
def test_ca_routing_rejects_garbage(bad):
    # Defensive: malformed / non-numeric / wrong-shape input is never a valid
    # Canadian routing number.
    assert _ca_routing_valid(bad) is False


def test_ca_routing_in_memo_detected():
    findings = _scan("EFT routed to 00012-003 RBC main branch")
    codes = [f for f in findings if f.type == "ca_routing_number"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the institution number survives for triage; the branch transit is masked.
    assert codes[0].evidence == "XXXXX-003"


def test_ca_routing_redaction_masks_transit():
    findings = _scan("beneficiary at 12345-004 TD")
    codes = [f for f in findings if f.type == "ca_routing_number"]
    assert len(codes) == 1
    assert codes[0].evidence == "XXXXX-004"
    # The branch-identifying transit number never leaves the tool.
    assert "12345" not in codes[0].evidence


def test_ca_routing_decoy_institution_not_reported():
    # 11111-999 has the right MICR shape but an out-of-range institution number,
    # so it must NOT be reported.
    findings = _scan("decoy reference 11111-999 logged")
    assert "ca_routing_number" not in {f.type for f in findings}


def test_ca_routing_zero_institution_not_reported():
    findings = _scan("placeholder 12345-000 in the template")
    assert "ca_routing_number" not in {f.type for f in findings}


def test_contiguous_eight_digits_not_a_ca_routing():
    # The hyphenated TTTTT-III shape is the defining feature: a plain digit run
    # is never reclassified as a Canadian routing number.
    findings = _scan("reference 12345003 noted")
    assert "ca_routing_number" not in {f.type for f in findings}


def test_ca_routing_does_not_break_other_identifiers():
    # The hyphenated routing scan must not interfere with the other identifiers
    # when those appear on their own.
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]
    aba_findings = [f for f in _scan("routing 121000248 on file")
                    if f.type == "routing_number"]
    assert len(aba_findings) == 1


def test_ca_routing_does_not_collide_with_digit_scanners():
    # The hyphen breaks the run into a five- and a three-digit piece, so the
    # 8+/9-digit account/routing scanners never also claim it.
    findings = _scan("paid via 00012-003 to the account")
    types = [f.type for f in findings]
    assert types.count("ca_routing_number") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_ca_routing_does_not_collide_with_uk_sort_code():
    # A Canadian routing number (5-3 split) and a UK sort code (2-2-2 split) are
    # distinct shapes: each is reported only as its own type.
    ca = _scan("Canadian 00012-003 here")
    assert [f.type for f in ca] == ["ca_routing_number"]
    uk = _scan("British 20-00-00 here")
    assert [f.type for f in uk] == ["uk_sort_code"]


def test_ssn_not_misread_as_ca_routing():
    # An SSN (NNN-NN-NNNN, a 3-2-4 split) is a different shape and must be
    # reported as an SSN, never as a Canadian routing number.
    findings = _scan("client ssn 123-45-6789 on file")
    types = {f.type for f in findings}
    assert "ssn" in types
    assert "ca_routing_number" not in types


def test_same_ca_routing_deduped_per_field():
    findings = _scan("00012-003 and again 00012-003 in one memo")
    codes = [f for f in findings if f.type == "ca_routing_number"]
    assert len(codes) == 1


def test_ca_routing_leak_fixture(ca_routing_file):
    findings = check_pii(ca_routing_file.read_bytes())
    codes = [f for f in findings if f.type == "ca_routing_number"]
    types = {f.type for f in findings}
    assert "ca_routing_number" in types, f"expected ca_routing_number, got: {types}"
    # The fixture leaks two valid routing numbers in memos; the out-of-range
    # 11111-999 decoy must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # No raw transit number remains in the evidence.
        assert c.evidence.startswith("XXXXX-")


def test_clean_file_no_ca_routing(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "ca_routing_number" not in {f.type for f in findings}


# --- Australian BSB code detection (NNN-NNN structure + assigned bank-prefix
# gated) ---

# Real-format Australian BSB codes in the canonical NNN-NNN presentation: a
# leading bank/financial-institution prefix, a state digit, and a branch. Each
# must pass the hyphenated structure and the assigned bank-prefix gate. (Branch
# numbers are arbitrary; the leading pairs below are real AusPayNet bank prefixes.)
VALID_AU_BSB = [
    "062-000",  # Commonwealth Bank (CBA, prefix 06)
    "013-006",  # ANZ (prefix 01)
    "082-001",  # NAB (prefix 08)
    "032-000",  # Westpac (prefix 03)
    "012-003",  # ANZ (prefix 01 -- low end of the big-four/ADI range)
    "192-879",  # Bank of Melbourne (prefix 19 -- top of the 01-19 range)
    "484-799",  # an institution in the 20-79 other-ADI block (prefix 48)
    "802-101",  # a Cuscal-sponsored mutual / credit union (prefix 80)
    "899-555",  # top of the mutual / credit-union block (prefix 89)
]

# Strings shaped like a BSB but failing the structure or the assigned bank-prefix
# gate -- they must NOT validate.
INVALID_AU_BSB = [
    "000-123",  # prefix 00 is never an assigned bank code
    "901-234",  # prefix 90 falls in the reserved 90-99 range
    "999-999",  # prefix 99 is reserved / the classic decoy
    "12-345",   # first group not three digits
    "1234-567", # first group too long
    "123-45",   # second group not three digits
    "123-4567", # second group too long
    "123456",   # no hyphen (not the BSB shape)
    "123-456-7",  # three parts -- wrong structure
]


@pytest.mark.parametrize("code", VALID_AU_BSB)
def test_au_bsb_accepts_real_codes(code):
    assert _au_bsb_valid(code) is True


@pytest.mark.parametrize("code", INVALID_AU_BSB)
def test_au_bsb_rejects_invalid(code):
    assert _au_bsb_valid(code) is False


@pytest.mark.parametrize(
    "bad", ["", "  ", "abc-def", "062/000", "06X-000", "------", "062000"]
)
def test_au_bsb_rejects_garbage(bad):
    # Defensive: malformed / non-numeric / wrong-shape input is never a valid BSB.
    assert _au_bsb_valid(bad) is False


def test_au_bsb_in_memo_detected():
    findings = _scan("BECS direct entry to 062-000 CBA branch")
    codes = [f for f in findings if f.type == "au_bsb"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the leading bank pair survives for triage; the branch is masked.
    assert codes[0].evidence == "06X-XXX"


def test_au_bsb_redaction_masks_branch():
    findings = _scan("beneficiary at 013-006 ANZ")
    codes = [f for f in findings if f.type == "au_bsb"]
    assert len(codes) == 1
    assert codes[0].evidence == "01X-XXX"
    # The branch-identifying digits never leave the tool.
    assert "006" not in codes[0].evidence


def test_au_bsb_decoy_prefix_not_reported():
    # 999-999 has the right NNN-NNN shape but a reserved/out-of-range prefix,
    # so it must NOT be reported.
    findings = _scan("decoy reference 999-999 logged")
    assert "au_bsb" not in {f.type for f in findings}


def test_au_bsb_zero_prefix_not_reported():
    findings = _scan("placeholder 000-123 in the template")
    assert "au_bsb" not in {f.type for f in findings}


def test_contiguous_six_digits_not_an_au_bsb():
    # The hyphenated NNN-NNN shape is the defining feature: a plain digit run is
    # never reclassified as a BSB.
    findings = _scan("reference 062000 noted")
    assert "au_bsb" not in {f.type for f in findings}


def test_au_bsb_does_not_break_other_identifiers():
    # The hyphenated BSB scan must not interfere with the other identifiers when
    # those appear on their own.
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]
    aba_findings = [f for f in _scan("routing 121000248 on file")
                    if f.type == "routing_number"]
    assert len(aba_findings) == 1


def test_au_bsb_does_not_collide_with_digit_scanners():
    # The hyphen breaks the run into two three-digit pieces, so the 8+/9-digit
    # account/routing scanners never also claim it.
    findings = _scan("paid via 062-000 to the account")
    types = [f.type for f in findings]
    assert types.count("au_bsb") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_au_bsb_does_not_collide_with_other_hyphenated_codes():
    # A BSB (3-3 split) is distinct from a UK sort code (2-2-2) and a Canadian
    # routing number (5-3): each is reported only as its own type.
    au = _scan("Australian 062-000 here")
    assert [f.type for f in au] == ["au_bsb"]
    uk = _scan("British 20-00-00 here")
    assert [f.type for f in uk] == ["uk_sort_code"]
    ca = _scan("Canadian 00012-003 here")
    assert [f.type for f in ca] == ["ca_routing_number"]


def test_ssn_not_misread_as_au_bsb():
    # An SSN (NNN-NN-NNNN, a 3-2-4 split) is a different shape and must be
    # reported as an SSN, never as a BSB.
    findings = _scan("client ssn 123-45-6789 on file")
    types = {f.type for f in findings}
    assert "ssn" in types
    assert "au_bsb" not in types


def test_same_au_bsb_deduped_per_field():
    findings = _scan("062-000 and again 062-000 in one memo")
    codes = [f for f in findings if f.type == "au_bsb"]
    assert len(codes) == 1


def test_au_bsb_leak_fixture(au_bsb_file):
    findings = check_pii(au_bsb_file.read_bytes())
    codes = [f for f in findings if f.type == "au_bsb"]
    types = {f.type for f in findings}
    assert "au_bsb" in types, f"expected au_bsb, got: {types}"
    # The fixture leaks two valid BSBs in memos; the out-of-range 000-123 decoy
    # must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # No raw branch digits remain in the evidence.
        assert c.evidence.endswith("X-XXX")


def test_clean_file_no_au_bsb(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "au_bsb" not in {f.type for f in findings}


# --- Indian IFSC code detection (BBBB0BRANCH structure gated) ---

# Real-format Indian IFSC codes in the canonical BBBB0BRANCH presentation: a
# four-letter bank code, the mandatory reserved zero in the fifth position, and
# a six-character alphanumeric branch code. Each must pass the structure gate.
# (The leading four letters are real RBI-assigned bank codes; branch codes are
# arbitrary, as the IFSC carries no arithmetic check digit.)
VALID_IFSC = [
    "SBIN0000123",  # State Bank of India
    "HDFC0001234",  # HDFC Bank
    "ICIC0005678",  # ICICI Bank
    "PUNB0123456",  # Punjab National Bank
    "UTIB0000ABC",  # Axis Bank -- alphanumeric branch code
    "KKBK0ABCDEF",  # Kotak Mahindra -- all-letter branch code
    "YESB0000001",  # Yes Bank
]

# Strings shaped like an IFSC but failing the structure gate -- they must NOT
# validate.
INVALID_IFSC = [
    "HDFCX001234",  # fifth character is not the mandatory reserved zero
    "HDF00001234",  # only three letters in the bank code
    "1DFC0001234",  # bank code contains a digit
    "HDFC000123",   # 10 characters -- too short
    "HDFC00012345", # 12 characters -- too long
    "HDFC0001-23",  # non-alphanumeric in the branch code
    "HDFC1001234",  # fifth character is 1, not 0
]


@pytest.mark.parametrize("code", VALID_IFSC)
def test_ifsc_accepts_real_codes(code):
    assert _ifsc_valid(code) is True


@pytest.mark.parametrize("code", INVALID_IFSC)
def test_ifsc_rejects_invalid(code):
    assert _ifsc_valid(code) is False


@pytest.mark.parametrize("bad", ["", "  ", "abcdefghijk", "SBIN0", "0000000000000"])
def test_ifsc_rejects_garbage(bad):
    # Defensive: empty / wrong-length / wrong-shape input is never a valid IFSC.
    assert _ifsc_valid(bad) is False


def test_ifsc_in_memo_detected():
    findings = _scan("NEFT routed via SBIN0000123 Mumbai branch")
    codes = [f for f in findings if f.type == "ifsc"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the four-letter bank code survives for triage; the branch is masked.
    assert codes[0].evidence == "SBINXXXXXXX"


def test_ifsc_redaction_masks_branch():
    findings = _scan("beneficiary at HDFC0001234")
    codes = [f for f in findings if f.type == "ifsc"]
    assert len(codes) == 1
    assert codes[0].evidence == "HDFCXXXXXXX"
    # The branch-identifying digits never leave the tool.
    assert "001234" not in codes[0].evidence


def test_ifsc_lowercase_accepted():
    # IFSC codes are case-insensitive at validation time even though they are
    # conventionally upper-case.
    assert _ifsc_valid("sbin0000123") is True


def test_ifsc_no_reserved_zero_not_reported():
    # An 11-char token with the right letter prefix but no zero in the fifth
    # position has the IFSC shape but fails the structure gate -- not reported.
    findings = _scan("decoy reference HDFCX001234 logged")
    assert "ifsc" not in {f.type for f in findings}


def test_ifsc_does_not_break_other_identifiers():
    # The IFSC scan must not interfere with the other identifiers when those
    # appear on their own.
    isin_findings = _scan("US0378331005 holding")
    assert [f.type for f in isin_findings] == ["isin"]
    aba_findings = [f for f in _scan("routing 121000248 on file")
                    if f.type == "routing_number"]
    assert len(aba_findings) == 1


def test_ifsc_does_not_collide_with_digit_scanners():
    # The IFSC's branch digit run is reserved, so the 8+/9-digit account/routing
    # scanners never also claim it as a separate finding.
    findings = _scan("paid via SBIN0000123 to the account")
    types = [f.type for f in findings]
    assert types.count("ifsc") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_ifsc_does_not_collide_with_bic():
    # A BIC is 8 or 11 chars but its first six are all letters; an IFSC's fifth
    # character is a digit, so each is reported only as its own type.
    ifsc = _scan("Indian SBIN0000123 here")
    assert [f.type for f in ifsc] == ["ifsc"]
    bic = _scan("SWIFT DEUTDEFF here")
    assert [f.type for f in bic] == ["bic"]


def test_same_ifsc_deduped_per_field():
    findings = _scan("SBIN0000123 and again SBIN0000123 in one memo")
    codes = [f for f in findings if f.type == "ifsc"]
    assert len(codes) == 1


def test_ifsc_leak_fixture(ifsc_file):
    findings = check_pii(ifsc_file.read_bytes())
    codes = [f for f in findings if f.type == "ifsc"]
    types = {f.type for f in findings}
    assert "ifsc" in types, f"expected ifsc, got: {types}"
    # The fixture leaks two valid IFSCs in memos; the no-reserved-zero
    # HDFCX001234 decoy must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # No raw branch characters remain in the evidence.
        assert c.evidence.endswith("XXXXXXX")


def test_clean_file_no_ifsc(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "ifsc" not in {f.type for f in findings}


# --- Email-address leak detection ---------------------------------------------

# Addresses that must be detected: ordinary, tagged (+), subdomained, and
# multi-label-TLD forms a real export might echo.
VALID_EMAILS = [
    "john.doe@example.com",
    "a@example.com",
    "billing+stmt@sub.corp.co.uk",
    "first.last@mail.example.org",
    "user_name@example-host.io",
    "JANE.SMITH@EXAMPLE.COM",
]

# Strings that look email-ish but are NOT a valid address -- the detector must
# stay silent on these so it keeps its near-zero false-positive promise.
NON_EMAILS = [
    "no at sign here",
    "twitter @handle mention",          # @ not part of an address
    "@example.com",                      # no local part
    "user@",                             # no domain
    "user@localhost",                    # no dot / no TLD
    "user@example",                      # bare label, no TLD
    "user@example.c",                    # 1-char TLD
    "price was $5@store today",          # local part touches a non-atom $
]


@pytest.mark.parametrize("text", VALID_EMAILS)
def test_email_address_detected_in_freetext(text):
    findings = _scan(f"please contact {text} for details")
    emails = [f for f in findings if f.type == "email_address"]
    assert len(emails) == 1, f"expected one email finding for {text!r}"
    assert emails[0].check == "pii"
    assert emails[0].severity == "high"
    # The raw address never leaves the scanner -- only the first local char survives.
    assert text.lower() not in (emails[0].evidence or "").lower()


@pytest.mark.parametrize("text", NON_EMAILS)
def test_non_email_strings_not_flagged(text):
    findings = _scan(text)
    assert "email_address" not in {f.type for f in findings}, (
        f"{text!r} should not be reported as an email"
    )


def test_email_evidence_is_redacted():
    findings = _scan("send to john.doe@example.com")
    email = next(f for f in findings if f.type == "email_address")
    # Local part masked (only the first character survives), domain preserved.
    assert email.evidence == "j*******@example.com"


@pytest.mark.parametrize(
    "email,expected",
    [
        ("john.doe@example.com", "j*******@example.com"),
        ("a@example.com", "*@example.com"),
        ("billing+stmt@sub.corp.co.uk", "b***********@sub.corp.co.uk"),
    ],
)
def test_redact_email_masks_local_part(email, expected):
    assert _redact_email(email) == expected


def test_redact_email_leaves_non_address_untouched():
    # Defensive: a string with no @ is returned unchanged.
    assert _redact_email("not-an-email") == "not-an-email"


def test_same_email_deduped_per_field_case_insensitive():
    findings = _scan("a@example.com and again A@Example.COM in one memo")
    emails = [f for f in findings if f.type == "email_address"]
    assert len(emails) == 1


def test_distinct_emails_each_reported():
    findings = _scan("alice@example.com paid bob@other.org")
    emails = [f for f in findings if f.type == "email_address"]
    assert len(emails) == 2


def test_email_does_not_collide_with_numeric_detectors():
    # An address whose local part is digits must be reported as an email, not as
    # an account-number / routing-number run.
    findings = _scan("statement to 1234567890@example.com on file")
    types = {f.type for f in findings}
    assert "email_address" in types
    assert "account_number" not in types
    assert "routing_number" not in types


def test_email_leak_fixture(email_file):
    findings = check_pii(email_file.read_bytes())
    emails = [f for f in findings if f.type == "email_address"]
    types = {f.type for f in findings}
    assert "email_address" in types, f"expected email_address, got: {types}"
    # The fixture leaks the same address twice (different case) in txn 0 and a
    # distinct address in txn 1; the "ref 99" decoy in txn 2 yields nothing.
    assert len(emails) == 2
    assert all(e.severity == "high" for e in emails)
    for e in emails:
        assert "@" in e.evidence and "*" in e.evidence


def test_clean_file_no_email(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "email_address" not in {f.type for f in findings}


# --- Mexican CLABE detection (18-digit, bank code + mod-10 control digit) ---

# Real-format Mexican CLABE numbers (18 digits: 3-digit bank code + 3-digit
# plaza + 11-digit account + 1 control digit). Each control digit was computed
# from the public mod-10 weighted algorithm, so each must pass the gate. The
# leading three digits are non-zero Banxico-assigned bank codes (002 Banamex,
# 012 BBVA, 014 Santander, 032 IXE/Banorte family, 127 Azteca).
VALID_CLABE = [
    "002180001234567896",  # bank 002 (Banamex)
    "012180005432109877",  # bank 012 (BBVA)
    "012180000000543213",  # bank 012, account-heavy zeros
    "032180001112223332",  # bank 032
    "127180012345678904",  # bank 127
]

# 18-digit runs shaped like a CLABE but failing a gate -- they must NOT validate.
INVALID_CLABE = [
    "002180001234567890",  # wrong control digit (real one is ...96)
    "012180005432109870",  # wrong control digit (real one is ...77)
    "000180001234567890",  # bank code 000 is never assigned
    "111111111111111111",  # all-ones -- fails the control digit
    "123456789012345678",  # sequential -- fails the control digit
]


@pytest.mark.parametrize("digits", VALID_CLABE)
def test_clabe_accepts_real_numbers(digits):
    assert _clabe_valid(digits) is True


@pytest.mark.parametrize("digits", INVALID_CLABE)
def test_clabe_rejects_invalid(digits):
    assert _clabe_valid(digits) is False


@pytest.mark.parametrize(
    "bad",
    ["", "  ", "00218000123456789", "0021800012345678901", "abcdefghijklmnopqr"],
)
def test_clabe_rejects_garbage(bad):
    # Defensive: empty / wrong-length (17 or 19) / non-numeric input is never a
    # valid CLABE.
    assert _clabe_valid(bad) is False


def test_clabe_in_memo_detected():
    findings = _scan("Routed to CLABE 002180001234567896 Banamex")
    codes = [f for f in findings if f.type == "clabe"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the three-digit bank code survives for triage; the rest is masked.
    assert codes[0].evidence == "002XXXXXXXXXXXXXXX"


def test_clabe_redaction_masks_account():
    findings = _scan("beneficiary 012180005432109877")
    codes = [f for f in findings if f.type == "clabe"]
    assert len(codes) == 1
    assert codes[0].evidence == "012XXXXXXXXXXXXXXX"
    # The account-identifying digits never leave the tool.
    assert "543210987" not in codes[0].evidence


def test_clabe_wrong_control_digit_not_reported():
    # An 18-digit run with a valid bank code but a wrong control digit has the
    # CLABE shape but fails the checksum -- it is not reported as a CLABE.
    findings = _scan("decoy reference 002180001234567890 logged")
    assert "clabe" not in {f.type for f in findings}


def test_clabe_zero_bank_code_not_reported():
    # A 000 bank code is never assigned, so even a checksum-shaped run is not a
    # CLABE.
    findings = _scan("reference 000180001234567890 logged")
    assert "clabe" not in {f.type for f in findings}


def test_clabe_does_not_collide_with_digit_scanners():
    # A valid CLABE is reserved under the card / account / routing namespaces, so
    # the 13-19-digit card scanner and the 8+-digit account scanner never also
    # claim the same run as a separate finding.
    findings = _scan("paid via 002180001234567896 to vendor")
    types = [f.type for f in findings]
    assert types.count("clabe") == 1
    assert "account_number" not in types
    assert "credit_card" not in types
    assert "routing_number" not in types


def test_clabe_does_not_break_other_identifiers():
    # The CLABE scan must not interfere with the other identifiers when those
    # appear on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    acct_findings = [f for f in _scan("account 123456789012 on file")
                     if f.type == "account_number"]
    assert len(acct_findings) == 1


def test_invalid_clabe_still_seen_as_account_number():
    # An 18-digit run that fails the CLABE control digit is NOT a CLABE, but it
    # is still an account-number-shaped run and must be reported as such (no leak
    # is silently dropped).
    findings = _scan("reference 002180001234567890 noted")
    types = {f.type for f in findings}
    assert "clabe" not in types
    assert "account_number" in types


def test_same_clabe_deduped_per_field():
    findings = _scan(
        "CLABE 002180001234567896 and again 002180001234567896 in one memo"
    )
    codes = [f for f in findings if f.type == "clabe"]
    assert len(codes) == 1


def test_clabe_leak_fixture(clabe_file):
    findings = check_pii(clabe_file.read_bytes())
    codes = [f for f in findings if f.type == "clabe"]
    types = {f.type for f in findings}
    assert "clabe" in types, f"expected clabe, got: {types}"
    # The fixture leaks two valid CLABEs in memos; the wrong-control-digit
    # decoy (012180005432109870) must NOT be reported as a CLABE.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # Only the three-digit bank code survives in the evidence.
        assert c.evidence.endswith("X" * 15)
        assert "clabe" == c.type


def test_clean_file_no_clabe(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "clabe" not in {f.type for f in findings}


# --- South Korean Giro number detection (NNNNN-NN, payee block + mod-10 check) ---

# Real-format South Korean Giro numbers (7 digits, written NNNNN-NN: a 6-digit
# payee block + 1 trailing mod-10 weighted check digit). Each check digit was
# computed from the public weighted algorithm (weights 3,1,3,1,3,1 over the
# first six digits), so each must pass the gate.
VALID_KR_GIRO = [
    "10005-20",  # base 100052, check 0
    "20315-09",  # base 203150, check 9
    "70000-18",  # base 700001, check 8
    "45678-95",  # base 456789, check 5
    "99999-92",  # all-nines payee, check 2
    "00001-98",  # zero-heavy but non-zero payee block, check 8
]

# NNNNN-NN-shaped runs that must NOT validate -- wrong check digit or an
# all-zeros payee block.
INVALID_KR_GIRO = [
    "10005-21",  # wrong check digit (real one is ...0)
    "20315-00",  # wrong check digit (real one is ...9)
    "00000-00",  # all-zeros payee block is never a live Giro number
    "12345-67",  # coincidental token -- fails the check digit
    "98765-43",  # coincidental token -- fails the check digit
]


@pytest.mark.parametrize("code", VALID_KR_GIRO)
def test_kr_giro_accepts_real_numbers(code):
    assert _kr_giro_valid(code) is True


@pytest.mark.parametrize("code", INVALID_KR_GIRO)
def test_kr_giro_rejects_invalid(code):
    assert _kr_giro_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    ["", "  ", "1234-567", "100052-0", "1000-520", "abcde-fg", "10005--20", "10005-2"],
)
def test_kr_giro_rejects_garbage(bad):
    # Defensive: empty / wrong split (4-3, 6-1, 4-3) / non-numeric / double-hyphen
    # / short-tail input is never a valid Giro number.
    assert _kr_giro_valid(bad) is False


def test_kr_giro_in_memo_detected():
    findings = _scan("Paid utility giro 10005-20 KEPCO")
    codes = [f for f in findings if f.type == "kr_giro"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the leading two digits survive for triage; the rest is masked.
    assert codes[0].evidence == "10XXX-XX"


def test_kr_giro_redaction_masks_payee():
    findings = _scan("biller 20315-09 on file")
    codes = [f for f in findings if f.type == "kr_giro"]
    assert len(codes) == 1
    assert codes[0].evidence == "20XXX-XX"
    # The payee-identifying digits and the check digit never leave the tool.
    assert "315" not in codes[0].evidence
    assert "09" not in codes[0].evidence


def test_kr_giro_wrong_check_digit_not_reported():
    # An NNNNN-NN run with a non-zero payee block but a wrong check digit has the
    # Giro shape but fails the checksum -- it is not reported as a Giro number.
    findings = _scan("decoy reference 10005-21 logged")
    assert "kr_giro" not in {f.type for f in findings}


def test_kr_giro_zero_payee_block_not_reported():
    # An all-zeros payee block is never a live Giro number, so even a
    # checksum-shaped run is not reported.
    findings = _scan("reference 00000-00 logged")
    assert "kr_giro" not in {f.type for f in findings}


def test_kr_giro_does_not_collide_with_digit_scanners():
    # A Giro number is a hyphenated 5-2 token; the hyphen breaks it into a
    # five- and a two-digit piece, so the 9-digit routing scanner, the 8+-digit
    # account scanner, and the card scanner never also claim it.
    findings = _scan("paid via 10005-20 to biller")
    types = [f.type for f in findings]
    assert types.count("kr_giro") == 1
    assert "account_number" not in types
    assert "credit_card" not in types
    assert "routing_number" not in types


def test_kr_giro_does_not_collide_with_other_hyphenated_detectors():
    # The 5-2 Giro split must not be confused with the UK sort code (2-2-2),
    # the Canadian routing number (5-3), the Australian BSB (3-3), or the SSN
    # (3-2-4); each of those tokens must be classified as itself, never as a
    # Giro number.
    assert "kr_giro" not in {f.type for f in _scan("sort 20-00-00 here")}
    assert "kr_giro" not in {f.type for f in _scan("routing 12345-003 here")}
    assert "kr_giro" not in {f.type for f in _scan("bsb 062-000 here")}
    assert "kr_giro" not in {f.type for f in _scan("ssn 123-45-6789 here")}


def test_kr_giro_does_not_break_other_identifiers():
    # The Giro scan must not interfere with other identifiers on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    sort_findings = [f for f in _scan("sort code 20-00-00 today")
                     if f.type == "uk_sort_code"]
    assert len(sort_findings) == 1


def test_same_kr_giro_deduped_per_field():
    findings = _scan(
        "giro 10005-20 and again 10005-20 in one memo"
    )
    codes = [f for f in findings if f.type == "kr_giro"]
    assert len(codes) == 1


def test_kr_giro_leak_fixture(kr_giro_file):
    findings = check_pii(kr_giro_file.read_bytes())
    codes = [f for f in findings if f.type == "kr_giro"]
    types = {f.type for f in findings}
    assert "kr_giro" in types, f"expected kr_giro, got: {types}"
    # The fixture leaks two valid Giro numbers in memos; the wrong-check-digit
    # decoy (10005-21) must NOT be reported as a Giro number.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # Only the leading two digits survive in the evidence.
        assert c.evidence.endswith("XXX-XX")
        assert "kr_giro" == c.type


def test_clean_file_no_kr_giro(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "kr_giro" not in {f.type for f in findings}


# --- Thai national ID / PromptPay proxy id detection ---
# (N-NNNN-NNNNN-NN-N, category digit + mod-11 check)

# Real-format Thai national IDs (13 digits, written N-NNNN-NNNNN-NN-N: a 1-8
# category digit, then the 1-4-5-2-1 grouping ending in a trailing mod-11
# weighted check digit). Each check digit was computed from the public weighted
# algorithm (weights 13..2 over the first twelve digits), so each must pass the
# gate.
VALID_TH_NATID = [
    "1-1017-00522-00-8",  # category 1, check 8
    "3-1007-01234-56-7",  # category 3, check 7
    "5-2009-98877-00-9",  # category 5, check 9
    "1-4002-00030-00-5",  # zero-heavy but valid, check 5
    "8-1001-00010-00-2",  # category 8 (the highest issued), check 2
    "2-9999-99999-90-3",  # nine-heavy payload, check 3
]

# N-NNNN-NNNNN-NN-N-shaped runs that must NOT validate -- wrong check digit or an
# unissued category digit.
INVALID_TH_NATID = [
    "1-1017-00522-00-7",  # wrong check digit (real one is ...8)
    "3-1007-01234-56-6",  # wrong check digit (real one is ...7)
    "0-1017-00522-00-8",  # category 0 is never an issued first digit
    "9-1017-00522-00-8",  # category 9 is never an issued first digit
    "1-2345-67890-12-3",  # coincidental token -- fails the check digit
]


@pytest.mark.parametrize("code", VALID_TH_NATID)
def test_th_natid_accepts_real_numbers(code):
    assert _th_natid_valid(code) is True


@pytest.mark.parametrize("code", INVALID_TH_NATID)
def test_th_natid_rejects_invalid(code):
    assert _th_natid_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "1101700522008",      # contiguous (no hyphen grouping) is not the canonical form
        "11-017-00522-00-8",  # wrong split (2-3-5-2-1)
        "1-1017-0052-200-8",  # wrong split (1-4-4-3-1)
        "1-1017-00522-008",   # only four groups
        "1-1017-00522-00-8-9",  # six groups
        "a-1017-00522-00-8",  # non-numeric
        "1--1017-00522-00-8",  # double hyphen
    ],
)
def test_th_natid_rejects_garbage(bad):
    # Defensive: empty / wrong split / contiguous / non-numeric / extra-group /
    # double-hyphen input is never a valid national ID in the canonical form.
    assert _th_natid_valid(bad) is False


def test_th_natid_in_memo_detected():
    findings = _scan("PromptPay payee natid 1-1017-00522-00-8 Somchai")
    codes = [f for f in findings if f.type == "th_natid"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the leading category digit survives for triage; the rest is masked.
    assert codes[0].evidence == "1-XXXX-XXXXX-XX-X"


def test_th_natid_redaction_masks_identity():
    findings = _scan("proxy id 3-1007-01234-56-7 on file")
    codes = [f for f in findings if f.type == "th_natid"]
    assert len(codes) == 1
    assert codes[0].evidence == "3-XXXX-XXXXX-XX-X"
    # The identity-bearing digits and the check digit never leave the tool.
    assert "1007" not in codes[0].evidence
    assert "01234" not in codes[0].evidence


def test_th_natid_wrong_check_digit_not_reported():
    # A N-NNNN-NNNNN-NN-N run with a valid category digit but a wrong check digit
    # has the national-ID shape but fails the checksum -- not reported.
    findings = _scan("decoy reference 1-1017-00522-00-7 logged")
    assert "th_natid" not in {f.type for f in findings}


def test_th_natid_bad_category_digit_not_reported():
    # A leading 0 or 9 is never an issued category digit, so even a
    # checksum-shaped run is not reported.
    assert "th_natid" not in {f.type for f in _scan("ref 0-1017-00522-00-8 here")}
    assert "th_natid" not in {f.type for f in _scan("ref 9-1017-00522-00-8 here")}


def test_th_natid_does_not_collide_with_digit_scanners():
    # The national ID's single-dash grouping satisfies the credit-card matcher,
    # so without the reservation it would be double-counted. The compact 13-digit
    # run is reserved under the card / account / routing namespaces, so the ID is
    # classified exactly once and never also as a card or account number.
    findings = _scan("paid 1-1017-00522-00-8 to payee")
    types = [f.type for f in findings]
    assert types.count("th_natid") == 1
    assert "account_number" not in types
    assert "credit_card" not in types
    assert "routing_number" not in types


def test_th_natid_does_not_collide_with_other_hyphenated_detectors():
    # The 1-4-5-2-1 national-ID split must not be confused with the UK sort code
    # (2-2-2), the Canadian routing number (5-3), the Australian BSB (3-3), the
    # South Korean Giro (5-2), or the SSN (3-2-4); each of those must be
    # classified as itself, never as a national ID.
    assert "th_natid" not in {f.type for f in _scan("sort 20-00-00 here")}
    assert "th_natid" not in {f.type for f in _scan("routing 12345-003 here")}
    assert "th_natid" not in {f.type for f in _scan("bsb 062-000 here")}
    assert "th_natid" not in {f.type for f in _scan("giro 10005-20 here")}
    assert "th_natid" not in {f.type for f in _scan("ssn 123-45-6789 here")}


def test_th_natid_does_not_break_other_identifiers():
    # The national-ID scan must not interfere with other identifiers on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    giro_findings = [f for f in _scan("giro 10005-20 today")
                     if f.type == "kr_giro"]
    assert len(giro_findings) == 1


def test_same_th_natid_deduped_per_field():
    findings = _scan(
        "id 1-1017-00522-00-8 and again 1-1017-00522-00-8 in one memo"
    )
    codes = [f for f in findings if f.type == "th_natid"]
    assert len(codes) == 1


def test_th_natid_leak_fixture(th_natid_file):
    findings = check_pii(th_natid_file.read_bytes())
    codes = [f for f in findings if f.type == "th_natid"]
    types = {f.type for f in findings}
    assert "th_natid" in types, f"expected th_natid, got: {types}"
    # The fixture leaks two valid national IDs in memos; the wrong-check-digit
    # decoy (1-1017-00522-00-7) must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # Only the leading category digit survives in the evidence.
        assert c.evidence.endswith("-XXXX-XXXXX-XX-X")
        assert "th_natid" == c.type
    # The reservation guarantees the IDs are never also reported as cards /
    # account numbers.
    assert "credit_card" not in types
    assert "account_number" not in types


def test_clean_file_no_th_natid(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "th_natid" not in {f.type for f in findings}


# Real-format Brazilian CPFs (11 digits, written NNN.NNN.NNN-NN: a 3.3.3-2
# dotted-and-dashed grouping ending in two trailing mod-11 weighted check
# digits). Each pair of check digits was computed from the public weighted
# algorithm (descending weights 10..2 then 11..2), so each must pass the gate.
VALID_BR_CPF = [
    "111.444.777-35",
    "123.456.789-09",
    "529.982.247-25",
    "398.273.113-52",
    "468.613.100-69",
]

# NNN.NNN.NNN-NN-shaped runs that must NOT validate -- wrong check digit or a
# repeated-digit placeholder that passes the arithmetic but is an invalid CPF.
INVALID_BR_CPF = [
    "111.444.777-34",  # wrong second check digit (real one is ...35)
    "123.456.789-00",  # wrong check digits (real one is ...09)
    "111.111.111-11",  # all-same-digit placeholder -- passes arithmetic, invalid
    "000.000.000-00",  # all-zero placeholder -- passes arithmetic, invalid
    "529.982.247-24",  # one off from a real CPF -- checksum must catch it
]


@pytest.mark.parametrize("code", VALID_BR_CPF)
def test_br_cpf_accepts_real_numbers(code):
    assert _br_cpf_valid(code) is True


@pytest.mark.parametrize("code", INVALID_BR_CPF)
def test_br_cpf_rejects_invalid(code):
    assert _br_cpf_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "11144477735",        # contiguous (no dotted grouping) is not the canonical form
        "111-444-777-35",     # hyphens, not the dotted CPF presentation
        "11.1444.777-35",     # wrong split
        "111.444.777.35",     # final separator is a dot, not a dash
        "111.444.77-35",      # short middle/last block
        "a11.444.777-35",     # non-numeric
        "111..444.777-35",    # double dot
    ],
)
def test_br_cpf_rejects_garbage(bad):
    # Defensive: empty / wrong split / contiguous / hyphenated / non-numeric /
    # double-separator input is never a valid CPF in the canonical form.
    assert _br_cpf_valid(bad) is False


def test_br_cpf_in_memo_detected():
    findings = _scan("Pix payee CPF 111.444.777-35 Joao")
    codes = [f for f in findings if f.type == "br_cpf"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the leading block survives for triage; the rest is masked.
    assert codes[0].evidence == "111.XXX.XXX-XX"


def test_br_cpf_redaction_masks_identity():
    findings = _scan("chave 529.982.247-25 on file")
    codes = [f for f in findings if f.type == "br_cpf"]
    assert len(codes) == 1
    assert codes[0].evidence == "529.XXX.XXX-XX"
    # The identity-bearing digits and the check digits never leave the tool.
    assert "982" not in codes[0].evidence
    assert "247" not in codes[0].evidence


def test_br_cpf_wrong_check_digit_not_reported():
    # A NNN.NNN.NNN-NN run with the CPF shape but a wrong check digit fails the
    # checksum -- not reported.
    findings = _scan("decoy reference 111.444.777-34 logged")
    assert "br_cpf" not in {f.type for f in findings}


def test_br_cpf_repeated_digit_placeholder_not_reported():
    # The all-same-digit placeholders pass the checksum arithmetic but are
    # well-known invalid CPFs, so even a checksum-shaped run is not reported.
    assert "br_cpf" not in {f.type for f in _scan("ref 111.111.111-11 here")}
    assert "br_cpf" not in {f.type for f in _scan("ref 000.000.000-00 here")}


def test_br_cpf_does_not_collide_with_digit_scanners():
    # The CPF's dotted-and-dashed presentation breaks the 11-digit run, so the
    # contiguous account / routing scanners never see it; the reservation keeps
    # that guarantee explicit. The CPF is classified exactly once.
    findings = _scan("paid 111.444.777-35 to payee")
    types = [f.type for f in findings]
    assert types.count("br_cpf") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_br_cpf_does_not_collide_with_other_separated_detectors():
    # The dotted 3.3.3-2 CPF split must not be confused with any hyphenated
    # detector -- the UK sort code (2-2-2), the Canadian routing number (5-3),
    # the Australian BSB (3-3), the South Korean Giro (5-2), the Thai national ID
    # (1-4-5-2-1), or the SSN (3-2-4); each of those must be classified as itself,
    # never as a CPF.
    assert "br_cpf" not in {f.type for f in _scan("sort 20-00-00 here")}
    assert "br_cpf" not in {f.type for f in _scan("routing 12345-003 here")}
    assert "br_cpf" not in {f.type for f in _scan("bsb 062-000 here")}
    assert "br_cpf" not in {f.type for f in _scan("giro 10005-20 here")}
    assert "br_cpf" not in {f.type for f in _scan("natid 1-1017-00522-00-8 here")}
    assert "br_cpf" not in {f.type for f in _scan("ssn 123-45-6789 here")}


def test_br_cpf_does_not_break_other_identifiers():
    # The CPF scan must not interfere with other identifiers on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    natid_findings = [f for f in _scan("natid 1-1017-00522-00-8 today")
                      if f.type == "th_natid"]
    assert len(natid_findings) == 1


def test_same_br_cpf_deduped_per_field():
    findings = _scan(
        "cpf 111.444.777-35 and again 111.444.777-35 in one memo"
    )
    codes = [f for f in findings if f.type == "br_cpf"]
    assert len(codes) == 1


def test_br_cpf_leak_fixture(br_cpf_file):
    findings = check_pii(br_cpf_file.read_bytes())
    codes = [f for f in findings if f.type == "br_cpf"]
    types = {f.type for f in findings}
    assert "br_cpf" in types, f"expected br_cpf, got: {types}"
    # The fixture leaks two valid CPFs in memos; the wrong-check-digit decoy
    # (111.444.777-34) must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # Only the leading block survives in the evidence.
        assert c.evidence.endswith(".XXX.XXX-XX")
        assert "br_cpf" == c.type
    # The reservation guarantees the CPFs are never also reported as cards /
    # account numbers.
    assert "credit_card" not in types
    assert "account_number" not in types


def test_clean_file_no_br_cpf(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "br_cpf" not in {f.type for f in findings}


# --- Mexican CURP (Clave Única de Registro de Población) -------------------
#
# Each VALID_MX_CURP value is a structurally complete 18-character CURP whose
# RENAPO mod-10 check digit was computed from its own first 17 characters, so
# the suite carries no real person's CURP -- the values are self-consistent
# synthetic identities (the leading initials/date/state are plausible but the
# bearers are fictitious). INVALID_MX_CURP collects near-miss tokens that must
# each fail one structural or checksum gate.
VALID_MX_CURP = [
    "HEGG560427MVZRRL08",  # VZ (Veracruz), female, 1956-04-27
    "MARC890123HDFRZN06",  # DF (Mexico City), male, 1989-01-23
    "GALR720815MSPLPS09",  # SP (San Luis Potosi), female, 1972-08-15
    "PXTR051231HNERMA01",  # NE (foreign-born), male, 2005-12-31, letter homoclave
]
INVALID_MX_CURP = [
    "HEGG560427MVZRRL09",  # wrong check digit (real one is ...08)
    "HEGG560427MZZRRL08",  # ZZ is not a registered state code
    "HEGG561327MVZRRL00",  # impossible month (13)
    "HEGG560432MVZRRL00",  # impossible day (32)
    "HEGG560427XVZRRL00",  # sex marker neither H nor M
    "1234560427MVZRRL00",  # leading block is digits, not name letters
]


@pytest.mark.parametrize("code", VALID_MX_CURP)
def test_mx_curp_accepts_real_structure(code):
    assert _curp_valid(code) is True


@pytest.mark.parametrize("code", INVALID_MX_CURP)
def test_mx_curp_rejects_invalid(code):
    assert _curp_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "HEGG560427MVZRRL0",    # 17 chars -- too short
        "HEGG560427MVZRRL088",  # 19 chars -- too long
        "HEGG560427MVZRRL0A",   # check position must be a digit, not a letter
        "HEG5560427MVZRRL08",   # name block must be four letters
    ],
)
def test_mx_curp_rejects_garbage(bad):
    # Defensive: empty / wrong-length / wrong-position-type input is never a
    # valid CURP.
    assert _curp_valid(bad) is False


def test_mx_curp_in_memo_detected():
    findings = _scan("Beneficiario CURP HEGG560427MVZRRL08 Hernandez")
    codes = [f for f in findings if f.type == "curp"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the four leading name initials survive for triage; the rest is masked.
    assert codes[0].evidence == "HEGGXXXXXXXXXXXXXX"


def test_mx_curp_redaction_masks_identity():
    findings = _scan("curp MARC890123HDFRZN06 on file")
    codes = [f for f in findings if f.type == "curp"]
    assert len(codes) == 1
    assert codes[0].evidence == "MARCXXXXXXXXXXXXXX"
    # The birth date, state, and check digit never leave the tool.
    assert "890123" not in codes[0].evidence
    assert "DF" not in codes[0].evidence[4:]


def test_mx_curp_wrong_check_digit_not_reported():
    # An 18-char CURP-shaped run with a wrong check digit fails the checksum.
    findings = _scan("decoy reference HEGG560427MVZRRL09 logged")
    assert "curp" not in {f.type for f in findings}


def test_mx_curp_bad_state_not_reported():
    # A CURP-shaped run with an unregistered state code (ZZ) fails the state gate.
    findings = _scan("decoy HEGG560427MZZRRL08 here")
    assert "curp" not in {f.type for f in findings}


def test_mx_curp_lowercase_not_reported_from_text():
    # A CURP is always transmitted upper-case; the scanner's regex is upper-only
    # (the precision lever, mirroring the BIC/IFSC gates), so a lower-case run in
    # prose is left for the prose, not reported as a CURP.
    assert "curp" not in {f.type for f in _scan("ref hegg560427mvzrrl08 here")}


def test_mx_curp_does_not_collide_with_clabe():
    # The CLABE is 18 *digits*; the CURP is 18 chars led by four LETTERS. The two
    # 18-character Mexican identifiers must each be classified as themselves.
    curp = _scan("identity HEGG560427MVZRRL08 here")
    assert [f.type for f in curp if f.type in ("curp", "clabe")] == ["curp"]
    clabe = _scan("account 002010077777777771 here")
    assert "curp" not in {f.type for f in clabe}


def test_mx_curp_does_not_collide_with_digit_scanners():
    # The only contiguous digit run in a CURP is the six-digit birth date -- too
    # short for the account (8+) / routing (9) / card (13+) scanners -- and the
    # reservation keeps that guarantee explicit. The CURP is classified once.
    findings = _scan("paid beneficiary HEGG560427MVZRRL08 today")
    types = [f.type for f in findings]
    assert types.count("curp") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_mx_curp_does_not_break_other_identifiers():
    # The CURP scan must not interfere with other identifiers on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    cpf_findings = [f for f in _scan("cpf 111.444.777-35 today")
                    if f.type == "br_cpf"]
    assert len(cpf_findings) == 1


def test_same_mx_curp_deduped_per_field():
    findings = _scan(
        "curp HEGG560427MVZRRL08 and again HEGG560427MVZRRL08 in one memo"
    )
    codes = [f for f in findings if f.type == "curp"]
    assert len(codes) == 1


def test_mx_curp_leak_fixture(mx_curp_file):
    findings = check_pii(mx_curp_file.read_bytes())
    codes = [f for f in findings if f.type == "curp"]
    types = {f.type for f in findings}
    assert "curp" in types, f"expected curp, got: {types}"
    # The fixture leaks two valid CURPs in memos; the wrong-check-digit decoy
    # (HEGG560427MVZRRL09) must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # Only the four leading name initials survive in the evidence.
        assert len(c.evidence) == 18
        assert c.evidence.endswith("X" * 14)
        assert "curp" == c.type
    # The reservation guarantees the CURPs are never also reported as cards /
    # account numbers.
    assert "credit_card" not in types
    assert "account_number" not in types


def test_clean_file_no_mx_curp(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "curp" not in {f.type for f in findings}


# --- South Korean RRN (Resident Registration Number) -------------------------

# Each VALID_KR_RRN value is a structurally complete 13-digit RRN in its
# canonical YYMMDD-SNNNNNN (6-7) presentation whose embedded birth date is real
# and whose mod-11 check digit verifies (these are synthetic, fictitious numbers
# constructed only to pass the public checksum). The set spans the issued
# century/sex markers (1-2 citizens born 1900s, 3-4 citizens born 2000s, 5-6 / 7-8
# foreign residents). INVALID_KR_RRN collects near-miss tokens that must fail.
VALID_KR_RRN = [
    "900101-1123459",  # citizen, male, born 1900s
    "780630-2123451",  # citizen, female, born 1900s
    "050304-3123459",  # citizen, male, born 2000s
    "991231-5123451",  # foreign resident, born 1900s
    "850815-1010106",  # citizen, male, born 1900s
    "201225-7890126",  # foreign resident, born 2000s
]

INVALID_KR_RRN = [
    "900101-1123450",  # wrong check digit (off by one)
    "901301-1123459",  # impossible month (13)
    "900132-1123459",  # impossible day (32)
    "900100-1123459",  # impossible day (00)
    "900001-1123459",  # impossible month (00)
    "123456-7890123",  # arbitrary run, fails the checksum
]


@pytest.mark.parametrize("code", VALID_KR_RRN)
def test_kr_rrn_accepts_real_structure(code):
    assert _kr_rrn_valid(code) is True


@pytest.mark.parametrize("code", INVALID_KR_RRN)
def test_kr_rrn_rejects_invalid(code):
    assert _kr_rrn_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "90010-1123459",     # head too short (5 digits)
        "9001010-123459",    # wrong split (7-6)
        "900101-112345",     # tail too short (6 digits)
        "900101-11234567",   # tail too long (8 digits)
        "9001011123459",     # no hyphen -- contiguous run, not the RRN shape
        "900101-112345a",    # non-digit in the tail
        "abcdef-1123459",    # non-digit head
    ],
)
def test_kr_rrn_rejects_garbage(bad):
    # Defensive: empty / wrong-length / wrong-split / non-numeric input is never a
    # valid RRN.
    assert _kr_rrn_valid(bad) is False


def test_kr_rrn_in_memo_detected():
    findings = _scan("Verified holder RRN 900101-1123459 on file")
    codes = [f for f in findings if f.type == "kr_rrn"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the century/sex marker survives for triage; the rest is masked.
    assert codes[0].evidence == "XXXXXX-1XXXXXX"


def test_kr_rrn_redaction_masks_identity():
    findings = _scan("co-signer 780630-2123451 logged")
    codes = [f for f in findings if f.type == "kr_rrn"]
    assert len(codes) == 1
    assert codes[0].evidence == "XXXXXX-2XXXXXX"
    # The birth date, the serial, and the check digit never leave the tool.
    assert "780630" not in codes[0].evidence
    assert "123451" not in codes[0].evidence


def test_kr_rrn_wrong_check_digit_not_reported():
    # A YYMMDD-SNNNNNN-shaped run with a wrong check digit fails the checksum.
    findings = _scan("decoy reference 900101-1123450 ignored")
    assert "kr_rrn" not in {f.type for f in findings}


def test_kr_rrn_bad_birth_date_not_reported():
    # An RRN-shaped run with an impossible month fails the date gate even though
    # the checksum could pass for some such tokens.
    findings = _scan("decoy 901301-1123459 here")
    assert "kr_rrn" not in {f.type for f in findings}


def test_kr_rrn_does_not_collide_with_digit_scanners():
    # The hyphen breaks the token into a 6- and a 7-digit piece, neither of which
    # the account (8+) / routing (9) / card (13+) scanners match, and the
    # reservation keeps that guarantee explicit. The RRN is classified once.
    findings = _scan("paid holder 900101-1123459 today")
    types = [f.type for f in findings]
    assert types.count("kr_rrn") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_kr_rrn_does_not_collide_with_other_hyphenated_detectors():
    # The 6-7 split is distinct from every other hyphenated detector, so an RRN is
    # never mistaken for a Giro / sort code / routing / BSB / SSN and vice versa.
    assert "kr_rrn" not in {f.type for f in _scan("giro 10005-20 here")}
    assert "kr_rrn" not in {f.type for f in _scan("sort 20-00-00 here")}
    assert "kr_rrn" not in {f.type for f in _scan("routing 12345-003 here")}
    assert "kr_rrn" not in {f.type for f in _scan("bsb 062-000 here")}
    assert "kr_rrn" not in {f.type for f in _scan("ssn 123-45-6789 here")}


def test_kr_rrn_does_not_break_other_identifiers():
    # The RRN scan must not interfere with other identifiers on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    giro_findings = [f for f in _scan("giro 10005-20 today")
                     if f.type == "kr_giro"]
    assert len(giro_findings) == 1


def test_same_kr_rrn_deduped_per_field():
    findings = _scan(
        "rrn 900101-1123459 and again 900101-1123459 in one memo"
    )
    codes = [f for f in findings if f.type == "kr_rrn"]
    assert len(codes) == 1


def test_kr_rrn_leak_fixture(kr_rrn_file):
    findings = check_pii(kr_rrn_file.read_bytes())
    codes = [f for f in findings if f.type == "kr_rrn"]
    types = {f.type for f in findings}
    assert "kr_rrn" in types, f"expected kr_rrn, got: {types}"
    # The fixture leaks two valid RRNs in memos; the wrong-check-digit decoy
    # (900101-1123450) must NOT be reported.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # The masked shape preserves only the century/sex marker.
        assert c.evidence.startswith("XXXXXX-")
        assert c.evidence.endswith("XXXXXX")
        assert c.type == "kr_rrn"
    # The reservation guarantees the RRNs are never also reported as cards /
    # account numbers.
    assert "credit_card" not in types
    assert "account_number" not in types


def test_clean_file_no_kr_rrn(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "kr_rrn" not in {f.type for f in findings}


# --- Turkish TCKN (T.C. Kimlik Numarasi, national identification number) ----

# Each VALID_TR_TCKN value is a structurally complete 11-digit TCKN whose
# leading digit is 1-9 and whose two check digits both verify (these are
# synthetic, fictitious numbers constructed only to pass the public dual
# checksum, not real TCKNs of identified people). INVALID_TR_TCKN collects
# near-miss tokens that must fail the validator.
VALID_TR_TCKN = [
    "12345678950",  # d1..d9 = 1..9; A=25,B=20 -> d10=5; sum=50 -> d11=0
    "98765432150",  # d1..d9 = 9..1; A=25,B=20 -> d10=5; sum=50 -> d11=0
    "10000000078",  # d1=1, rest 0; A=1,B=0 -> d10=7; sum=8 -> d11=8
    "29722072102",  # mixed; A=19,B=13 -> d10=0; sum=32 -> d11=2
]

INVALID_TR_TCKN = [
    "12345678951",  # wrong d11 (expected 0, given 1)
    "12345678940",  # wrong d10 (expected 5, given 4)
    "00000000000",  # leading zero -- never a live TCKN
    "01234567899",  # leading zero -- never a live TCKN
    "11111111111",  # repeated digit -- fails the d10 check
    "12345678900",  # wrong both check digits
]


@pytest.mark.parametrize("code", VALID_TR_TCKN)
def test_tr_tckn_accepts_real_structure(code):
    assert _tr_tckn_valid(code) is True


@pytest.mark.parametrize("code", INVALID_TR_TCKN)
def test_tr_tckn_rejects_invalid(code):
    assert _tr_tckn_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "1234567895",       # 10 digits -- too short
        "123456789500",     # 12 digits -- too long
        "1234567895a",      # non-digit character
        "12345-67-8950",    # hyphenated -- not the canonical contiguous form
        "abcdefghijk",      # all letters
    ],
)
def test_tr_tckn_rejects_garbage(bad):
    # Defensive: empty / wrong-length / non-numeric input is never a valid TCKN.
    assert _tr_tckn_valid(bad) is False


def test_tr_tckn_in_memo_detected():
    findings = _scan("Verified holder TCKN 12345678950 on file")
    codes = [f for f in findings if f.type == "tr_tckn"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the leading digit survives for triage; the rest is masked.
    assert codes[0].evidence == "1XXXXXXXXXX"


def test_tr_tckn_redaction_masks_identity():
    findings = _scan("Co-signer 98765432150 logged")
    codes = [f for f in findings if f.type == "tr_tckn"]
    assert len(codes) == 1
    assert codes[0].evidence == "9XXXXXXXXXX"
    # The body of the TCKN and both check digits never leave the tool.
    assert "98765432150" not in codes[0].evidence
    assert "8765432150" not in codes[0].evidence


def test_tr_tckn_wrong_check_digit_not_reported_as_tckn():
    # An 11-digit token with a wrong check digit fails the gate and is NOT a
    # TCKN finding; the contiguous run still falls through to the
    # account-number scanner, which is the correct downgraded classification.
    findings = _scan("decoy reference 12345678951 ignored")
    types = {f.type for f in findings}
    assert "tr_tckn" not in types
    assert "account_number" in types


def test_tr_tckn_leading_zero_not_reported():
    # A leading zero is never a live TCKN; the validator rejects it and the run
    # falls through to the account-number scanner.
    findings = _scan("decoy reference 01234567899 ignored")
    assert "tr_tckn" not in {f.type for f in findings}


def test_tr_tckn_does_not_collide_with_digit_scanners():
    # Like the CLABE, the 11-digit TCKN run would otherwise be claimed by the
    # account-number scanner. The reservation guarantees it is reported once,
    # as a TCKN, and never also as an account number or a card or a routing
    # number. (The card scanner's 13-digit floor sits above the 11-digit TCKN
    # window, so no card collision is possible to begin with.)
    findings = _scan("paid holder 12345678950 today")
    types = [f.type for f in findings]
    assert types.count("tr_tckn") == 1
    assert "account_number" not in types
    assert "credit_card" not in types
    assert "routing_number" not in types


def test_tr_tckn_does_not_collide_with_hyphenated_detectors():
    # The TCKN is a contiguous 11-digit run; the hyphenated detectors all key
    # off a hyphenated presentation, so neither side mis-classifies the other.
    assert "tr_tckn" not in {f.type for f in _scan("ssn 123-45-6789 here")}
    assert "tr_tckn" not in {f.type for f in _scan("rrn 900101-1123459 here")}
    assert "tr_tckn" not in {f.type for f in _scan("cpf 111.444.777-35 here")}


def test_tr_tckn_does_not_break_other_identifiers():
    # The TCKN scan must not interfere with other identifiers on their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    routing_findings = _scan("routing 121000248 today")
    assert any(f.type == "routing_number" for f in routing_findings)


def test_same_tr_tckn_deduped_per_field():
    findings = _scan(
        "tckn 12345678950 and again 12345678950 in one memo"
    )
    codes = [f for f in findings if f.type == "tr_tckn"]
    assert len(codes) == 1


def test_tr_tckn_leak_fixture(tr_tckn_file):
    findings = check_pii(tr_tckn_file.read_bytes())
    codes = [f for f in findings if f.type == "tr_tckn"]
    types = {f.type for f in findings}
    assert "tr_tckn" in types, f"expected tr_tckn, got: {types}"
    # The fixture leaks two valid TCKNs in memos; the wrong-check-digit decoy
    # (12345678951) must NOT be reported as a TCKN. The decoy still falls
    # through to the generic account-number scanner -- that is correct and the
    # promised downgrade behaviour.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        assert c.evidence.endswith("XXXXXXXXXX")
        assert c.type == "tr_tckn"
    # The reservation guarantees the two valid TCKNs are never also reported
    # as account numbers.
    leading_digits = {c.evidence[0] for c in codes}
    assert leading_digits == {"1", "9"}


def test_clean_file_no_tr_tckn(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "tr_tckn" not in {f.type for f in findings}


# --- Norwegian fødselsnummer (national identity number) ---------------------

# Each VALID_NO_FNR value is a structurally complete 11-digit fødselsnummer:
# a real DDMMYY birth date, an individual / century-encoding number, and two
# trailing mod-11 weighted check digits that both verify (these are synthetic,
# fictitious numbers constructed only to satisfy the public dual checksum, not
# real fødselsnummer of identified people). INVALID_NO_FNR collects near-miss
# tokens that must fail the validator.
VALID_NO_FNR = [
    "11037543251",  # DDMMYY=11/03/75, ind=432, k1=5, k2=1
    "15059011089",  # DDMMYY=15/05/90, ind=110, k1=8, k2=9
    "23046032179",  # DDMMYY=23/04/60, ind=321, k1=7, k2=9
    "01010100050",  # DDMMYY=01/01/01, ind=000, k1=5, k2=0 (leading zero OK)
    "11037510035",  # DDMMYY=11/03/75, ind=100, k1=3, k2=5
]

INVALID_NO_FNR = [
    "11037543252",  # wrong k2 (expected 1, given 2)
    "11037543241",  # wrong k1 (expected 5, given 4)
    "00000000000",  # zero day AND zero month -- date fails
    "32010100000",  # day=32 -- impossible date
    "01130100000",  # month=13 -- impossible date
    "12345678950",  # synthetic TCKN -- date 12/34 fails, dual mod-11 too
    "98765432150",  # synthetic TCKN -- month 76 fails
    "11111111111",  # repeated digit -- both checksums fail
]


@pytest.mark.parametrize("code", VALID_NO_FNR)
def test_no_fnr_accepts_real_structure(code):
    assert _no_fnr_valid(code) is True


@pytest.mark.parametrize("code", INVALID_NO_FNR)
def test_no_fnr_rejects_invalid(code):
    assert _no_fnr_valid(code) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "1103754325",       # 10 digits -- too short
        "110375432510",     # 12 digits -- too long
        "1103754325a",      # non-digit character
        "11-03-75-43251",   # hyphenated -- not the canonical contiguous form
        "abcdefghijk",      # all letters
    ],
)
def test_no_fnr_rejects_garbage(bad):
    # Defensive: empty / wrong-length / non-numeric input is never a valid
    # fødselsnummer.
    assert _no_fnr_valid(bad) is False


def test_no_fnr_in_memo_detected():
    findings = _scan("Verified holder fnr 11037543251 on file")
    codes = [f for f in findings if f.type == "no_fnr"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the birth-month pair survives for triage; the rest is masked.
    assert codes[0].evidence == "XX03XXXXXXX"


def test_no_fnr_redaction_masks_identity():
    findings = _scan("Co-signer 23046032179 logged")
    codes = [f for f in findings if f.type == "no_fnr"]
    assert len(codes) == 1
    assert codes[0].evidence == "XX04XXXXXXX"
    # The full number, the day digits, year digits, individual number, and
    # both check digits never leave the tool.
    assert "23046032179" not in codes[0].evidence
    assert "230460" not in codes[0].evidence
    assert "32179" not in codes[0].evidence


def test_no_fnr_wrong_check_digit_not_reported_as_fnr():
    # An 11-digit token with a wrong check digit fails the gate and is NOT a
    # fødselsnummer finding; the contiguous run still falls through to the
    # account-number scanner, which is the correct downgraded classification.
    findings = _scan("decoy reference 11037543252 ignored")
    types = {f.type for f in findings}
    assert "no_fnr" not in types
    assert "account_number" in types


def test_no_fnr_bad_date_not_reported():
    # A token whose embedded birth date is impossible is never a live
    # fødselsnummer; the validator rejects it and the run falls through to
    # the account-number scanner.
    findings = _scan("decoy reference 32130100000 ignored")
    assert "no_fnr" not in {f.type for f in findings}


def test_no_fnr_does_not_collide_with_digit_scanners():
    # Like the TCKN, the 11-digit fødselsnummer run would otherwise be
    # claimed by the account-number scanner. The reservation guarantees it is
    # reported once, as a fødselsnummer, and never also as an account number
    # or a card or a routing number. (The card scanner's 13-digit floor sits
    # above the 11-digit window, so no card collision is possible.)
    findings = _scan("paid holder 11037543251 today")
    types = [f.type for f in findings]
    assert types.count("no_fnr") == 1
    assert "account_number" not in types
    assert "credit_card" not in types
    assert "routing_number" not in types


def test_no_fnr_does_not_collide_with_tckn():
    # The Norwegian scan runs BEFORE the Turkish scan; a fødselsnummer is
    # never re-reported as a TCKN. (The two dual-checksum gates are
    # independent, so a random 11-digit run passing both is astronomical,
    # but the reservation keeps the no-double-counting guarantee explicit.)
    findings = _scan("holder 11037543251 today")
    types = [f.type for f in findings]
    assert "no_fnr" in types
    assert "tr_tckn" not in types


def test_no_fnr_does_not_break_tckn():
    # A real TCKN must still be reported as a TCKN; the Norwegian scan above
    # it must not accidentally swallow it.
    findings = _scan("paid holder 12345678950 today")
    types = [f.type for f in findings]
    assert "tr_tckn" in types
    assert "no_fnr" not in types


def test_no_fnr_does_not_collide_with_hyphenated_detectors():
    # The fødselsnummer is a contiguous 11-digit run; the hyphenated detectors
    # all key off a hyphenated presentation, so neither side mis-classifies
    # the other.
    assert "no_fnr" not in {f.type for f in _scan("ssn 123-45-6789 here")}
    assert "no_fnr" not in {f.type for f in _scan("rrn 900101-1123459 here")}
    assert "no_fnr" not in {f.type for f in _scan("cpf 111.444.777-35 here")}


def test_no_fnr_does_not_break_other_identifiers():
    # The fødselsnummer scan must not interfere with other identifiers on
    # their own.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]
    routing_findings = _scan("routing 121000248 today")
    assert any(f.type == "routing_number" for f in routing_findings)


def test_same_no_fnr_deduped_per_field():
    findings = _scan(
        "fnr 11037543251 and again 11037543251 in one memo"
    )
    codes = [f for f in findings if f.type == "no_fnr"]
    assert len(codes) == 1


def test_no_fnr_leak_fixture(no_fnr_file):
    findings = check_pii(no_fnr_file.read_bytes())
    codes = [f for f in findings if f.type == "no_fnr"]
    types = {f.type for f in findings}
    assert "no_fnr" in types, f"expected no_fnr, got: {types}"
    # The fixture leaks two valid fødselsnummer in memos; the wrong-check-digit
    # decoy (11037543252) must NOT be reported as a fødselsnummer. The decoy
    # still falls through to the generic account-number scanner -- that is
    # correct and the promised downgrade behaviour.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        assert c.evidence.startswith("XX")
        assert c.evidence.endswith("XXXXXXX")
        assert c.type == "no_fnr"
    # The reservation guarantees the two valid fødselsnummer are never also
    # reported as account numbers or as TCKNs.
    month_pairs = {c.evidence[2:4] for c in codes}
    assert month_pairs == {"03", "04"}
    assert "tr_tckn" not in types


def test_clean_file_no_no_fnr(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "no_fnr" not in {f.type for f in findings}


# --- Finnish HETU (henkilötunnus / personal identity code) -----------------

# Each VALID_FI_HETU value is a structurally complete 11-character HETU: a
# six-digit DDMMYY birth date, a single century separator, a three-digit
# individual number, and a trailing mod-31 check character drawn from the
# 31-symbol alphabet ``0123456789ABCDEFHJKLMNPRSTUVWXY``. The check character
# is computed via ``alphabet[int(DDMMYY + NNN) mod 31]``. These are synthetic,
# fictitious values constructed only to satisfy the public mod-31 check, not
# real HETUs of identified people. INVALID_FI_HETU collects near-miss tokens
# that must fail the validator.
VALID_FI_HETU = [
    "131052-308T",   # 1900s, woman (NNN even); separator ``-``
    "010187-123V",   # 1900s, man (NNN odd); separator ``-``
    "290200A102L",   # 2000s; separator ``A``
    "100575-459M",   # 1900s, man
    "150892-247U",   # 1900s, man
    "110375-432T",   # 1900s, woman
    "151278+4566",   # 1800s separator ``+``; check is a digit (``6``)
    "010100A8883",   # 2000s; check is a digit (``3``)
]

INVALID_FI_HETU = [
    "131052-3089",   # wrong check char (correct is ``T``)
    "131052-308G",   # ``G`` is excluded from the check alphabet
    "131052-308I",   # ``I`` is excluded from the check alphabet
    "131052-308O",   # ``O`` is excluded from the check alphabet
    "131052-308Q",   # ``Q`` is excluded from the check alphabet
    "131052-308Z",   # ``Z`` is excluded from the check alphabet
    "320152-308T",   # day=32 -- impossible date
    "011352-308T",   # month=13 -- impossible date
    "131052/308T",   # ``/`` is not an assigned century separator
    "131052*308T",   # ``*`` is not an assigned century separator
    "131052H308T",   # ``H`` is not in the separator set
    "131052-30T",    # too short (10 chars)
    "131052-3081T",  # too long (12 chars)
    "abc052-308T",   # non-digit in date
    "131052-30aT",   # non-digit in individual number
]


@pytest.mark.parametrize("hetu", VALID_FI_HETU)
def test_fi_hetu_accepts_real_structure(hetu):
    assert _fi_hetu_valid(hetu) is True


@pytest.mark.parametrize("hetu", INVALID_FI_HETU)
def test_fi_hetu_rejects_invalid(hetu):
    assert _fi_hetu_valid(hetu) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "131052-308",       # missing check char
        "131052308T",       # missing separator (10 chars)
        "abcdefghijk",      # all letters
        "12345678901",      # all digits -- a TCKN-shaped contiguous run
    ],
)
def test_fi_hetu_rejects_garbage(bad):
    # Defensive: empty / wrong-length / structurally-wrong input is never a
    # valid HETU.
    assert _fi_hetu_valid(bad) is False


def test_fi_hetu_validator_accepts_lowercase():
    # The helper is case-insensitive; canonical forms are upper-case but a
    # lower-case run validates structurally so the helper is safe to reuse.
    assert _fi_hetu_valid("131052-308t") is True
    assert _fi_hetu_valid("290200a102l") is True


def test_fi_hetu_in_memo_detected():
    findings = _scan("Verified holder hetu 131052-308T on file")
    codes = [f for f in findings if f.type == "fi_hetu"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the century separator survives for triage; the rest is masked.
    assert codes[0].evidence == "XXXXXX-XXXX"


def test_fi_hetu_2000s_separator_preserved_in_redaction():
    # A 2000s HETU uses the ``A`` separator; redaction keeps it as the cohort
    # triage hint.
    findings = _scan("Co-signer 290200A102L logged")
    codes = [f for f in findings if f.type == "fi_hetu"]
    assert len(codes) == 1
    assert codes[0].evidence == "XXXXXXAXXXX"


def test_fi_hetu_redaction_masks_identity():
    findings = _scan("Verified 010187-123V on file")
    codes = [f for f in findings if f.type == "fi_hetu"]
    assert len(codes) == 1
    # The full HETU, the birth date, the individual number, and the check
    # character never leave the tool.
    assert "010187" not in codes[0].evidence
    assert "123" not in codes[0].evidence
    assert "V" not in codes[0].evidence


def test_fi_hetu_uppercase_only_in_memo():
    # The detection regex is UPPER-CASE-only (the precision lever, mirroring
    # the BIC / IFSC gates), so a lower-case HETU in prose is not reported as
    # a HETU finding.
    findings = _scan("verified holder 131052-308t on file")
    assert "fi_hetu" not in {f.type for f in findings}


def test_fi_hetu_wrong_check_char_not_reported():
    # A HETU-shaped token with a wrong check character fails the gate and is
    # NOT a fi_hetu finding.
    findings = _scan("decoy reference 131052-3089 ignored")
    assert "fi_hetu" not in {f.type for f in findings}


def test_fi_hetu_excluded_letter_not_reported():
    # The check-character alphabet deliberately omits G, I, O, Q, Z. A token
    # whose 11th character is any of those is not a HETU.
    for bad_check in ("G", "I", "O", "Q", "Z"):
        findings = _scan(f"decoy 131052-308{bad_check} ignored")
        assert "fi_hetu" not in {f.type for f in findings}, bad_check


def test_fi_hetu_bad_date_not_reported():
    # A token whose embedded DDMMYY does not form a real date is never a HETU.
    findings = _scan("malformed 320152-308T ignored")
    assert "fi_hetu" not in {f.type for f in findings}


def test_fi_hetu_does_not_collide_with_digit_scanners():
    # The HETU's century separator is a non-digit, so the contiguous-digit
    # scanners (account / routing / card) cannot match the full token. The
    # six-digit date is too short for the 8+/9/13+ floors, so no digit
    # scanner ever competes with the HETU.
    findings = _scan("holder 131052-308T file")
    types = [f.type for f in findings]
    assert types.count("fi_hetu") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_fi_hetu_does_not_collide_with_no_fnr_or_tckn():
    # The fødselsnummer and the TCKN are both contiguous 11-digit runs; the
    # HETU carries a non-digit separator, so the candidate windows are
    # disjoint. A pure fødselsnummer / TCKN run never trips fi_hetu, and a
    # HETU never trips no_fnr / tr_tckn.
    findings = _scan("fnr 11037543251 here")
    assert "fi_hetu" not in {f.type for f in findings}
    findings = _scan("hetu 131052-308T here")
    types = {f.type for f in findings}
    assert "fi_hetu" in types
    assert "no_fnr" not in types
    assert "tr_tckn" not in types


def test_fi_hetu_does_not_collide_with_hyphenated_detectors():
    # The HETU is structurally distinct from every other hyphenated
    # detector: a HETU has 6-letter-3-1 layout (with a letter or symbol in
    # position 7 and a letter or digit in position 11), where the SSN /
    # sort-code / routing / Giro / RRN / national-ID / CPF detectors all use
    # digit-only structural shapes.
    assert "fi_hetu" not in {f.type for f in _scan("ssn 123-45-6789 here")}
    assert "fi_hetu" not in {f.type for f in _scan("rrn 900101-1123459 here")}
    assert "fi_hetu" not in {f.type for f in _scan("cpf 111.444.777-35 here")}
    assert "fi_hetu" not in {f.type for f in _scan("sort 20-00-00 here")}


def test_fi_hetu_does_not_break_other_identifiers():
    # The HETU scan must not interfere with other identifiers on the same
    # statement; an SSN sitting in the same memo is still flagged.
    findings = _scan("ssn 123-45-6789 and hetu 131052-308T")
    types = {f.type for f in findings}
    assert "fi_hetu" in types
    assert "ssn" in types


def test_same_fi_hetu_deduped_per_field():
    # The same HETU written twice in the same field collapses to one finding.
    findings = _scan("hetu 131052-308T and 131052-308T again")
    codes = [f for f in findings if f.type == "fi_hetu"]
    assert len(codes) == 1


def test_fi_hetu_leak_fixture(fi_hetu_file):
    findings = check_pii(fi_hetu_file.read_bytes())
    codes = [f for f in findings if f.type == "fi_hetu"]
    types = {f.type for f in findings}
    assert "fi_hetu" in types, f"expected fi_hetu, got: {types}"
    # The fixture leaks two valid HETUs in memos; the wrong-check-char decoy
    # (131052-3089) must NOT be reported as a HETU.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        assert c.evidence.startswith("XXXXXX")
        assert c.evidence.endswith("XXXX")
        assert c.type == "fi_hetu"
    # The two leaked HETUs have separators ``-`` (1900s) and ``A`` (2000s);
    # the redaction preserves the separator as the cohort triage hint.
    separators = {c.evidence[6] for c in codes}
    assert separators == {"-", "A"}


def test_clean_file_no_fi_hetu(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "fi_hetu" not in {f.type for f in findings}


# --- Swedish personnummer ---------------------------------------------------

# Each VALID_SE_PNR value is a structurally complete 11-character personnummer:
# a six-digit YYMMDD birth date, a single century separator (``-`` for
# residents under 100, ``+`` for residents 100+), a three-digit individual
# number, and a trailing Luhn check digit over the nine YYMMDDNNN digits.
# These are synthetic, fictitious values constructed only to satisfy the
# public Luhn check, not real personnummer of identified people.
VALID_SE_PNR = [
    "890101-3493",  # under 100, ``-`` separator
    "890214-3323",
    "140101-1018",  # under 100, ``-`` separator (2014 birth)
    "850716-1233",
    "720101-1017",
    "950302-0076",
    "460104-0886",
    "140101+1018",  # 100+, ``+`` separator -- same digits as above
    "600616-3056",
    "730411-5178",
    "690913-7546",
]

INVALID_SE_PNR = [
    "890101-3490",  # wrong Luhn check digit (correct is ``3``)
    "890101-3491",
    "890101-3492",
    "891332-3493",  # day=32 -- impossible date (positions 5-6 of YYMMDD)
    "891301-3493",  # month=13 -- impossible date
    "890101/3493",  # ``/`` is not an assigned century separator
    "890101A3493",  # ``A`` is not an assigned personnummer separator
    "890101-0008",  # NNN=000 -- never assigned (the Luhn would compute 8)
    "890101-349",   # too short (10 chars)
    "890101-34931", # too long (12 chars)
    "abc101-3493",  # non-digit in date
    "890101-34a3",  # non-digit in tail
]


@pytest.mark.parametrize("pnr", VALID_SE_PNR)
def test_se_pnr_accepts_real_structure(pnr):
    assert _se_pnr_valid(pnr) is True


@pytest.mark.parametrize("pnr", INVALID_SE_PNR)
def test_se_pnr_rejects_invalid(pnr):
    assert _se_pnr_valid(pnr) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "890101-349",       # missing check digit
        "8901013493",       # missing separator (10 chars contiguous)
        "abcdefghijk",      # all letters
        "12345678901",      # all digits -- a TCKN-shaped contiguous run
    ],
)
def test_se_pnr_rejects_garbage(bad):
    # Defensive: empty / wrong-length / structurally-wrong input is never a
    # valid personnummer.
    assert _se_pnr_valid(bad) is False


def test_se_pnr_in_memo_detected():
    findings = _scan("Verified holder personnummer 890101-3493 on file")
    codes = [f for f in findings if f.type == "personnummer"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the century separator survives for triage; the rest is masked.
    assert codes[0].evidence == "XXXXXX-XXXX"


def test_se_pnr_plus_separator_preserved_in_redaction():
    # A 100+ years old personnummer uses the ``+`` separator; redaction keeps
    # it as the cohort triage hint.
    findings = _scan("Co-signer 140101+1018 logged")
    codes = [f for f in findings if f.type == "personnummer"]
    assert len(codes) == 1
    assert codes[0].evidence == "XXXXXX+XXXX"


def test_se_pnr_redaction_masks_identity():
    findings = _scan("Verified 720101-1017 on file")
    codes = [f for f in findings if f.type == "personnummer"]
    assert len(codes) == 1
    # The full personnummer, the birth date, the individual number, and the
    # check digit never leave the tool.
    assert "720101" not in codes[0].evidence
    assert "101" not in codes[0].evidence
    assert "1017" not in codes[0].evidence


def test_se_pnr_wrong_check_digit_not_reported():
    # A personnummer-shaped token with a wrong Luhn check digit fails the
    # gate and is NOT a personnummer finding.
    findings = _scan("decoy reference 890101-3490 ignored")
    assert "personnummer" not in {f.type for f in findings}


def test_se_pnr_bad_date_not_reported():
    # A token whose embedded YYMMDD does not form a real date is never a
    # personnummer.
    findings = _scan("malformed 891332-3493 ignored")
    assert "personnummer" not in {f.type for f in findings}


def test_se_pnr_zero_nnn_not_reported():
    # The NNN block was never assigned ``000``; the validator rejects it as a
    # structural impossibility.
    findings = _scan("decoy 890101-0008 ignored")
    assert "personnummer" not in {f.type for f in findings}


def test_se_pnr_does_not_collide_with_digit_scanners():
    # The personnummer's century separator is a non-digit, so the
    # contiguous-digit scanners (account / routing / card) cannot match the
    # full token. The six-digit date and the four-digit tail are too short
    # for the 8+/9/13+ floors, so no digit scanner ever competes with the
    # personnummer.
    findings = _scan("holder 890101-3493 file")
    types = [f.type for f in findings]
    assert types.count("personnummer") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_se_pnr_does_not_collide_with_fi_hetu():
    # The personnummer and the HETU share the ``\d{6}[-+]\d{4}`` candidate
    # window when the HETU's 11th check character happens to be a decimal
    # digit, but the validators are arithmetically independent: a token that
    # clears the Luhn-over-nine-digits check almost never clears the HETU's
    # mod-31 alphabet check, and vice versa. A pure HETU never trips
    # personnummer, and a pure personnummer never trips fi_hetu.
    findings = _scan("hetu 131052-308T here")
    types = {f.type for f in findings}
    assert "fi_hetu" in types
    assert "personnummer" not in types
    findings = _scan("pnr 890101-3493 here")
    types = {f.type for f in findings}
    assert "personnummer" in types
    assert "fi_hetu" not in types


def test_se_pnr_does_not_collide_with_no_fnr_or_tckn():
    # The fødselsnummer and the TCKN are both contiguous 11-digit runs; the
    # personnummer carries a non-digit separator, so the candidate windows
    # are disjoint. A pure fødselsnummer / TCKN run never trips personnummer,
    # and a personnummer never trips no_fnr / tr_tckn.
    findings = _scan("fnr 11037543251 here")
    assert "personnummer" not in {f.type for f in findings}
    findings = _scan("pnr 890101-3493 here")
    types = {f.type for f in findings}
    assert "personnummer" in types
    assert "no_fnr" not in types
    assert "tr_tckn" not in types


def test_se_pnr_does_not_collide_with_hyphenated_detectors():
    # The personnummer is structurally distinct from every other hyphenated
    # detector: a personnummer has a 6-1-3-1 layout, where the SSN /
    # sort-code / routing / Giro / RRN / national-ID / CPF detectors all use
    # different digit-grouping shapes.
    assert "personnummer" not in {f.type for f in _scan("ssn 123-45-6789 here")}
    assert "personnummer" not in {f.type for f in _scan("rrn 900101-1123459 here")}
    assert "personnummer" not in {f.type for f in _scan("cpf 111.444.777-35 here")}
    assert "personnummer" not in {f.type for f in _scan("sort 20-00-00 here")}


def test_se_pnr_does_not_break_other_identifiers():
    # The personnummer scan must not interfere with other identifiers on the
    # same statement; an SSN sitting in the same memo is still flagged.
    findings = _scan("ssn 123-45-6789 and pnr 890101-3493")
    types = {f.type for f in findings}
    assert "personnummer" in types
    assert "ssn" in types
    # A credit card in the same memo is still flagged.
    card_findings = _scan("card 4111111111111111 today")
    assert [f.type for f in card_findings] == ["credit_card"]


def test_same_se_pnr_deduped_per_field():
    # The same personnummer written twice in the same field collapses to one
    # finding.
    findings = _scan("pnr 890101-3493 and 890101-3493 again")
    codes = [f for f in findings if f.type == "personnummer"]
    assert len(codes) == 1


def test_se_pnr_leak_fixture(se_pnr_file):
    findings = check_pii(se_pnr_file.read_bytes())
    codes = [f for f in findings if f.type == "personnummer"]
    types = {f.type for f in findings}
    assert "personnummer" in types, f"expected personnummer, got: {types}"
    # The fixture leaks two valid personnummer in memos; the wrong-Luhn decoy
    # (890101-3490) must NOT be reported as a personnummer.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        assert c.evidence.startswith("XXXXXX")
        assert c.evidence.endswith("XXXX")
        assert c.type == "personnummer"
    # The two leaked personnummer have separators ``-`` (under 100) and ``+``
    # (100+); the redaction preserves the separator as the cohort triage hint.
    separators = {c.evidence[6] for c in codes}
    assert separators == {"-", "+"}


def test_clean_file_no_se_pnr(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "personnummer" not in {f.type for f in findings}


# --- Swiss AHV / AVS social-security number --------------------------------

# Each VALID_CH_AHV value is a structurally complete 13-digit AHV in its
# canonical 756.XXXX.XXXX.XX dotted form whose trailing EAN-13 mod-10 check
# digit verifies. These are synthetic, fictitious values constructed only to
# satisfy the public EAN-13 check, not real AHV numbers of identified people.
VALID_CH_AHV = [
    "756.1234.5678.97",
    "756.9217.0769.85",
    "756.3047.5009.62",
    "756.1111.1111.13",
    "756.9876.5432.17",
    "756.0000.0000.57",
]

INVALID_CH_AHV = [
    "756.1234.5678.90",  # wrong EAN-13 check digit (correct is 7)
    "756.1234.5678.91",
    "756.1234.5678.96",
    "756.1234.5678.98",
    "123.1234.5678.97",  # wrong country prefix -- not Swiss
    "757.1234.5678.97",  # wrong country prefix -- off-by-one from 756
    "000.0000.0000.00",  # all zeros: wrong prefix AND wrong check
    "756.1234.5678.9",   # too short (12 digits)
    "756.1234.5678.971", # too long (14 digits)
    "756-1234-5678-97",  # hyphens instead of the canonical dots
    "75612345678 97",    # no separators, then a space -- never canonical
    "756.abcd.5678.97",  # non-digit in body
]


@pytest.mark.parametrize("ahv", VALID_CH_AHV)
def test_ch_ahv_accepts_real_structure(ahv):
    assert _ch_ahv_valid(ahv) is True


@pytest.mark.parametrize("ahv", INVALID_CH_AHV)
def test_ch_ahv_rejects_invalid(ahv):
    assert _ch_ahv_valid(ahv) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "756",
        "756.1234.5678",      # missing tail
        "abcdefghijklm",      # all letters
        "756.....",           # only dots, no digits
        "...1234.5678.97",    # missing 756 prefix block
    ],
)
def test_ch_ahv_rejects_garbage(bad):
    assert _ch_ahv_valid(bad) is False


def test_ch_ahv_in_memo_detected():
    findings = _scan("Verified holder AHV 756.1234.5678.97 on file")
    codes = [f for f in findings if f.type == "ch_ahv"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # Only the Swiss 756 country prefix survives for triage; the rest is masked.
    assert codes[0].evidence == "756.XXXX.XXXX.XX"


def test_ch_ahv_redaction_masks_identity():
    findings = _scan("Verified 756.9217.0769.85 on file")
    codes = [f for f in findings if f.type == "ch_ahv"]
    assert len(codes) == 1
    # The identity-bearing digits and the check digit never leave the tool.
    assert "9217" not in codes[0].evidence
    assert "0769" not in codes[0].evidence
    assert "85" not in codes[0].evidence


def test_ch_ahv_wrong_check_digit_not_reported():
    # An AHV-shaped token with a wrong EAN-13 check digit fails the gate.
    findings = _scan("decoy reference 756.1234.5678.90 ignored")
    assert "ch_ahv" not in {f.type for f in findings}


def test_ch_ahv_wrong_country_prefix_not_reported():
    # A 3.4.4.2 dotted 13-digit token whose first triple is not 756 is never
    # a Swiss AHV.
    findings = _scan("decoy 123.1234.5678.97 ignored")
    assert "ch_ahv" not in {f.type for f in findings}


def test_ch_ahv_does_not_collide_with_digit_scanners():
    # The dotted AHV is structurally distinct from any contiguous digit run,
    # and the underlying 13-digit compact form is reserved under the
    # account / card / routing namespaces so a valid AHV is reported once
    # as the identity it is rather than being double-counted as a card or a
    # plain account-number run.
    findings = _scan("holder 756.1234.5678.97 file")
    types = [f.type for f in findings]
    assert types.count("ch_ahv") == 1
    assert "account_number" not in types
    assert "credit_card" not in types
    assert "routing_number" not in types


def test_ch_ahv_does_not_collide_with_cpf():
    # The only other ``.``-separated detector in this module is the
    # Brazilian CPF (NNN.NNN.NNN-NN), whose layout (3.3.3 with a trailing
    # dash) is structurally disjoint from the AHV's 3.4.4.2 all-dotted form.
    # A pure CPF never trips ch_ahv and a pure AHV never trips br_cpf.
    findings = _scan("cpf 111.444.777-35 here")
    types = {f.type for f in findings}
    assert "br_cpf" in types
    assert "ch_ahv" not in types
    findings = _scan("ahv 756.1234.5678.97 here")
    types = {f.type for f in findings}
    assert "ch_ahv" in types
    assert "br_cpf" not in types


def test_ch_ahv_does_not_break_other_identifiers():
    # The AHV scan must not interfere with other identifiers on the same
    # statement; an SSN in the same memo is still flagged.
    findings = _scan("ssn 123-45-6789 and ahv 756.1234.5678.97")
    types = {f.type for f in findings}
    assert "ch_ahv" in types
    assert "ssn" in types


def test_same_ch_ahv_deduped_per_field():
    # The same AHV written twice in the same field collapses to one finding.
    findings = _scan("ahv 756.1234.5678.97 and 756.1234.5678.97 again")
    codes = [f for f in findings if f.type == "ch_ahv"]
    assert len(codes) == 1


def test_ch_ahv_leak_fixture(ch_ahv_file):
    findings = check_pii(ch_ahv_file.read_bytes())
    codes = [f for f in findings if f.type == "ch_ahv"]
    types = {f.type for f in findings}
    assert "ch_ahv" in types, f"expected ch_ahv, got: {types}"
    # The fixture leaks two valid AHVs in memos; the wrong-check-digit decoy
    # (756.1234.5678.90) must NOT be reported as an AHV.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        assert c.evidence == "756.XXXX.XXXX.XX"
        assert c.type == "ch_ahv"


def test_clean_file_no_ch_ahv(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "ch_ahv" not in {f.type for f in findings}


# --- Danish CPR (Centrale Personregister) -----------------------------------

# Each VALID_DK_CPR value is a structurally complete 11-character CPR number:
# a six-digit DDMMYY birth date, a mandatory hyphen separator, and a four-digit
# serial that must not be 0000. These are synthetic, fictitious values
# constructed only to satisfy the public structural gates, not real CPR numbers
# of identified people.
VALID_DK_CPR = [
    "110375-4325",  # day=11, month=03, year=75, serial=4325
    "010180-1234",  # day=01, month=01, year=80, serial=1234
    "311299-0001",  # day=31, month=12, year=99, serial=0001 (non-zero)
    "150660-9999",  # day=15, month=06, year=60, serial=9999
    "280290-5678",  # day=28, month=02, year=90 (a common birth-date format)
]

INVALID_DK_CPR = [
    "991399-1234",  # month=13 -- impossible date
    "320175-4325",  # day=32 -- impossible date
    "000175-4325",  # day=00 -- impossible date (DD is 1-31)
    "110075-4325",  # month=00 -- impossible date (MM is 1-12)
    "110375-0000",  # serial=0000 -- never assigned
    "110375-432",   # too short (10 chars)
    "110375-43250", # too long (12 chars)
    "110375/4325",  # ``/`` not a hyphen
    "1103754325",   # missing separator (10 chars contiguous)
    "110375A4325",  # letter in separator position
    "ab0375-4325",  # non-digit in date
    "11037X-4325",  # non-digit in date
    "110375-432X",  # non-digit in serial
]


@pytest.mark.parametrize("cpr", VALID_DK_CPR)
def test_dk_cpr_accepts_real_structure(cpr):
    assert _dk_cpr_valid(cpr) is True


@pytest.mark.parametrize("cpr", INVALID_DK_CPR)
def test_dk_cpr_rejects_invalid(cpr):
    assert _dk_cpr_valid(cpr) is False


def test_dk_cpr_in_memo_detected():
    findings = _scan("Verified holder CPR 110375-4325 on file")
    codes = [f for f in findings if f.type == "dk_cpr"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # The month digits survive for triage; everything else is masked.
    assert codes[0].evidence == "XX03XX-XXXX"


def test_dk_cpr_redaction_masks_identity():
    findings = _scan("holder 010180-1234 file")
    codes = [f for f in findings if f.type == "dk_cpr"]
    assert len(codes) == 1
    # Birth day, year, and serial must never leave the tool.
    assert "01" not in codes[0].evidence[:2]   # day masked
    assert "80" not in codes[0].evidence[4:6]  # year masked
    assert "1234" not in codes[0].evidence     # serial masked


def test_dk_cpr_bad_date_not_reported():
    # A token whose embedded DDMMYY does not form a real date is never a CPR.
    findings = _scan("decoy reference 991399-1234 ignored")
    assert "dk_cpr" not in {f.type for f in findings}


def test_dk_cpr_zero_serial_not_reported():
    # The serial was never assigned 0000; the validator rejects it.
    findings = _scan("decoy 110375-0000 ignored")
    assert "dk_cpr" not in {f.type for f in findings}


def test_dk_cpr_does_not_collide_with_personnummer():
    # The personnummer scan runs before CPR (it's more precise); a token that
    # passes the Luhn check is claimed as a personnummer and is not also
    # reported as a dk_cpr.
    findings = _scan("pnr 890101-3493 here")
    types = {f.type for f in findings}
    assert "personnummer" in types
    assert "dk_cpr" not in types


def test_dk_cpr_does_not_collide_with_digit_scanners():
    # The CPR's mandatory hyphen keeps the six-digit date and four-digit serial
    # disjoint from the contiguous-digit scanners (account / routing / card).
    findings = _scan("holder 110375-4325 file")
    types = [f.type for f in findings]
    assert types.count("dk_cpr") == 1
    assert "account_number" not in types
    assert "routing_number" not in types
    assert "credit_card" not in types


def test_dk_cpr_does_not_collide_with_other_hyphenated_detectors():
    # The CPR uses a 6-4 hyphenated split -- distinct from SSN (3-2-4), UK
    # sort code (2-2-2), Canadian routing (5-3), and Australian BSB (3-3).
    assert "dk_cpr" not in {f.type for f in _scan("ssn 123-45-6789 here")}
    assert "dk_cpr" not in {f.type for f in _scan("sort 20-00-00 here")}


def test_dk_cpr_does_not_break_other_identifiers():
    # The CPR scan must not interfere with other identifiers in the same memo.
    findings = _scan("ssn 123-45-6789 and cpr 110375-4325")
    types = {f.type for f in findings}
    assert "dk_cpr" in types
    assert "ssn" in types


def test_same_dk_cpr_deduped_per_field():
    # The same CPR written twice in the same field collapses to one finding.
    findings = _scan("cpr 110375-4325 and 110375-4325 again")
    codes = [f for f in findings if f.type == "dk_cpr"]
    assert len(codes) == 1


def test_dk_cpr_leak_fixture(dk_cpr_file):
    findings = check_pii(dk_cpr_file.read_bytes())
    codes = [f for f in findings if f.type == "dk_cpr"]
    types = {f.type for f in findings}
    assert "dk_cpr" in types, f"expected dk_cpr, got: {types}"
    # The fixture leaks two valid CPRs in memos; the bad-date decoy
    # (991399-1234, month=13) must NOT be reported as a dk_cpr.
    assert len(codes) == 2
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        # Evidence format: XXDDXX-XXXX where month digits survive.
        assert c.evidence.startswith("XX")
        assert c.evidence[4:6] == "XX"
        assert c.evidence.endswith("-XXXX")
        assert c.type == "dk_cpr"


def test_clean_file_no_dk_cpr(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "dk_cpr" not in {f.type for f in findings}


# --- Dutch BSN (Burgerservicenummer) ----------------------------------------

# Each VALID_NL_BSN value is a 9-digit Dutch citizen-service number that
# passes the public mod-11 elfproef and the non-zero leading-digit gate.
# These are synthetic values constructed to satisfy the public formula only;
# they are not real BSNs of identified people.
VALID_NL_BSN = [
    "123456782",  # 9*1+8*2+7*3+6*4+5*5+4*6+3*7+2*8-2 = 154, 154%11==0
    "111111110",  # 9+8+7+6+5+4+3+2-0 = 44, 44%11==0
    "987654329",  # 9*9+8*8+7*7+6*6+5*5+4*4+3*3+2*2-9 = 275, 275%11==0
    "234567818",  # 9*2+8*3+7*4+6*5+5*6+4*7+3*8+2*1-8 = 176, 176%11==0
]

# Synthetic BSNs that must NOT pass the elfproef or the structural gates.
INVALID_NL_BSN = [
    "123456780",  # elfproef fails (152%11=9)
    "000000000",  # all-zeros -- also leading-zero gate
    "012345678",  # leading zero -- valid elfproef but d1==0
    "12345678",   # 8 digits -- too short
    "1234567890", # 10 digits -- too long
    "12345678X",  # non-digit
    "ABCDEFGHI",  # all letters
]


def _bsn_elfproef(s: str) -> int:
    """Compute the elfproef weighted sum for a 9-digit string."""
    d = [int(c) for c in s]
    return sum([9, 8, 7, 6, 5, 4, 3, 2, -1][i] * d[i] for i in range(9))


# Verify our hardcoded VALID_NL_BSN values actually pass the elfproef.
@pytest.mark.parametrize("bsn", VALID_NL_BSN)
def test_nl_bsn_elfproef_verified(bsn):
    """Each VALID_NL_BSN entry must pass the elfproef (this guards the list)."""
    if not bsn.isdigit() or len(bsn) != 9:
        pytest.skip("malformed test data")
    if bsn[0] == "0":
        pytest.skip("leading-zero entry")
    assert _bsn_elfproef(bsn) % 11 == 0, f"{bsn} does not pass elfproef"


@pytest.mark.parametrize("bsn", ["123456782", "111111110"])
def test_nl_bsn_accepts_valid(bsn):
    assert _nl_bsn_valid(bsn) is True


@pytest.mark.parametrize("bsn", INVALID_NL_BSN)
def test_nl_bsn_rejects_invalid(bsn):
    assert _nl_bsn_valid(bsn) is False


def test_nl_bsn_leading_zero_rejected():
    # A 9-digit run starting with 0 is always rejected, even if the digits
    # happen to satisfy the elfproef weighted sum.
    assert _nl_bsn_valid("012345678") is False


def test_nl_bsn_in_memo_detected():
    findings = _scan("Verified holder BSN 123456782 on file")
    codes = [f for f in findings if f.type == "nl_bsn"]
    assert len(codes) == 1
    assert codes[0].severity == "high"
    assert codes[0].check == "pii"
    # All 9 digits are masked -- no identifying fragment survives.
    assert codes[0].evidence == "XXXXXXXXX"


def test_nl_bsn_redaction_masks_all_digits():
    findings = _scan("BSN 111111110 on record")
    codes = [f for f in findings if f.type == "nl_bsn"]
    assert len(codes) == 1
    assert codes[0].evidence == "XXXXXXXXX"


def test_nl_bsn_elfproef_failure_not_reported():
    # A 9-digit run that fails the elfproef must not be reported as nl_bsn.
    findings = _scan("reference 123456780 skip")
    assert "nl_bsn" not in {f.type for f in findings}


def test_nl_bsn_does_not_collide_with_routing_number():
    # A BSN that passes the elfproef must be reported as nl_bsn, not as a
    # routing_number or probable_routing_number -- it is reserved first.
    findings = _scan("BSN 123456782 on file")
    types = {f.type for f in findings}
    assert "nl_bsn" in types
    assert "routing_number" not in types
    assert "probable_routing_number" not in types


def test_nl_bsn_does_not_collide_with_account_number():
    # The same 9-digit BSN run must not also appear as an account_number.
    findings = _scan("BSN 123456782 here")
    types = {f.type for f in findings}
    assert "nl_bsn" in types
    assert "account_number" not in types


def test_nl_bsn_does_not_collide_with_credit_card():
    # The 9-digit BSN is too short for a card but must not be misclassified.
    findings = _scan("BSN 111111110 in memo")
    types = {f.type for f in findings}
    assert "nl_bsn" in types
    assert "credit_card" not in types


def test_same_nl_bsn_deduped_per_field():
    # The same BSN written twice in the same field collapses to one finding.
    findings = _scan("bsn 123456782 and 123456782 again")
    codes = [f for f in findings if f.type == "nl_bsn"]
    assert len(codes) == 1


def test_nl_bsn_does_not_break_other_identifiers():
    # The BSN scan must not interfere with other identifiers in the same memo.
    findings = _scan("ssn 123-45-6789 and bsn 123456782")
    types = {f.type for f in findings}
    assert "nl_bsn" in types
    assert "ssn" in types


def test_nl_bsn_leak_fixture(nl_bsn_file):
    findings = check_pii(nl_bsn_file.read_bytes())
    codes = [f for f in findings if f.type == "nl_bsn"]
    types = {f.type for f in findings}
    assert "nl_bsn" in types, f"expected nl_bsn, got: {types}"
    assert len(codes) >= 1
    assert all(c.severity == "high" for c in codes)
    for c in codes:
        assert c.evidence == "XXXXXXXXX"


def test_clean_file_no_nl_bsn(clean_file):
    findings = check_pii(clean_file.read_bytes())
    assert "nl_bsn" not in {f.type for f in findings}
