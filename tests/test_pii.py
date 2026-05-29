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
    _ca_routing_valid,
    _cusip_valid,
    _iban_valid,
    _ifsc_valid,
    _isin_valid,
    _itin_valid,
    _lei_valid,
    _luhn_valid,
    _redact_email,
    _sedol_valid,
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
