"""Shared pytest fixtures: paths to the OFX test files shipped in the repo."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def xxe_file() -> Path:
    return FIXTURES / "xxe-attempt.ofx"


@pytest.fixture
def pii_file() -> Path:
    return FIXTURES / "pii-leak.ofx"


@pytest.fixture
def clean_file() -> Path:
    return FIXTURES / "clean.ofx"


@pytest.fixture
def itin_file() -> Path:
    """A bank statement leaking valid US ITINs (and a real SSN) in free text."""
    return FIXTURES / "itin-leak.ofx"


@pytest.fixture
def credit_card_file() -> Path:
    """A bank statement leaking Luhn-valid payment-card numbers in free text."""
    return FIXTURES / "credit-card-leak.ofx"


@pytest.fixture
def email_file() -> Path:
    """A bank statement leaking email addresses in free-text name/memo fields."""
    return FIXTURES / "email-leak.ofx"


@pytest.fixture
def iban_file() -> Path:
    """A bank statement leaking valid IBANs (mod-97) in free text."""
    return FIXTURES / "iban-leak.ofx"


@pytest.fixture
def anomaly_file() -> Path:
    return FIXTURES / "anomaly.ofx"


@pytest.fixture
def anomalous_amount_file() -> Path:
    """A bank statement carrying zero, sign-flipped, and out-of-range amounts."""
    return FIXTURES / "anomalous-amount.ofx"


@pytest.fixture
def isin_file() -> Path:
    """An investment statement leaking valid ISINs (ISO 6166) in free text."""
    return FIXTURES / "isin-leak.ofx"


@pytest.fixture
def cusip_file() -> Path:
    """An investment statement leaking valid CUSIPs in free-text memos."""
    return FIXTURES / "cusip-leak.ofx"


@pytest.fixture
def sedol_file() -> Path:
    """An investment statement leaking valid SEDOLs in free-text memos."""
    return FIXTURES / "sedol-leak.ofx"


@pytest.fixture
def lei_file() -> Path:
    """An investment statement leaking valid LEIs (ISO 17442) in free text."""
    return FIXTURES / "lei-leak.ofx"


@pytest.fixture
def bic_file() -> Path:
    """A bank statement leaking valid BIC/SWIFT codes (ISO 9362) in free text."""
    return FIXTURES / "bic-leak.ofx"


@pytest.fixture
def uk_sort_code_file() -> Path:
    """A bank statement leaking valid UK sort codes (NN-NN-NN) in free text."""
    return FIXTURES / "uk-sort-code-leak.ofx"


@pytest.fixture
def ca_routing_file() -> Path:
    """A bank statement leaking valid Canadian routing numbers (TTTTT-III)."""
    return FIXTURES / "ca-routing-leak.ofx"


@pytest.fixture
def au_bsb_file() -> Path:
    """A bank statement leaking valid Australian BSB codes (NNN-NNN)."""
    return FIXTURES / "au-bsb-leak.ofx"


@pytest.fixture
def ifsc_file() -> Path:
    """A bank statement leaking valid Indian IFSC codes (BBBB0BRANCH)."""
    return FIXTURES / "ifsc-leak.ofx"


@pytest.fixture
def clabe_file() -> Path:
    """A bank statement leaking valid Mexican CLABE numbers (18-digit) in free text."""
    return FIXTURES / "clabe-leak.ofx"


@pytest.fixture
def kr_giro_file() -> Path:
    """A bank statement leaking valid South Korean Giro numbers (NNNNN-NN)."""
    return FIXTURES / "kr-giro-leak.ofx"


@pytest.fixture
def th_natid_file() -> Path:
    """A bank statement leaking valid Thai national IDs (N-NNNN-NNNNN-NN-N)."""
    return FIXTURES / "th-natid-leak.ofx"


@pytest.fixture
def br_cpf_file() -> Path:
    """A bank statement leaking valid Brazilian CPFs (NNN.NNN.NNN-NN)."""
    return FIXTURES / "br-cpf-leak.ofx"


@pytest.fixture
def mx_curp_file() -> Path:
    """A bank statement leaking valid Mexican CURPs (18-char identity keys)."""
    return FIXTURES / "mx-curp-leak.ofx"


@pytest.fixture
def kr_rrn_file() -> Path:
    """A bank statement leaking valid South Korean RRNs (YYMMDD-SNNNNNN)."""
    return FIXTURES / "kr-rrn-leak.ofx"


@pytest.fixture
def tr_tckn_file() -> Path:
    """A bank statement leaking valid Turkish TCKNs (11-digit national IDs)."""
    return FIXTURES / "tr-tckn-leak.ofx"


@pytest.fixture
def no_fnr_file() -> Path:
    """A bank statement leaking valid Norwegian fødselsnummer (11-digit IDs)."""
    return FIXTURES / "no-fnr-leak.ofx"


@pytest.fixture
def fi_hetu_file() -> Path:
    """A bank statement leaking valid Finnish HETUs (DDMMYYCNNNK identity codes)."""
    return FIXTURES / "fi-hetu-leak.ofx"


@pytest.fixture
def se_pnr_file() -> Path:
    """A bank statement leaking valid Swedish personnummer (YYMMDD-NNNC identity codes)."""
    return FIXTURES / "se-pnr-leak.ofx"


@pytest.fixture
def entity_bomb_file() -> Path:
    return FIXTURES / "entity-bomb.ofx"


@pytest.fixture
def cdata_injection_file() -> Path:
    return FIXTURES / "cdata-injection.ofx"


@pytest.fixture
def investment_file() -> Path:
    """A clean investment (INVSTMTRS) statement: a buy and a sell, no leaks."""
    return FIXTURES / "investment.ofx"


@pytest.fixture
def investment_pii_file() -> Path:
    """Investment statement leaking an SSN and carrying anomalous amounts."""
    return FIXTURES / "investment-pii.ofx"


@pytest.fixture
def investment_secid_leak_file() -> Path:
    """Investment statement with an SSN smuggled into the security id."""
    return FIXTURES / "investment-secid-leak.ofx"
