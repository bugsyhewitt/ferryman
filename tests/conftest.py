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
def credit_card_file() -> Path:
    """A bank statement leaking Luhn-valid payment-card numbers in free text."""
    return FIXTURES / "credit-card-leak.ofx"


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
