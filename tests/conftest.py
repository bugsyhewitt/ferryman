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
def anomaly_file() -> Path:
    return FIXTURES / "anomaly.ofx"
