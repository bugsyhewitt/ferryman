"""Safe OFX parsing helpers for the pii and anomaly checks.

[Worker decision: ofxtools is used only for the pii and anomaly checks, which
require a structured view of well-formed OFX. The malformed check never calls
in here -- it inspects raw bytes so a hostile file is never parsed. If parsing
fails (the file is malformed), these helpers return an empty statement list;
the malformed check is the one responsible for reporting that the file could
not be trusted.]

v0.1 scope: BankAccount + CreditAccount statements only. Investment accounts
are explicitly out of scope, so we iterate ``ofx.statements`` (which covers
bank and credit-card statements) and ignore anything else.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Transaction:
    """A flattened transaction with the fields ferryman inspects."""

    trntype: str | None
    dtposted: datetime | None
    name: str | None
    memo: str | None
    fitid: str | None
    amount: str | None


@dataclass(slots=True)
class Statement:
    """A flattened bank/credit statement."""

    acctid: str | None
    accttype: str | None
    bankid: str | None
    transactions: list[Transaction]


def _str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def parse_statements(raw: bytes) -> list[Statement]:
    """Parse raw OFX bytes into a list of flattened statements.

    Returns an empty list if the bytes cannot be parsed as valid OFX. The
    malformed check, not this helper, is responsible for flagging un-parseable
    input.
    """
    # Imported lazily so importing ferryman.parsing never hard-requires
    # ofxtools at module-load time (keeps unit tests of other modules light).
    from ofxtools.Parser import OFXTree

    try:
        tree = OFXTree()
        tree.parse(io.BytesIO(raw))
        ofx = tree.convert()
    except Exception:
        return []

    statements: list[Statement] = []
    for stmt in getattr(ofx, "statements", []) or []:
        account = getattr(stmt, "account", None)
        acctid = _str(getattr(account, "acctid", None))
        accttype = _str(getattr(account, "accttype", None))
        bankid = _str(getattr(account, "bankid", None))

        txs: list[Transaction] = []
        for tx in getattr(stmt, "transactions", []) or []:
            txs.append(
                Transaction(
                    trntype=_str(getattr(tx, "trntype", None)),
                    dtposted=getattr(tx, "dtposted", None),
                    name=_str(getattr(tx, "name", None)),
                    memo=_str(getattr(tx, "memo", None)),
                    fitid=_str(getattr(tx, "fitid", None)),
                    amount=_str(getattr(tx, "trnamt", None)),
                )
            )
        statements.append(
            Statement(
                acctid=acctid,
                accttype=accttype,
                bankid=bankid,
                transactions=txs,
            )
        )
    return statements
