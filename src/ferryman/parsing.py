"""Safe OFX parsing helpers for the pii and anomaly checks.

[Worker decision: ofxtools is used only for the pii and anomaly checks, which
require a structured view of well-formed OFX. The malformed check never calls
in here -- it inspects raw bytes so a hostile file is never parsed. If parsing
fails (the file is malformed), these helpers return an empty statement list;
the malformed check is the one responsible for reporting that the file could
not be trusted.]

Scope: BankAccount + CreditAccount statements *and* investment (``INVSTMTRS``)
statements. ofxtools exposes all three under ``ofx.statements`` -- bank and
credit statements carry ``transactions`` of the ``STMTTRN`` shape, while an
investment statement carries an ``INVTRANLIST`` of investment transactions
(``BUYMF``, ``SELLMF``, ``REINVEST``, ``INCOME``, ...). We flatten both kinds
into the same :class:`Transaction` model so the pii and anomaly checks can walk
a single uniform structure, with investment-only fields (units, unit price,
security id) populated only for investment transactions.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Transaction:
    """A flattened transaction with the fields ferryman inspects.

    Bank / credit transactions populate ``trntype``, ``dtposted``, ``name``,
    ``memo``, ``fitid`` and ``amount``. Investment transactions reuse the same
    fields where they map cleanly (``dtposted`` from the trade date, ``amount``
    from the transaction ``TOTAL``) and additionally populate the investment-
    only fields below. ``is_investment`` lets a check branch on the kind without
    re-deriving it.
    """

    trntype: str | None
    dtposted: datetime | None
    name: str | None
    memo: str | None
    fitid: str | None
    amount: str | None
    # Investment-only fields. ``None`` for bank/credit transactions.
    is_investment: bool = False
    units: str | None = None
    unitprice: str | None = None
    secid: str | None = None


@dataclass(slots=True)
class Statement:
    """A flattened bank / credit / investment statement."""

    acctid: str | None
    accttype: str | None
    bankid: str | None
    transactions: list[Transaction]
    # True when this came from an INVSTMTRS investment response. For investment
    # statements ``bankid`` carries the broker id and ``accttype`` is ``None``.
    is_investment: bool = False


def _str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _flatten_bank_transactions(stmt: Any) -> list[Transaction]:
    """Flatten a bank/credit statement's STMTTRN transactions."""
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
    return txs


def _flatten_investment_transactions(stmt: Any) -> list[Transaction]:
    """Flatten an INVSTMTRS statement's investment transactions.

    ofxtools exposes investment transactions (``BUYMF``, ``SELLMF``,
    ``REINVEST``, ``INCOME``, ...) through ``stmt.transactions`` just like bank
    statements, but the per-transaction shape differs: there is no ``name`` and
    no ``trnamt`` / ``dtposted``. We map the investment fields onto the shared
    model so the existing checks keep working:

    - ``trntype``   <- the transaction's class name (e.g. ``BUYMF``), upper-cased
    - ``dtposted``  <- the trade date (``dttrade``), or settle date as a fallback
    - ``amount``    <- the transaction ``TOTAL``
    - ``memo``      <- the investment ``MEMO`` free-text field
    - ``units`` / ``unitprice`` / ``secid`` <- investment-only fields
    """
    txs: list[Transaction] = []
    for tx in getattr(stmt, "transactions", []) or []:
        dt = getattr(tx, "dttrade", None) or getattr(tx, "dtsettle", None)
        txs.append(
            Transaction(
                trntype=type(tx).__name__.upper(),
                dtposted=dt if isinstance(dt, datetime) else None,
                name=None,
                memo=_str(getattr(tx, "memo", None)),
                fitid=_str(getattr(tx, "fitid", None)),
                amount=_str(getattr(tx, "total", None)),
                is_investment=True,
                units=_str(getattr(tx, "units", None)),
                unitprice=_str(getattr(tx, "unitprice", None)),
                secid=_str(getattr(tx, "uniqueid", None)),
            )
        )
    return txs


def _is_investment_statement(stmt: Any) -> bool:
    """Return True if a parsed statement is an INVSTMTRS investment response.

    We detect by class name (``INVSTMTRS``) rather than ``isinstance`` so we
    never have to import the investment model at module-load time, and so a
    future ofxtools rename of the concrete class still degrades gracefully.
    """
    return type(stmt).__name__.upper() == "INVSTMTRS"


def parse_statements(raw: bytes) -> list[Statement]:
    """Parse raw OFX bytes into a list of flattened statements.

    Covers bank, credit, and investment (INVSTMTRS) statements. Returns an
    empty list if the bytes cannot be parsed as valid OFX -- the malformed
    check, not this helper, is responsible for flagging un-parseable input.
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

        if _is_investment_statement(stmt):
            # Investment accounts carry a broker id, not a bank id / acct type.
            statements.append(
                Statement(
                    acctid=acctid,
                    accttype=None,
                    bankid=_str(getattr(account, "brokerid", None)),
                    transactions=_flatten_investment_transactions(stmt),
                    is_investment=True,
                )
            )
            continue

        statements.append(
            Statement(
                acctid=acctid,
                accttype=_str(getattr(account, "accttype", None)),
                bankid=_str(getattr(account, "bankid", None)),
                transactions=_flatten_bank_transactions(stmt),
                is_investment=False,
            )
        )
    return statements
