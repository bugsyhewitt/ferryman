"""HackerOne-markdown output for ferryman, built on the shared h1-reporter lib.

ferryman's internal :class:`ferryman.findings.Finding` is scanner-shaped
(check / type / message / location / evidence). The HackerOne submission body is
not ferryman's concern -- that formatting lives in the suite-wide ``h1_reporter``
library so every necromancer tool produces a consistent report. This module is
the thin adapter that maps a ferryman finding into an ``h1_reporter.Finding``.

[Worker decision: ferryman had no h1md output before this refactor -- only json
and text. Adding h1md here is the integration point for the shared library; it
introduces a new --format choice without changing any existing json/text output,
so all pre-existing fixtures and tests remain byte-identical.]
"""

from __future__ import annotations

from typing import Iterable

from h1_reporter import Finding as H1Finding
from h1_reporter import render_h1md

from ferryman.findings import Finding

# Per-check business-impact framing for the fintech/OFX surface.
_IMPACT = {
    "malformed": (
        "A malformed or hostile OFX document can drive parser confusion in the "
        "consuming application -- XML external entity expansion, entity-bomb "
        "denial of service, or schema-violation crashes -- on the financial "
        "data-ingest path."
    ),
    "pii": (
        "The document exposes personally identifiable financial data (account "
        "numbers, names, balances). Leakage on this path is a privacy and "
        "compliance exposure for the program owner."
    ),
    "anomaly": (
        "Anomalous transaction values may indicate data-integrity problems or "
        "an injection attempt against downstream financial processing."
    ),
}


def _to_h1_finding(f: Finding) -> H1Finding:
    """Map one ferryman finding into the shared h1_reporter Finding shape."""
    title = f"{f.check}/{f.type}"
    description = f.message or ""

    repro: list[str] = []
    if f.location:
        repro.append(f"Inspect `{f.location}` in the scanned OFX document.")
    repro.append(f"Run `ferryman --check {f.check} <file.ofx>` and review the finding.")

    evidence = [f.evidence] if f.evidence else []

    return H1Finding(
        title=title,
        severity=f.severity,
        description=description,
        reproduction_steps=repro,
        business_impact=_IMPACT.get(f.check, ""),
        evidence=evidence,
    )


def to_h1md(findings: Iterable[Finding]) -> str:
    """Render ferryman findings to HackerOne-flavored markdown."""
    mapped = [_to_h1_finding(f) for f in findings]
    return render_h1md(mapped, title="ferryman OFX findings")
