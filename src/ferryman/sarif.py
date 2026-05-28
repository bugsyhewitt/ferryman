"""SARIF 2.1.0 output for ferryman (POST_V01 Rank 9).

SARIF (Static Analysis Results Interchange Format) is the standard machine
output for security scanners: GitHub's Security tab, the VS Code Problems panel,
and most CI SAST dashboards ingest it natively. Emitting `--format sarif` lets
ferryman findings appear alongside professional SAST tools rather than only in a
HackerOne markdown report.

[Worker decision (POST_V01 Rank 9): SARIF is just a JSON schema, so this module
adds zero new dependencies -- it builds the envelope with the stdlib ``json``
module via the canonical Finding shape. It is a sibling of ``reporting.py``
(the h1md adapter) rather than living in it, so the two output integrations stay
independent and neither touches the existing json/text paths.

Severity mapping: SARIF's ``level`` enum is only error/warning/note/none, which
is coarser than ferryman's five-level scale. We map critical+high -> "error",
medium -> "warning", low+info -> "note", and preserve the exact ferryman
severity in ``properties.severity`` plus a numeric ``rank`` (0-100) so SARIF
consumers that surface rank (e.g. GitHub) order findings the way ferryman does.

When a finding's ``location`` carries a parseable ``line N`` token (the malformed
check emits these) we attach a SARIF ``region`` with ``startLine`` so the finding
links to the right line in a viewer. Otherwise the artifact location alone is
emitted, with the free-form locator preserved in ``properties.location``.]
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from ferryman import __version__
from ferryman.findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

# ferryman severity -> SARIF result.level (the coarse SARIF enum).
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# ferryman severity -> SARIF rank (0.0 worst..100.0; higher = more severe).
# GitHub and other consumers use rank to order results within a level.
_RANK_BY_SEVERITY = {
    "critical": 100.0,
    "high": 80.0,
    "medium": 50.0,
    "low": 20.0,
    "info": 5.0,
}

# Default artifact URI when a batch report folds the source file into the
# location field instead of carrying a standalone path.
_DEFAULT_ARTIFACT = "input.ofx"

# Pull a 1-based line number out of a free-form location string ("line 4",
# "input.ofx: line 4", etc). Used to build a SARIF region.
_LINE_RE = re.compile(r"\bline\s+(\d+)\b", re.IGNORECASE)


def _level_for(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "warning")


def _rank_for(severity: str) -> float:
    return _RANK_BY_SEVERITY.get(severity, 50.0)


def _rule_id(f: Finding) -> str:
    """Stable rule id: ``<check>/<type>`` (e.g. ``malformed/xxe``)."""
    return f"{f.check}/{f.type}"


def _split_location(location: str | None) -> tuple[str, int | None]:
    """Return (artifact_uri, line) from a ferryman location string.

    A batch h1md/sarif run prefixes the source file as ``<file>: <locator>``;
    a single-file run emits just the locator. We treat a ``<prefix>:`` segment
    that looks like a path (contains ``.`` or ``/``) as the artifact uri, and we
    scan the whole string for a ``line N`` token to build a region.
    """
    if not location:
        return _DEFAULT_ARTIFACT, None

    line: int | None = None
    match = _LINE_RE.search(location)
    if match:
        line = int(match.group(1))

    artifact = _DEFAULT_ARTIFACT
    head, sep, _tail = location.partition(": ")
    if sep and ("." in head or "/" in head):
        artifact = head

    return artifact, line


def _result_for(f: Finding) -> dict[str, Any]:
    artifact, line = _split_location(f.location)

    physical: dict[str, Any] = {
        "artifactLocation": {"uri": artifact},
    }
    if line is not None:
        physical["region"] = {"startLine": line}

    properties: dict[str, Any] = {"severity": f.severity}
    if f.location:
        properties["location"] = f.location
    if f.metadata:
        properties.update(f.metadata)

    result: dict[str, Any] = {
        "ruleId": _rule_id(f),
        "level": _level_for(f.severity),
        "rank": _rank_for(f.severity),
        "message": {"text": f.message or _rule_id(f)},
        "locations": [{"physicalLocation": physical}],
        "properties": properties,
    }
    if f.evidence:
        # Snippet lives on the region when we have one, else on properties.
        if line is not None:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.evidence
            }
        else:
            properties["evidence"] = f.evidence
    return result


def _rules_for(findings: list[Finding]) -> list[dict[str, Any]]:
    """One SARIF reportingDescriptor per distinct rule id, sorted for stability."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(_rule_id(f), f)
    rules: list[dict[str, Any]] = []
    for rule_id in sorted(seen):
        f = seen[rule_id]
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("/", "_"),
                "shortDescription": {"text": f"{f.check} check: {f.type}"},
                "defaultConfiguration": {"level": _level_for(f.severity)},
                "properties": {"check": f.check, "type": f.type},
            }
        )
    return rules


def to_sarif(findings: Iterable[Finding]) -> str:
    """Render ferryman findings to a SARIF 2.1.0 JSON document (string)."""
    findings = list(findings)
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ferryman",
                        "version": __version__,
                        "informationUri": "https://github.com/bugsyhewitt/ferryman",
                        "rules": _rules_for(findings),
                    }
                },
                "results": [_result_for(f) for f in findings],
            }
        ],
    }
    return json.dumps(document, indent=2)
