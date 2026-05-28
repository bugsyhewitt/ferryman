"""Tests for the SARIF 2.1.0 output format (POST_V01 Rank 9).

Covers both the pure ``to_sarif`` adapter and the CLI ``--format sarif`` wiring,
in single-file and multi-file (file-attributed) modes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ferryman import __version__
from ferryman.cli import main
from ferryman.findings import Finding
from ferryman.sarif import SARIF_VERSION, to_sarif


def run_cli(capsys, argv):
    code = main(argv)
    out = capsys.readouterr().out
    return code, out


# --- to_sarif adapter ----------------------------------------------------


def test_to_sarif_is_valid_json_with_envelope():
    doc = json.loads(to_sarif([]))
    assert doc["version"] == SARIF_VERSION
    assert "$schema" in doc and "sarif" in doc["$schema"]
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "ferryman"
    assert driver["version"] == __version__
    # No findings -> no results and no rules.
    assert doc["runs"][0]["results"] == []
    assert driver["rules"] == []


def test_to_sarif_result_count_matches_findings():
    findings = [
        Finding(check="pii", type="ssn", severity="critical", message="leak"),
        Finding(check="anomaly", type="anomalous_amount", severity="medium", message="zero"),
    ]
    doc = json.loads(to_sarif(findings))
    assert len(doc["runs"][0]["results"]) == 2


def test_to_sarif_severity_maps_to_level_and_rank():
    findings = [
        Finding(check="malformed", type="xxe", severity="critical", message="x"),
        Finding(check="malformed", type="dtd", severity="high", message="x"),
        Finding(check="anomaly", type="anomalous_amount", severity="medium", message="x"),
        Finding(check="pii", type="probable", severity="low", message="x"),
        Finding(check="pii", type="probable_routing_number", severity="info", message="x"),
    ]
    doc = json.loads(to_sarif(findings))
    results = doc["runs"][0]["results"]
    levels = [r["level"] for r in results]
    assert levels == ["error", "error", "warning", "note", "note"]
    # rank is monotonically decreasing with severity, highest first.
    ranks = [r["rank"] for r in results]
    assert ranks == sorted(ranks, reverse=True)
    # ferryman's exact severity is preserved in properties.
    assert [r["properties"]["severity"] for r in results] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_to_sarif_rule_per_distinct_rule_id():
    findings = [
        Finding(check="pii", type="ssn", severity="critical", message="a"),
        Finding(check="pii", type="ssn", severity="critical", message="b"),
        Finding(check="anomaly", type="anomalous_amount", severity="medium", message="c"),
    ]
    doc = json.loads(to_sarif(findings))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    # Two distinct rule ids even though there are three findings.
    assert rule_ids == {"pii/ssn", "anomaly/anomalous_amount"}
    # Every result's ruleId is declared in the rules table.
    declared = {r["id"] for r in rules}
    for result in doc["runs"][0]["results"]:
        assert result["ruleId"] in declared


def test_to_sarif_parses_line_into_region():
    f = Finding(
        check="malformed",
        type="xxe",
        severity="critical",
        message="x",
        location="line 4",
        evidence="<!ENTITY xxe SYSTEM",
    )
    doc = json.loads(to_sarif([f]))
    phys = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert phys["region"]["startLine"] == 4
    # Evidence rides along as the region snippet when we have a region.
    assert phys["region"]["snippet"]["text"] == "<!ENTITY xxe SYSTEM"


def test_to_sarif_no_line_uses_default_artifact_and_keeps_locator():
    f = Finding(
        check="pii",
        type="ssn",
        severity="critical",
        message="x",
        location="statement[0].transaction[0].name (fitid 0001)",
    )
    doc = json.loads(to_sarif([f]))
    result = doc["runs"][0]["results"][0]
    phys = result["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "input.ofx"
    assert "region" not in phys
    # The free-form locator is preserved in properties so nothing is lost.
    assert result["properties"]["location"] == f.location


def test_to_sarif_file_attributed_location_becomes_artifact_uri():
    # Multi-file mode folds the file into the location as "<file>: <loc>".
    f = Finding(
        check="pii",
        type="ssn",
        severity="critical",
        message="x",
        location="statements/acct.ofx: statement[0].transaction[0].name",
    )
    doc = json.loads(to_sarif([f]))
    phys = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "statements/acct.ofx"


# --- CLI --format sarif --------------------------------------------------


def test_help_lists_sarif_format(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "sarif" in out


def test_cli_sarif_single_file(capsys, xxe_file):
    code, out = run_cli(
        capsys, ["--check", "malformed", "--format", "sarif", str(xxe_file)]
    )
    assert code == 0
    doc = json.loads(out)
    assert doc["version"] == SARIF_VERSION
    results = doc["runs"][0]["results"]
    assert any(r["ruleId"] == "malformed/xxe" for r in results)


def test_cli_sarif_result_count_matches_json(capsys, pii_file):
    # The SARIF result count must match the canonical json finding count.
    _, json_out = run_cli(
        capsys, ["--check", "all", "--format", "json", str(pii_file)]
    )
    json_total = json.loads(json_out)["summary"]["total"]
    _, sarif_out = run_cli(
        capsys, ["--check", "all", "--format", "sarif", str(pii_file)]
    )
    sarif_results = json.loads(sarif_out)["runs"][0]["results"]
    assert len(sarif_results) == json_total


def test_cli_sarif_multi_file_attributes_artifact(capsys, xxe_file, pii_file):
    code, out = run_cli(
        capsys,
        ["--check", "all", "--format", "sarif", str(xxe_file), str(pii_file)],
    )
    assert code == 0
    doc = json.loads(out)
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in doc["runs"][0]["results"]
    }
    # Both source files appear as SARIF artifact URIs.
    assert str(xxe_file) in uris
    assert str(pii_file) in uris


def test_cli_sarif_clean_file_has_empty_results(capsys, clean_file):
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "sarif", str(clean_file)]
    )
    assert code == 0
    doc = json.loads(out)
    assert doc["runs"][0]["results"] == []


def test_cli_sarif_respects_fail_on(capsys, xxe_file):
    # Output format is independent of the --fail-on exit-code gate.
    code, out = run_cli(
        capsys,
        ["--check", "all", "--format", "sarif", "--fail-on", "high", str(xxe_file)],
    )
    assert code == 1
    json.loads(out)  # still valid SARIF
