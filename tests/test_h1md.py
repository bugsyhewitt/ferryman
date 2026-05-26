"""Tests for the h1md output format, built on the shared h1-reporter library.

ferryman gained h1md output in the h1-reporter refactor. These tests pin the
contract that the report routes through the shared renderer and carries the
finding detail. The json and text paths are covered (unchanged) in test_cli.py.
"""

from __future__ import annotations

from ferryman.cli import main
from ferryman.findings import Finding
from ferryman.reporting import to_h1md


def run_cli(capsys, argv):
    code = main(argv)
    out = capsys.readouterr().out
    return code, out


def test_h1md_format_renders_markdown(capsys, pii_file):
    code, out = run_cli(capsys, ["--check", "pii", "--format", "h1md", str(pii_file)])
    assert code == 0
    assert out.startswith("# ferryman OFX findings")
    assert "**Total findings:**" in out
    assert "**Severity:**" in out
    assert "pii/" in out


def test_h1md_clean_file_reports_zero(capsys, clean_file):
    code, out = run_cli(capsys, ["--check", "all", "--format", "h1md", str(clean_file)])
    assert code == 0
    assert "**Total findings:** 0" in out
    assert "_No findings._" in out


def test_to_h1md_maps_finding_fields():
    findings = [
        Finding(
            check="malformed",
            type="xxe",
            severity="high",
            message="external entity declaration found",
            location="line 3",
            evidence="<!ENTITY xxe SYSTEM ...>",
        )
    ]
    md = to_h1md(findings)
    assert "## Finding 1: malformed/xxe" in md
    assert "**Severity:** HIGH" in md
    assert "external entity declaration found" in md
    assert "<!ENTITY xxe SYSTEM ...>" in md
    # business-impact framing for the malformed check is present
    assert "parser confusion" in md


def test_to_h1md_ends_with_single_newline():
    findings = [Finding(check="pii", type="ssn", severity="critical", message="x")]
    md = to_h1md(findings)
    assert md.endswith("\n")
    assert not md.endswith("\n\n")
