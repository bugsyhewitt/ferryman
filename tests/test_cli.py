"""Tests for the ferryman CLI surface (argparse, exit codes, JSON shape)."""

from __future__ import annotations

import json

import pytest

from ferryman.cli import main


def run_cli(capsys, argv):
    """Invoke ferryman's main() with argv, returning (exit_code, stdout)."""
    code = main(argv)
    out = capsys.readouterr().out
    return code, out


def test_help_lists_required_options(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--format" in out
    assert "--check" in out
    assert "json" in out and "text" in out
    assert "malformed" in out and "pii" in out and "anomaly" in out and "all" in out


def test_malformed_json_xxe(capsys, xxe_file):
    code, out = run_cli(
        capsys, ["--check", "malformed", "--format", "json", str(xxe_file)]
    )
    assert code == 0
    data = json.loads(out)
    findings = data["findings"]
    assert any(
        f["check"] == "malformed" and f["type"] == "xxe" for f in findings
    ), f"expected malformed/xxe finding, got: {findings}"


def test_pii_json(capsys, pii_file):
    code, out = run_cli(capsys, ["--check", "pii", "--format", "json", str(pii_file)])
    assert code == 0
    data = json.loads(out)
    findings = data["findings"]
    assert any(f["check"] == "pii" for f in findings)
    assert all(f["check"] == "pii" for f in findings)


def test_all_check_runs_every_check(capsys, pii_file):
    code, out = run_cli(capsys, ["--check", "all", "--format", "json", str(pii_file)])
    assert code == 0
    data = json.loads(out)
    assert data["check"] == "all"


def test_text_format_renders_lines(capsys, xxe_file):
    code, out = run_cli(
        capsys, ["--check", "malformed", "--format", "text", str(xxe_file)]
    )
    assert code == 0
    assert "malformed/xxe" in out


def test_missing_file_errors(capsys):
    code, _ = run_cli(capsys, ["--check", "all", "does-not-exist.ofx"])
    assert code != 0


def test_default_format_is_json(capsys, xxe_file):
    code, out = run_cli(capsys, ["--check", "malformed", str(xxe_file)])
    assert code == 0
    # Should parse as JSON by default.
    json.loads(out)
