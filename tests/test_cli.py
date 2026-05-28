"""Tests for the ferryman CLI surface (argparse, exit codes, JSON shape)."""

from __future__ import annotations

import json
from pathlib import Path

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


def test_help_lists_dir_flag(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "--dir" in out
    # The FILE metavar should now accept multiple paths.
    assert "FILE" in out


# --- Multi-file (POST_V01 Rank 7) ----------------------------------------


def test_no_input_errors(capsys):
    code, _ = run_cli(capsys, ["--check", "all"])
    assert code == 3


def test_multi_file_json_envelope(capsys, xxe_file, pii_file):
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "json", str(xxe_file), str(pii_file)]
    )
    assert code == 0
    data = json.loads(out)
    # Multi-file mode wraps results in a {"files": [...]} envelope.
    assert "files" in data
    assert "findings" not in data  # not the single-file shape
    assert data["summary"]["file_count"] == 2
    assert len(data["files"]) == 2
    files = {entry["file"] for entry in data["files"]}
    assert str(xxe_file) in files and str(pii_file) in files
    # Envelope total equals the sum of per-file totals.
    per_file = sum(e["summary"]["total"] for e in data["files"])
    assert data["summary"]["total"] == per_file
    # Each per-file entry keeps the canonical single-file shape.
    for entry in data["files"]:
        assert entry["tool"] == "ferryman"
        assert "findings" in entry and "summary" in entry


def test_multi_file_text_per_file_summary(capsys, xxe_file, pii_file):
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "text", str(xxe_file), str(pii_file)]
    )
    assert code == 0
    assert "2 file(s)" in out
    assert str(xxe_file) in out and str(pii_file) in out
    assert "malformed/xxe" in out


def test_multi_file_h1md_attributes_file(capsys, xxe_file, pii_file):
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "h1md", str(xxe_file), str(pii_file)]
    )
    assert code == 0
    assert out.startswith("# ferryman OFX findings")
    # File attribution is folded into the location field of each finding.
    assert str(xxe_file) in out
    assert str(pii_file) in out


def test_dir_mode_scans_all_ofx(capsys, tmp_path, xxe_file, pii_file):
    # Copy two real fixtures plus a non-OFX file into a scratch directory.
    (tmp_path / "a.ofx").write_bytes(xxe_file.read_bytes())
    (tmp_path / "b.ofx").write_bytes(pii_file.read_bytes())
    (tmp_path / "ignore.txt").write_text("not ofx")
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "json", "--dir", str(tmp_path)]
    )
    assert code == 0
    data = json.loads(out)
    # Only the two .ofx files are scanned; the .txt is ignored.
    assert data["summary"]["file_count"] == 2
    scanned = {Path(e["file"]).name for e in data["files"]}
    assert scanned == {"a.ofx", "b.ofx"}


def test_dir_mode_is_always_envelope_even_for_one_file(capsys, tmp_path, xxe_file):
    # A directory with a single match still uses the multi-file envelope,
    # so scripts that pass --dir get a stable shape regardless of count.
    (tmp_path / "only.ofx").write_bytes(xxe_file.read_bytes())
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "json", "--dir", str(tmp_path)]
    )
    assert code == 0
    data = json.loads(out)
    assert "files" in data
    assert data["summary"]["file_count"] == 1


def test_dir_not_a_directory_errors(capsys, xxe_file):
    code, _ = run_cli(capsys, ["--check", "all", "--dir", str(xxe_file)])
    assert code == 3


def test_empty_dir_errors(capsys, tmp_path):
    code, _ = run_cli(capsys, ["--check", "all", "--dir", str(tmp_path)])
    assert code == 3


def test_multi_file_missing_one_errors(capsys, xxe_file):
    code, _ = run_cli(
        capsys, ["--check", "all", str(xxe_file), "does-not-exist.ofx"]
    )
    assert code == 3


def test_dir_plus_positional_combine(capsys, tmp_path, xxe_file, pii_file):
    (tmp_path / "in_dir.ofx").write_bytes(pii_file.read_bytes())
    code, out = run_cli(
        capsys,
        ["--check", "all", "--format", "json", str(xxe_file), "--dir", str(tmp_path)],
    )
    assert code == 0
    data = json.loads(out)
    # Positional FILE plus --dir matches are merged.
    assert data["summary"]["file_count"] == 2
    names = {Path(e["file"]).name for e in data["files"]}
    assert "in_dir.ofx" in names


# --- Exit-code gating: --fail-on (POST_V01 Rank 8) -----------------------


def test_help_lists_fail_on_flag(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "--fail-on" in out


def test_no_fail_on_always_exits_zero_even_with_findings(capsys, xxe_file):
    # Without --fail-on, a completed scan exits 0 regardless of findings,
    # preserving the pre-Rank-8 contract.
    code, out = run_cli(capsys, ["--check", "all", "--format", "json", str(xxe_file)])
    assert code == 0
    data = json.loads(out)
    assert data["summary"]["total"] > 0  # the file genuinely has findings


def test_fail_on_returns_one_when_threshold_met(capsys, xxe_file):
    # The xxe fixture emits a high/critical malformed finding, so a high
    # threshold must trip the gate -> exit 1.
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "json", "--fail-on", "high", str(xxe_file)]
    )
    assert code == 1
    # Output is still emitted in full -- only the exit code changed.
    data = json.loads(out)
    assert data["summary"]["total"] > 0


def test_fail_on_critical_not_met_on_lower_findings(capsys, anomaly_file):
    # Pick a threshold above every finding's severity in the file: gate must
    # not trip, so we still exit 0.
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "json", str(anomaly_file)]
    )
    assert code == 0
    findings = json.loads(out)["findings"]
    order = {s: i for i, s in enumerate(["info", "low", "medium", "high", "critical"])}
    top = max((order[f["severity"]] for f in findings), default=-1)
    # Choose a threshold strictly above the file's highest finding severity.
    higher = ["info", "low", "medium", "high", "critical"][min(top + 1, 4)]
    if top == 4:
        pytest.skip("fixture already carries a critical finding")
    code, _ = run_cli(
        capsys, ["--check", "all", "--fail-on", higher, str(anomaly_file)]
    )
    assert code == 0


def test_fail_on_info_trips_on_any_finding(capsys, pii_file):
    # info is the lowest severity, so --fail-on info trips whenever there is
    # at least one finding of any kind.
    code, _ = run_cli(
        capsys, ["--check", "all", "--fail-on", "info", str(pii_file)]
    )
    assert code == 1


def test_fail_on_clean_file_exits_zero(capsys, clean_file):
    # A clean file produces no findings, so even --fail-on info exits 0.
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "json", "--fail-on", "info", str(clean_file)]
    )
    assert code == 0
    assert json.loads(out)["summary"]["total"] == 0


def test_fail_on_works_in_multi_file_mode(capsys, clean_file, xxe_file):
    # A clean file and a malicious file together: the gate trips on the
    # malicious one even though the clean one contributes nothing.
    code, out = run_cli(
        capsys,
        ["--check", "all", "--format", "json", "--fail-on", "high", str(clean_file), str(xxe_file)],
    )
    assert code == 1
    data = json.loads(out)
    assert "files" in data  # full multi-file envelope still emitted


def test_fail_on_text_format_still_gates(capsys, xxe_file):
    # Exit-code gating is independent of output format.
    code, out = run_cli(
        capsys, ["--check", "all", "--format", "text", "--fail-on", "high", str(xxe_file)]
    )
    assert code == 1
    assert "malformed/xxe" in out
