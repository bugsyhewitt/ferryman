"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_XXE = REPO_ROOT / "tests" / "fixtures" / "xxe-attempt.ofx"


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO_ROOT,
    )
    wheels = list(out.glob("ferryman-1.0.0-*.whl"))
    sdists = list(out.glob("ferryman-1.0.0.tar.gz"))
    assert wheels, f"wheel not built; got: {list(out.iterdir())}"
    assert sdists, f"sdist not built; got: {list(out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point."""
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding build test did not produce a wheel")

    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"

    # Install wheel; pip resolves all declared runtime deps (ofxtools, h1-reporter).
    _run([str(pip), "install", "--quiet", str(wheel)])

    cli = venv_dir / "bin" / "ferryman"
    version_out = _run([str(cli), "--version"]).stdout.strip()
    assert version_out == "ferryman 1.0.0", f"unexpected --version output: {version_out!r}"

    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv(tmp_path):
    """`import ferryman; ferryman.__version__` == '1.0.0' inside the fresh venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    _run(
        [str(py), "-c", "import ferryman; assert ferryman.__version__ == '1.0.0'"],
    )


@pytest.mark.ship_gate
def test_installed_wheel_public_api(tmp_path):
    """The installed wheel exposes the full public API surface."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    check_script = (
        "import ferryman.cli, ferryman.scanner, ferryman.findings, "
        "ferryman.checks.malformed, ferryman.checks.pii, ferryman.checks.anomaly"
    )
    _run([str(py), "-c", check_script])


@pytest.mark.ship_gate
def test_installed_wheel_runs_end_to_end(tmp_path):
    """The installed wheel flags the shipped XXE fixture with type=xxe, severity critical/high."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    cli = venv_dir / "bin" / "ferryman"
    raw = _run(
        [str(cli), "--check", "malformed", "--format", "json", str(FIXTURE_XXE)]
    ).stdout
    result = json.loads(raw)
    findings = result.get("findings", [])
    types = {f["type"] for f in findings}
    xxe_severities = {f["severity"] for f in findings if f["type"] == "xxe"}

    assert "xxe" in types, f"installed wheel did not detect XXE; got findings: {findings}"
    assert xxe_severities <= {"high", "critical"}, (
        f"unexpected severity for xxe findings: {xxe_severities}"
    )
    assert xxe_severities, f"no xxe findings with severity; findings: {findings}"


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """CHANGELOG.md exists at repo root and contains a ## [1.0.0] - 2026-06-20 entry."""
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.is_file(), f"CHANGELOG.md not found at {changelog}"
    text = changelog.read_text(encoding="utf-8")
    assert "## [1.0.0] - 2026-06-20" in text, (
        f"CHANGELOG.md missing v1.0.0 entry; first 20 lines:\n"
        + "\n".join(text.splitlines()[:20])
    )
