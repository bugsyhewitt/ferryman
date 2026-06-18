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
DIST = REPO_ROOT / "dist"


def _run(cmd, **kw):
    result = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd,
            output=result.stdout, stderr=result.stderr
        )
    return result


# Module-level stash for wheel path and venv dir so tests can share them
# without filesystem side-channels that pytest tmp_path doesn't permit.
_STATE: dict = {}


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    """Build the wheel + sdist once for the whole module."""
    out = tmp_path_factory.mktemp("build-out")
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO_ROOT,
    )
    wheels = list(out.glob("ferryman-0.1.0-*.whl"))
    sdists = list(out.glob("ferryman-0.1.0.tar.gz"))
    assert wheels, f"wheel not built; got: {list(out.iterdir())}"
    assert sdists, f"sdist not built; got: {list(out.iterdir())}"
    return wheels[0]


@pytest.fixture(scope="module")
def fresh_venv_dir(tmp_path_factory, built_wheel):
    """Spin up a fresh venv, install the wheel, and return the venv directory."""
    venv_dir = tmp_path_factory.mktemp("fresh-venv")
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    # Install the wheel itself
    _run([str(pip), "install", "--quiet", str(built_wheel)])
    # Install runtime dependencies declared in pyproject.toml
    _run([str(pip), "install", "--quiet",
          "ofxtools>=0.9.5",
          "h1-reporter @ git+https://github.com/bugsyhewitt/h1-reporter"])
    return venv_dir


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(built_wheel):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    assert built_wheel.exists(), f"wheel path does not exist: {built_wheel}"
    assert built_wheel.suffix == ".whl"


@pytest.mark.ship_gate
def test_wheel_installs_version_entry_point(fresh_venv_dir):
    """`ferryman --version` from the fresh venv prints `ferryman 0.1.0`."""
    ferryman_bin = fresh_venv_dir / "bin" / "ferryman"
    result = _run([str(ferryman_bin), "--version"])
    assert result.stdout.strip() == "ferryman 0.1.0", (
        f"unexpected version output: {result.stdout.strip()!r}"
    )


@pytest.mark.ship_gate
def test_wheel_python_import(fresh_venv_dir):
    """`python -c "import ferryman; assert ferryman.__version__ == '0.1.0'"` succeeds."""
    py = fresh_venv_dir / "bin" / "python"
    _run([str(py), "-c",
          "import ferryman; assert ferryman.__version__ == '0.1.0', ferryman.__version__"])


@pytest.mark.ship_gate
def test_wheel_public_surface(fresh_venv_dir):
    """The installed wheel exposes all required public modules and symbols."""
    py = fresh_venv_dir / "bin" / "python"
    _run([str(py), "-c", (
        "import ferryman.cli; "
        "import ferryman.scanner; "
        "import ferryman.findings; "
        "import ferryman.checks.malformed; "
        "import ferryman.checks.pii; "
        "import ferryman.checks.anomaly; "
        "from ferryman.findings import Finding; "
        "from ferryman.scanner import scan_file; "
        "from ferryman.cli import main"
    )])


@pytest.mark.ship_gate
def test_installed_wheel_runs_end_to_end(fresh_venv_dir):
    """The installed wheel flags the shipped XXE fixture from a fresh venv."""
    ferryman_bin = fresh_venv_dir / "bin" / "ferryman"
    xxe = REPO_ROOT / "tests" / "fixtures" / "xxe-attempt.ofx"
    result = _run([str(ferryman_bin), "--check", "malformed", "--format", "json", str(xxe)])
    findings_data = json.loads(result.stdout)
    findings = findings_data.get("findings", [])
    types = {f["type"] for f in findings}
    xxe_severities = {f["severity"] for f in findings if f["type"] == "xxe"}
    assert "xxe" in types, f"installed wheel did not detect XXE; findings: {findings}"
    assert xxe_severities <= {"high", "critical"} and xxe_severities, (
        f"unexpected severity set for xxe: {xxe_severities}"
    )
