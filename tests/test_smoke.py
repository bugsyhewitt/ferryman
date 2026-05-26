"""End-to-end smoke test required by the v0.1 criteria.

Runs the full scan pipeline through the CLI on the shipped fixtures and
asserts the headline behaviours hold together end to end.
"""

from __future__ import annotations

import json

from ferryman.cli import main


def test_smoke_end_to_end(capsys, xxe_file, pii_file, clean_file):
    # 1. XXE attempt is caught by the malformed check.
    assert main(["--check", "malformed", "--format", "json", str(xxe_file)]) == 0
    xxe = json.loads(capsys.readouterr().out)
    assert any(
        f["check"] == "malformed" and f["type"] == "xxe" for f in xxe["findings"]
    )

    # 2. PII leak is caught by the pii check.
    assert main(["--check", "pii", "--format", "json", str(pii_file)]) == 0
    pii = json.loads(capsys.readouterr().out)
    assert any(f["check"] == "pii" for f in pii["findings"])

    # 3. A clean file under --check all yields zero findings.
    assert main(["--check", "all", "--format", "json", str(clean_file)]) == 0
    clean = json.loads(capsys.readouterr().out)
    assert clean["findings"] == []
    assert clean["summary"]["total"] == 0
