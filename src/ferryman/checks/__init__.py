"""ferryman security checks.

Each check is a pure function ``check_<name>(raw: bytes) -> list[Finding]``.
Checks take raw file bytes so the malformed check can operate strictly
pre-parse (never feed a hostile file to a real parser), while the pii and
anomaly checks parse internally with ofxtools.
"""

from __future__ import annotations

from ferryman.checks.anomaly import check_anomaly
from ferryman.checks.malformed import check_malformed
from ferryman.checks.pii import check_pii

__all__ = ["check_anomaly", "check_malformed", "check_pii"]
