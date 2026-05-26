"""ferryman -- a security-focused scanner for OFX financial transaction files.

ferryman carries OFX files across to the other side: it inspects them for
parser-confusion attacks, PII exposure, and anomalous transactions, and emits
structured findings suitable for HackerOne report generation.
"""

from __future__ import annotations

__version__ = "0.1.0"

from ferryman.findings import Finding

__all__ = ["Finding", "__version__"]
