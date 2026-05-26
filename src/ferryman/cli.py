"""ferryman command-line interface.

[Worker decision: argparse, not Click, per the v0.1 tech-stack constraint
("keep dependency surface tight"). Output is JSON by default so the tool drops
straight into HackerOne report pipelines; --format text gives a readable
triage view.]

Exit codes:
    0  scan completed (whether or not findings were emitted)
    2  usage / argument error (argparse default)
    3  the input file could not be read
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from ferryman import __version__
from ferryman.findings import SEVERITIES
from ferryman.scanner import CHECK_CHOICES, scan_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ferryman",
        description=(
            "Security-focused scanner for OFX (Open Financial Exchange) files. "
            "Detects parser-confusion attacks, PII exposure, and anomalous "
            "transactions, emitting structured findings for HackerOne reports."
        ),
    )
    parser.add_argument(
        "input",
        metavar="FILE",
        help="path to the OFX file to scan",
    )
    parser.add_argument(
        "--check",
        choices=CHECK_CHOICES,
        default="all",
        help="which check to run (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        dest="output_format",
        help="output format (default: json)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ferryman {__version__}",
    )
    return parser


def _render_text(result: dict) -> str:
    lines: list[str] = []
    lines.append(f"ferryman {result['version']} -- {result['file']}")
    lines.append(f"check: {result['check']}")
    summary = result["summary"]
    lines.append(f"findings: {summary['total']}")
    if summary["total"]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        findings = sorted(
            result["findings"],
            key=lambda f: order.get(f["severity"], -1),
            reverse=True,
        )
        for f in findings:
            sev = f["severity"].upper()
            loc = f" @ {f['location']}" if f.get("location") else ""
            lines.append(f"  [{sev}] {f['check']}/{f['type']}{loc}: {f['message']}")
    else:
        lines.append("  (no findings)")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    path = Path(args.input)
    if not path.is_file():
        print(f"ferryman: cannot read file: {args.input}", file=sys.stderr)
        return 3

    try:
        result = scan_file(path, args.check)
    except OSError as exc:
        print(f"ferryman: error reading {args.input}: {exc}", file=sys.stderr)
        return 3

    if args.output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(_render_text(result))

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
