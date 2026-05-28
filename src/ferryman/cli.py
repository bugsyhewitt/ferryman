"""ferryman command-line interface.

[Worker decision: argparse, not Click, per the v0.1 tech-stack constraint
("keep dependency surface tight"). Output is JSON by default so the tool drops
straight into HackerOne report pipelines; --format text gives a readable
triage view.]

[Worker decision (POST_V01 Rank 7): the CLI now accepts multiple FILE arguments
and a --dir flag for batch scanning. Single-file invocations keep their exact
prior output shape (no envelope) so existing pipelines and tests are unchanged;
multi-file invocations wrap per-file results in a {"files": [...]} envelope for
JSON, a per-file summary for text, and a single combined report (with file
attribution in each finding's location) for h1md.]

[Worker decision (POST_V01 Rank 8): --fail-on SEVERITY makes ferryman return a
non-zero exit code when findings at or above the given severity are present, so
security-conscious pipelines can gate on it (e.g. `ferryman --fail-on high
stmt.ofx && upload stmt.ofx`). The flag is opt-in: without it, a completed scan
still exits 0 regardless of findings, preserving every existing pipeline and
test. Output (json/text/h1md) is always emitted in full first; the exit code is
the only thing the flag changes.]

[Worker decision (POST_V01 Rank 9): --format sarif emits a SARIF 2.1.0 document
so ferryman findings drop natively into GitHub's Security tab, the VS Code
Problems panel, and SARIF-consuming SAST dashboards. Like h1md, sarif uses the
combined-with-file-attribution shape in multi-file mode (findings carry their
source file in the location/properties) since SARIF is a single-run document.
The json/text/h1md paths are untouched.]

Exit codes:
    0  scan(s) completed and no --fail-on threshold was met
    1  --fail-on was set and a finding met or exceeded that severity
    2  usage / argument error (argparse default)
    3  an input file could not be read, or --dir matched no files
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from ferryman import __version__
from ferryman.findings import SEVERITIES, Finding
from ferryman.reporting import to_h1md
from ferryman.sarif import to_sarif
from ferryman.scanner import CHECK_CHOICES, scan_file

# Glob pattern used to discover OFX files inside a --dir directory.
_DIR_GLOB = "*.ofx"


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
        "inputs",
        metavar="FILE",
        nargs="*",
        help="path(s) to the OFX file(s) to scan (shell globs expand here)",
    )
    parser.add_argument(
        "--dir",
        metavar="DIR",
        dest="directory",
        help=f"scan every {_DIR_GLOB} file in DIR (non-recursive)",
    )
    parser.add_argument(
        "--check",
        choices=CHECK_CHOICES,
        default="all",
        help="which check to run (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text", "h1md", "sarif"),
        default="json",
        dest="output_format",
        help="output format (default: json)",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        dest="fail_on",
        help=(
            "exit non-zero (1) if any finding is at or above this severity "
            "(default: always exit 0 on a completed scan)"
        ),
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


def _render_multi_text(results: list[dict]) -> str:
    """Render a compact per-file summary for batch scans."""
    lines: list[str] = []
    total = sum(r["summary"]["total"] for r in results)
    lines.append(
        f"ferryman {__version__} -- {len(results)} file(s), {total} finding(s) total"
    )
    for result in results:
        lines.append("")
        lines.append(_render_text(result))
    return "\n".join(lines)


def _attribute_findings(result: dict) -> list[Finding]:
    """Rebuild Findings from a result, prefixing the file into each location.

    For the combined h1md report we lose the per-file JSON envelope, so we fold
    the source file into every finding's location field to preserve attribution.
    """
    file = result["file"]
    attributed: list[Finding] = []
    for f in result["findings"]:
        data = dict(f)
        loc = data.get("location")
        data["location"] = f"{file}: {loc}" if loc else file
        attributed.append(Finding(**data))
    return attributed


def _collect_inputs(args: argparse.Namespace) -> tuple[list[Path], str | None]:
    """Resolve the list of files to scan from positional args and/or --dir.

    Returns (paths, error). On error, paths is empty and error is a message.
    """
    paths: list[Path] = [Path(p) for p in args.inputs]

    if args.directory is not None:
        directory = Path(args.directory)
        if not directory.is_dir():
            return [], f"ferryman: not a directory: {args.directory}"
        # Sorted for deterministic output ordering across runs.
        paths.extend(sorted(directory.glob(_DIR_GLOB)))

    if not paths:
        if args.directory is not None:
            return [], (
                f"ferryman: no {_DIR_GLOB} files found in directory: "
                f"{args.directory}"
            )
        return [], "ferryman: no input file given (provide a FILE or --dir DIR)"

    return paths, None


def _meets_threshold(results: list[dict], threshold: str) -> bool:
    """True if any finding across all results is at or above ``threshold``.

    Unknown severity strings sort below ``info`` and never trip the gate.
    """
    rank = {sev: i for i, sev in enumerate(SEVERITIES)}
    floor = rank[threshold]
    for result in results:
        for finding in result["findings"]:
            if rank.get(finding["severity"], -1) >= floor:
                return True
    return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    paths, error = _collect_inputs(args)
    if error is not None:
        print(error, file=sys.stderr)
        return 3

    multi = len(paths) > 1 or args.directory is not None

    results: list[dict] = []
    for path in paths:
        if not path.is_file():
            print(f"ferryman: cannot read file: {path}", file=sys.stderr)
            return 3
        try:
            results.append(scan_file(path, args.check))
        except OSError as exc:
            print(f"ferryman: error reading {path}: {exc}", file=sys.stderr)
            return 3

    if not multi:
        # Single-file mode: byte-identical to the pre-batch behaviour.
        _emit_single(results[0], args.output_format)
    else:
        _emit_multi(results, args.output_format)

    if args.fail_on is not None and _meets_threshold(results, args.fail_on):
        return 1
    return 0


def _emit_single(result: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, indent=2))
    elif output_format == "h1md":
        findings = [Finding(**f) for f in result["findings"]]
        print(to_h1md(findings), end="")
    elif output_format == "sarif":
        findings = [Finding(**f) for f in result["findings"]]
        print(to_sarif(findings))
    else:
        print(_render_text(result))


def _emit_multi(results: list[dict], output_format: str) -> None:
    if output_format == "json":
        total = sum(r["summary"]["total"] for r in results)
        envelope = {
            "tool": "ferryman",
            "version": __version__,
            "files": results,
            "summary": {"file_count": len(results), "total": total},
        }
        print(json.dumps(envelope, indent=2))
    elif output_format == "h1md":
        findings: list[Finding] = []
        for result in results:
            findings.extend(_attribute_findings(result))
        print(to_h1md(findings), end="")
    elif output_format == "sarif":
        findings = []
        for result in results:
            findings.extend(_attribute_findings(result))
        print(to_sarif(findings))
    else:
        print(_render_multi_text(results))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
