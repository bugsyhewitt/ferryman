# Changelog

All notable changes to ferryman are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added
- **Wheel ship-gate contract** (`tests/test_wheel_ship_gate.py`): 5 ship-gate tests that
  pin the install contract — `python -m build` produces a wheel + sdist, `pip install`
  into a fresh venv resolves the `ferryman` entry point, `ferryman --version` reports
  the installed version, `import ferryman; ferryman.__version__` is importable, the
  full public API surface (`ferryman.cli`, `ferryman.scanner`, `ferryman.findings`,
  `ferryman.checks.malformed`, `ferryman.checks.pii`, `ferryman.checks.anomaly`)
  is exposed, and the installed wheel runs end-to-end on the shipped XXE fixture.
- **ABA Routing Number checksum validation** (PR #29-shipped PII improvement): the
  `routing_number` finding is now gated behind the ABA 3-7-1 weighted checksum. Nine-digit
  runs that fail the checksum are downgraded to `probable_routing_number` at `info` severity.
- **National-ID PII detectors** (PRs #30–#37, in shipped order):
  - Turkish TCKN (PR #30)
  - Norwegian fødselsnummer (PR #31)
  - Finnish HETU / henkilötunnus (PR #32)
  - Swedish personnummer (PR #33)
  - Swiss AHV / AVS social-security number (PR #34)
  - Danish CPR (PR #35)
  - Dutch BSN / Burgerservicenummer (PR #36)
  - German Steueridentifikationsnummer / IdNr (PR #37)

### Changed
- Version bumped from `0.1.0` to `1.0.0`. The package is production-ready: every shipped
  PII detector has regression tests, the install contract is pinned by the ship-gate
  suite, and the CLI + public API surface is stable.
- `README.md` JSON-output examples updated to report `"version": "1.0.0"`.

### Fixed
- N/A (this is the first 1.x release; the 0.1.0 baseline was feature-stable).

### Security
- All 932 tests (927 base + 5 ship-gate) pass at HEAD `59c5e43`. The ship-gate suite
  builds the wheel from the on-disk source tree, installs it into a fresh venv, and
  exercises the CLI + full public API — so any regression in packaging, entry-point
  resolution, import, or end-to-end behavior is caught at release time.

[1.0.0]: https://github.com/bugsyhewitt/ferryman/releases/tag/v1.0.0
