# ferryman — Post-v0.1 Improvement Backlog

**Research lap date:** 2026-05-26  
**Basis:** codebase review + OFX/fintech security landscape research (2024–2026)

Items are ranked by: security impact for bug-bounty reporters × detection gap × implementation effort.

---

## Rank 1 — ABA Routing Number Checksum Validation (HIGH signal, low effort)

**What:** The current `pii` check flags any 9-digit run as a routing number. ABA routing numbers
have a public weighted checksum (3-7-1 weighting). Validating the checksum before emitting a
finding would eliminate the false-positive flood from things like zip+4 codes, EIN-like numbers,
and telephone numbers embedded in memos. A genuine ABA number that passes checksum is a
near-certain leak; one that fails is likely coincidental.

**Why now:** Bug-bounty reporters using ferryman as a triage tool will quickly lose confidence if
every memo with a 9-digit order number produces a `routing_number` finding. Precision is a force
multiplier for their workflow.

**Research grounding:** ABA checksum is `(3d1 + 7d2 + d3 + 3d4 + 7d5 + d6 + 3d7 + 7d8 + d9)
mod 10 == 0`. It is public domain, zero dependencies, ~10 lines of Python. No library needed.

**Implementation sketch:**
- Add `_aba_checksum_valid(digits: str) -> bool` to `checks/pii.py`.
- Gate `routing_number` findings behind this check.
- Failing checksum: emit an `info`-severity `probable_routing_number` finding instead (to preserve
  visibility without crying wolf at critical/high).
- Add unit tests: valid ABA numbers, invalid ones, 9-digit non-ABA collisions.

**Estimated tokens:** 30–50K

---

## Rank 2 — Entity-Expansion (Billion Laughs) Detection in the Malformed Check (CRITICAL signal, medium effort)

**What:** The current `malformed` check detects external-entity XXE (`SYSTEM` keyword) and
DOCTYPE presence but does NOT detect recursive/nested entity expansion — the "Billion Laughs"
DoS vector. A file with deeply nested `<!ENTITY a "...">` chains referencing each other causes
memory exhaustion when parsed. Since OFX v2 is XML, this is a first-class attack on any fintech
import endpoint.

**Why now:** XXE-for-file-read gets the headlines but entity-expansion DoS is separately
reportable (and separately patchable). A bug-bounty report that distinguishes "file read via XXE"
from "DoS via entity expansion" is more actionable for the target's triage team and earns a
separate finding credit.

**Research grounding:** CVE-2026-34601 (CDATA injection in xmldom), billion-laughs DoS is
documented as a distinct vector in OWASP and CWE-400. Python's `xml.etree.ElementTree` is
theoretically vulnerable when DTD processing is enabled.

**Implementation sketch:**
- In `checks/malformed.py`, add `_count_entities(raw: bytes) -> int` — count `<!ENTITY`
  declarations without parsing (pure regex over bytes).
- If count >= 3 AND any entity name appears inside another entity body (nested reference pattern),
  emit `type="entity_expansion"`, severity `critical`.
- Threshold: ≥3 entity declarations with cross-reference. Practical threshold — legitimate OFX
  has zero custom entities; any nested chain is hostile.
- Fixture: add `tests/fixtures/entity-bomb.ofx` with a 3-level entity chain.
- Add unit tests.

**Estimated tokens:** 40–60K

---

## Rank 3 — CDATA Injection Detection (HIGH signal, low effort)

**What:** OFX v2 (XML format) supports CDATA sections. An attacker can embed `]]>` inside a
CDATA block to prematurely terminate it and inject raw XML markup into the parsed output. This
was exploited in CVE-2026-34601 (xmldom). In a fintech OFX import, injected markup could
manipulate downstream business logic (e.g., inject `<approved>true</approved>` or
`<TRNAMT>-99999</TRNAMT>`).

**Why now:** CVE-2026-34601 dropped in 2026 and affects the XML serialization path that many
OFX v2 processors use. It is fresh surface area.

**Implementation sketch:**
- In `checks/malformed.py`, add CDATA terminator regex: `rb"\]\]>"`.
- If found inside a CDATA section (`<!\[CDATA\[` ... `]]>`), flag `type="cdata_injection"`,
  severity `high`.
- Evidence: truncated snippet around the `]]>` occurrence.
- Add fixture + tests.

**Estimated tokens:** 25–35K

---

## Rank 4 — Investment Account (INVSTMTRS) Statement Support in PII + Anomaly Checks (coverage gap, medium effort)

**What:** `parsing.py` only iterates `ofx.statements`, which covers bank and credit-card
statement types. OFX investment accounts use `INVSTMTRS` responses, which `ofxtools` exposes
under a different attribute path. Investment statements contain ticker symbols, security names,
cost basis, quantity — all potential PII/anomaly surface. Brokerage accounts are exactly the high-
value targets fintech bug-bounty programs run.

**Why now:** v0.1 explicitly deferred investment accounts. Phase 2 is the time to extend. The
`ofxtools` library already parses `INVSTMTRS`; ferryman just does not iterate it.

**Implementation sketch:**
- Extend `parse_statements` in `parsing.py` to also yield investment statements from
  `ofx.statements` (ofxtools includes `InvStatement` in the same list but with different
  attributes: `invtranlist` instead of `transactions`, `invacctfrom` instead of `account`).
- Add a `Transaction`-compatible flattening path for investment transactions
  (`BUYMF`, `SELLMF`, `REINVEST`, `INCOME` types).
- Extend anomaly check: flag investment transactions with implausible unit prices (< 0 or
  abnormally large), quantities < 0 without a `SELL`/`SELLMF` type.
- Extend PII check: scan security names and broker IDs for SSN-shaped and account-shaped leaks.
- Add `tests/fixtures/investment.ofx` and `tests/fixtures/investment-pii.ofx`.
- Update README scope section.

**Estimated tokens:** 80–120K

---

## Rank 5 — OFX v1 SGML Header Injection Detection (medium signal, low effort)

**What:** OFX v1 uses a plaintext header block (OFXHEADER, DATA, VERSION, ENCODING, CHARSET...)
before the SGML body, separated by a blank line. A crafted file can smuggle a second header block
inside the SGML body, or inject unexpected values into ENCODING/CHARSET that trigger parser
confusion — e.g., declaring `ENCODING:UTF-8` while the body is Windows-1252 with non-ASCII
characters. Some parsers normalize silently; others crash.

**Why now:** The SGML/XML confusion check already exists and this is a natural extension. Header
injection has no existing detection in ferryman.

**Implementation sketch:**
- Parse the raw v1 header block (lines before the first blank line).
- Detect: (a) more than one header block (second `OFXHEADER:` occurrence after the separator),
  (b) ENCODING value not in the OFX-allowed set (`USASCII`, `UTF-8`, `1252` variants),
  (c) non-printable bytes in the header section (before the blank line).
- Emit `type="header_injection"`, severity `high` for (a); `type="encoding_mismatch"`,
  severity `medium` for (b) and (c).
- Add unit tests with inline byte payloads (no new fixture file needed).

**Estimated tokens:** 35–50K

---

## Rank 6 — Negative/Zero Transaction Amount Anomaly (medium signal, low effort)

**What:** OFX transaction amounts are decimal strings in `<TRNAMT>`. A crafted file can contain
`-0.00`, `NaN`, `Inf`, or extremely large/small values (e.g., `99999999999.99`). These may
bypass downstream financial validation and cause unexpected behavior. Negative amounts for
`DEBIT`-type transactions or zero amounts for any transaction type are also reportable anomalies.

**Why now:** Builds directly on the existing anomaly check with minimal new code. Transaction
amount anomalies are a well-known fintech injection class (business-logic attacks, negative
balance exploits).

**Implementation sketch:**
- In `checks/anomaly.py`, add amount anomaly detection in the existing transaction loop.
- Parse `tx.amount` (currently stored but not inspected) with `Decimal`.
- Flag: zero-amount transactions, negative amounts on credit/debit-type transactions where
  sign contradicts type, values exceeding a ceiling (e.g., $10M per transaction is outside
  all legitimate retail banking ranges).
- Emit `type="anomalous_amount"`, severity `medium` (or `high` for zero on a non-reversal type).
- Add unit tests.

**Estimated tokens:** 30–45K

---

## Rank 7 — Scan Multiple Files (Glob / Directory Input) via CLI (usability, medium effort)

**What:** The CLI accepts exactly one file. Bug-bounty researchers typically receive a dump of
many OFX files from a target and want to batch-scan. Adding `ferryman --check all *.ofx` or
`ferryman --check all --dir ./statements/` would substantially improve workflow.

**Why now:** Pure usability — no new detection logic. Easy to add without touching the check
layer. Useful when demonstrating a widespread PII leak across many exported files.

**Implementation sketch:**
- Update `cli.py`: accept multiple positional `FILE` arguments OR a `--dir` flag.
- For multi-file mode, wrap `scan_file` calls and aggregate findings with a per-file envelope in
  the JSON output: `{"files": [{"file": "...", "findings": [...]}, ...]}`.
- `--format text` prints a compact per-file summary.
- `--format h1md` renders all findings in a single report with file attribution in each finding's
  location field.
- Add CLI tests for multi-file invocation.

**Estimated tokens:** 50–70K

---

## Rank 8 — Exit Code Non-Zero on Findings Found (usability + CI integration, trivial effort)

**What:** Currently ferryman always exits `0` if the scan completed (regardless of findings).
This means `ferryman --check all statement.ofx && upload statement.ofx` will always upload, even
if ferryman found critical XXE. Security-conscious pipelines expect non-zero exits on findings.

**Why now:** One-line change in `cli.py`. High leverage for CI/CD integration and scripting.

**Implementation sketch:**
- Add `--fail-on SEVERITY` flag (e.g., `--fail-on high`). If any finding meets or exceeds that
  severity, exit with code `1`.
- Default remains `0` (no breaking change for existing users).
- Add CLI test.

**Estimated tokens:** 10–15K

---

## Rank 9 — SARIF Output Format (ecosystem integration, medium effort)

**What:** SARIF (Static Analysis Results Interchange Format) is the standard output format for
security scanners in GitHub Actions, VS Code, and many CI platforms. Adding `--format sarif` would
allow ferryman findings to appear natively in GitHub Security tab, VS Code Problems panel, and
SARIF-consuming SAST dashboards.

**Why now:** As ferryman matures as a tool, SARIF positions it alongside professional SAST tools
rather than just a script. GitHub Actions has first-class SARIF upload support.

**Implementation sketch:**
- Map `Finding` to SARIF 2.1.0 `result` schema: check → `ruleId`, severity → SARIF `level`,
  location → `physicalLocation` (with region if line number parseable).
- Produce the minimal valid SARIF envelope: `$schema`, `version`, `runs[0].tool`, `runs[0].results`.
- Zero new dependencies — SARIF is just a JSON schema.
- Add tests: valid JSON output, SARIF version field present, finding count matches.

**Estimated tokens:** 50–70K

---

## Research notes

**Sources consulted:**

- Cisco Talos / LibOFX buffer overflow (tag parsing code execution): structural tag parsing is
  the primary exploit class in OFX-aware libraries.
- Security Innovation `ofxpostern` (OFX Direct Connect scanner): demonstrates that OFX server
  endpoints, not just file formats, are in scope for fintech bug bounties. Out of scope for
  ferryman (file scanner only) but informs what bug-bounty programs care about.
- OWASP XXE Guide, PortSwigger Web Security Academy: confirmed entity expansion is a separately
  reportable vector from external-entity XXE.
- CVE-2026-34601 (xmldom CDATA injection): fresh 2026 vulnerability demonstrating CDATA injection
  as a live threat in XML processing pipelines relevant to OFX v2.
- `ofxtools` codebase: no known CVEs; inherits Python `xml.etree.ElementTree` risk surface.
- ABA routing number checksum: public spec, zero dependencies, directly actionable for Rank 1.
- Intigriti Finance Vulnerability Report 2024: information disclosure and injection are the top
  two fintech vulnerability classes — maps directly to ferryman's PII and malformed checks.
- Fintech PII API breach case studies (2025): confirms that account numbers in API responses /
  transaction exports are the most common leak class in active bug-bounty programs.
