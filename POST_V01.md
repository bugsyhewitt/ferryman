# ferryman — Post-v0.1 Improvement Backlog

**Research lap date:** 2026-05-26  
**Basis:** codebase review + OFX/fintech security landscape research (2024–2026)

Items are ranked by: security impact for bug-bounty reporters × detection gap × implementation effort.

---

## Rank 1 — ABA Routing Number Checksum Validation (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-26, Phase 2 Rotation 2)

**Status:** Shipped. `_aba_checksum_valid()` added to `src/ferryman/checks/pii.py`; the
`routing_number` (high) finding is now gated behind the ABA 3-7-1 weighted checksum. Nine-digit
runs that fail the checksum are downgraded to `probable_routing_number` at `info` severity instead
of crying wolf. Unit tests cover real ABA numbers, invalid 9-digit collisions (sequential, repeated,
off-by-one, phone-shaped), malformed input, and the no-double-count guarantee against the
account-number path. No new dependencies.

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

## Rank 4 — Investment Account (INVSTMTRS) Statement Support in PII + Anomaly Checks (coverage gap, medium effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 5)

**Status:** Shipped. `parsing.py` now detects investment statements (by
`INVSTMTRS` class name) in `ofx.statements` and flattens their `INVTRANLIST`
transactions into the shared `Transaction` model — mapping the trade date onto
`dtposted`, `TOTAL` onto `amount`, and populating new investment-only fields
(`is_investment`, `units`, `unitprice`, `secid`); the broker id is carried in
`bankid`. The pii check scans investment memos via the existing free-text path
and the security id (`UNIQUEID`/CUSIP) via a narrower `_scan_secid` rule (SSN
shape + 10-digit-or-longer runs only) so a legitimate numeric CUSIP never trips
the routing-number heuristic. The anomaly check adds `negative_unit_price`
(high), `negative_units` on non-sell types (high), and `implausible_unit_price`
(medium), with defensive `Decimal` parsing that rejects NaN/Inf. New fixtures
`investment.ofx`, `investment-pii.ofx`, `investment-secid-leak.ofx` and a
`tests/test_investment.py` module (12 tests) cover clean statements, leaks,
anomalies, the CUSIP false-positive guard, bank-statement regression, and
garbage-amount safety. No new dependencies.

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

## Rank 5 — OFX v1 SGML Header Injection Detection (medium signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 6)

**Status:** Shipped. `checks/malformed.py` gained `_is_ofx_v1()`, `_split_header()`,
and `_check_v1_header()`. For OFX v1 documents (those opening with `OFXHEADER:`),
the check now: (a) flags a second `OFXHEADER:` block found in the body after the
header/body separator as `header_injection` (high); (b) flags an `ENCODING` value
outside `{USASCII, UTF-8, UNICODE}` or an unexpected non-numeric `CHARSET` as
`encoding_mismatch` (medium); (c) flags non-printable control bytes inside the
header section as `encoding_mismatch` (medium). v2 pure-XML files are excluded by
the `_is_ofx_v1` guard, so no false positives there. Nine new unit tests cover the
clean fixture, inline clean v1 headers, injected second header, disallowed and
allowed encodings, odd/numeric charsets, control bytes, and the v2 exclusion. No
new fixture file and no new dependencies.

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

## Rank 6 — Negative/Zero Transaction Amount Anomaly (medium signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 7)

**Status:** Shipped. The anomaly check now inspects `tx.amount` for bank and
credit-card transactions via `_check_transaction_amount()` in
`checks/anomaly.py`. It emits a single `anomalous_amount` type covering three
cases: a **zero** amount (`high` — a posting that moves no money), a **sign that
contradicts the declared OFX type** (`medium` — a positive DEBIT/PAYMENT/FEE or a
negative CREDIT/DEP/INT, using the new `_DEBIT_TYPES` / `_CREDIT_TYPES` sets), and
an **out-of-range magnitude** above the `_MAX_TXN_AMOUNT` ($10M) ceiling
(`medium`). Normal postings that respect the debits-negative / credits-positive
convention are never flagged, and non-finite (`NaN`/`Inf`) or unparseable amounts
are left to the malformed check via the existing `_decimal_or_none` guard.
Investment transactions keep their dedicated price/quantity path. New fixture
`tests/fixtures/anomalous-amount.ofx` plus eleven unit tests in
`tests/test_anomaly.py` cover all cases, the false-positive guards, and the
no-regression promise on the clean fixture. No new dependencies.

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

## Rank 7 — Scan Multiple Files (Glob / Directory Input) via CLI (usability, medium effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 8)

**Status:** Shipped. `cli.py` now accepts multiple positional `FILE` arguments
(`nargs="*"`, so shell globs expand naturally) plus a `--dir DIR` flag that
scans every `*.ofx` file in `DIR` (non-recursive, sorted for deterministic
ordering); positional files and `--dir` matches merge. A **single-file**
invocation keeps the exact prior json/text/h1md output shape (no envelope), so
every existing pipeline and test is byte-identical. A **multi-file** invocation
(more than one file, or any use of `--dir`) wraps the results: json emits a
`{"tool", "version", "files": [<per-file result>...], "summary": {"file_count",
"total"}}` envelope where each `files` entry is the canonical single-file shape;
text prints a batch header plus the compact per-file summary; h1md renders one
combined HackerOne report with the source file folded into each finding's
`location` (`<file>: <loc>`) to preserve attribution. New error paths return
exit `3`: no input given, `--dir` not a directory, `--dir` matched no `*.ofx`,
or any listed file unreadable. Eleven new CLI tests in `tests/test_cli.py` cover
the json envelope, text and h1md batch output, `--dir` discovery and the
`.ofx`-only filter, the single-match-still-envelope guarantee for `--dir`,
positional+`--dir` merge, and all four error paths. README usage section
updated. No new dependencies.

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

## Rank 8 — Exit Code Non-Zero on Findings Found (usability + CI integration, trivial effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 9)

**Status:** Shipped. `cli.py` gained an opt-in `--fail-on SEVERITY` flag
(choices = the five `SEVERITIES`) plus a `_meets_threshold()` helper. When set,
the scan still emits its full json/text/h1md output, then returns exit code `1`
if any finding (across all files in a batch run) is at or above the chosen
severity; otherwise it returns `0`. Without the flag the prior contract is
preserved exactly — a completed scan always exits `0` regardless of findings —
so every existing pipeline and test is unchanged. The exit-code map is now `0`
clean/under-threshold, `1` threshold met, `2` usage error, `3` unreadable input.
Eight new CLI tests in `tests/test_cli.py` cover the help listing, the
zero-exit-without-flag guarantee, threshold-met and threshold-not-met cases,
`--fail-on info` tripping on any finding, the clean-file zero exit, multi-file
gating, and format-independence. README usage section gained a "Gating a
pipeline on findings" subsection. No new dependencies.

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

## Rank 9 — SARIF Output Format (ecosystem integration, medium effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 10)

**Status:** Shipped. A new `src/ferryman/sarif.py` module (sibling to the h1md
`reporting.py` adapter) renders findings to a SARIF 2.1.0 document, wired into
the CLI as `--format sarif`. The envelope carries `$schema`, `version`, and a
single `runs[0]` with a `tool.driver` (name/version/informationUri + one
`reportingDescriptor` rule per distinct `<check>/<type>` id) and a `results`
array. Severity maps to SARIF's coarse `level` (critical/high &rarr; `error`,
medium &rarr; `warning`, low/info &rarr; `note`) while the exact ferryman
severity is preserved in `properties.severity` and a numeric `rank` (0–100) so
consumers order findings ferryman's way. Free-form locations carrying a
`line N` token (the malformed check) gain a SARIF `region` with `startLine`
(and the evidence snippet); other locators are preserved in
`properties.location`. Multi-file / `--dir` runs reuse the existing file
attribution so each result's `artifactLocation.uri` is its source file. The
json/text/h1md paths are byte-identical to before. Thirteen new tests in
`tests/test_sarif.py` cover the empty envelope, result/rule counts, the full
severity-to-level/rank mapping, line-region parsing, the no-line default
artifact + locator preservation, file-attributed URIs, and the CLI single-file,
multi-file, clean-file, result-count-vs-json, and `--fail-on` interactions.
README gained a "SARIF output for GitHub Code Scanning and IDEs" section with a
GitHub Actions `upload-sarif` snippet. Zero new dependencies (stdlib `json`).

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

## Rank 10 — Payment-Card (PAN) Leak Detection, Luhn-gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 11)

**Status:** Shipped. `checks/pii.py` gained a `_luhn_valid()` helper (the public,
dependency-free mod-10 check digit every card network uses) and a `_CARD_RE`
matcher for 13–19 digit runs allowing the conventional space/hyphen grouping
(`4111 1111 1111 1111`, `4111-1111-1111-1111`, or unspaced). In `_scan_text`,
card detection runs **before** the generic account-number scan: a run that
passes Luhn and falls in the 13–19 digit length window is reported as
`credit_card` (severity `critical`, PCI-DSS sensitive), with the compact digits
reserved in the dedupe set under both the `credit_card` and `account_number`
namespaces so the same PAN is never double-counted as a plain account number and
the same card written two ways collapses to one finding per field. Runs that fail
Luhn, or that fall outside the length window (e.g. a 12-digit order number), fall
through untouched to the existing `account_number` / `routing_number` scanners.
Evidence is redacted to the card's shape (`XXXX XXXX XXXX XXXX`) so the raw PAN
never leaves the tool. The 13-digit card floor sits above the 9-digit routing
window, so there is no overlap with the ABA path. New fixture
`tests/fixtures/credit-card-leak.ofx` plus seventeen new tests in
`tests/test_pii.py` cover the Luhn helper (network test PANs, near-miss and
sequential rejects, non-numeric guards), spaced/dashed/unspaced detection,
per-field dedupe, the Luhn-fail and short-run fall-through to account_number, the
fixture, and the clean-file no-card guarantee. README gained a "Payment-card
(PAN) leak detection" section. No new dependencies.

**What:** The pii check covered SSN, account number, and routing number but not
payment-card numbers — a top fintech PII / PCI-DSS leak class. Card numbers carry
the public Luhn checksum, so gating on it (exactly as Rank 1 gated routing
numbers on the ABA checksum) yields a high-precision, zero-dependency detector.

**Research grounding:** Luhn (ISO/IEC 7812) is public domain, ~12 lines of
Python. Fintech PII breach case studies (2025) confirm full PANs in transaction
exports / API responses are a common, high-severity leak class in active
bug-bounty programs. PCI-DSS prohibits storing/transmitting an unmasked PAN.

**Estimated tokens:** 30–45K

---

## Rank 11 — IBAN Leak Detection, mod-97 / country-length gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 12)

**Status:** Shipped. `checks/pii.py` gained an `_iban_valid()` helper that gates an
IBAN candidate behind three independent public checks: ISO 13616 shape (two-letter
country code + two check digits + alphanumeric BBAN), the registered per-country
total length (`_IBAN_LENGTHS`, with a generic 15–34 fallback for countries not yet
in the table), and the mod-97 checksum (rearrange-and-remainder). An `_IBAN_RE`
matcher accepts both the contiguous form (`DE89370400440532013000`) and the
human-readable space-grouped form (`DE89 3704 0044 0532 0130 00`); a
`_trim_to_valid_iban()` post-step resolves the grouped form's tendency to
over-capture trailing words by dropping trailing space-separated tokens until the
remaining prefix validates. In `_scan_text`, IBAN detection runs **before** the
credit-card, routing, and account scanners, and every digit run inside a detected
IBAN is reserved under the `account_number`/`credit_card`/`routing_number` dedupe
namespaces so the same leak is never double-counted. Findings are `high` severity;
evidence is redacted to the country code plus masked digits via `_redact_iban()`
so the account body never leaves the tool. Candidates that fail any gate fall
through untouched to the existing heuristics. New fixture
`tests/fixtures/iban-leak.ofx` (two valid IBANs + a bad-checksum `XX` decoy +
an order-number) plus 29 new tests in `tests/test_pii.py` cover the validator
(published registry IBANs, wrong-check-digit / wrong-length / unknown-country /
no-country rejects, garbage guards, lowercase+spaced acceptance), contiguous and
spaced detection, per-field dedupe, the no-double-count guarantee, the
"don't swallow a following account number" guard, the invalid-IBAN no-report
case, the fixture, and the clean-file no-IBAN guarantee. README gained an
"IBAN leak detection" section. No new dependencies (stdlib `re` only).

**What:** The pii check covered SSN, payment card (PAN), US account number, and
US ABA routing number, but not the **IBAN** — the European/global bank-account
identifier and a top international fintech PII leak class. Like the ABA (Rank 1)
and Luhn (Rank 10) gates, the IBAN carries a public checksum (mod-97) plus a
per-country fixed length, so gating on country + length + checksum yields a
high-precision, zero-dependency detector.

**Research grounding:** ISO 13616 / ISO 7064 mod-97-10 is public domain, ~15 lines
of Python. IBANs appear in SEPA transaction memos and counterparty fields; an
export that echoes a full IBAN into free text is a reportable PII disclosure in
EU/UK fintech bug-bounty programs (GDPR financial-data exposure).

**Estimated tokens:** 35–50K

---

## Rank 12 — ISIN Leak Detection, ISO 6166 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 13)

**Status:** Shipped. `checks/pii.py` gained an `_isin_valid()` helper that gates an
ISIN candidate behind two independent public checks: the ISO 6166 shape
(two-letter country/issuer code + nine-character alphanumeric NSIN + one decimal
check digit, exactly twelve characters) and the ISO 6166 check digit (expand each
letter to its two-digit value, `A`=10&hellip;`Z`=35, then reuse the existing
`_luhn_valid()` mod-10 check over the whole expanded string). An `_ISIN_RE`
matcher (`[A-Z]{2}[A-Z0-9]{9}\d`, non-alphanumeric bounded) finds candidates in
free text. In `_scan_text`, ISIN detection runs **before** the credit-card,
routing, and account scanners, and every digit run inside a detected ISIN is
reserved under the `account_number`/`credit_card`/`routing_number` dedupe
namespaces so the same identifier is never double-counted. Findings are `high`
severity; evidence is redacted to the two-letter country/issuer prefix via
`_redact_isin()` so the NSIN body never leaves the tool. Candidates that fail the
check digit or the 12-char shape fall through untouched to the existing
heuristics. Crucially, an ISIN sitting in its own structured `SECID` field is
**not** flagged (the narrow `_scan_secid` path is unchanged) &mdash; only an ISIN
bleeding into a free-text memo/name, which discloses a customer's securities
holdings, is reported. New fixture `tests/fixtures/isin-leak.ofx` (a US ISIN and a
GB ISIN in two memos plus a wrong-check-digit `XX` decoy) plus 24 new tests in
`tests/test_pii.py` cover the validator (published registry ISINs incl. an
alphanumeric NSIN, wrong-check-digit / wrong-length / no-country rejects, garbage
guards, lowercase acceptance), memo detection and redaction, per-field dedupe, the
no-double-count guarantee, the invalid-ISIN no-report case, the fixture, and the
clean-file no-ISIN guarantee. README gained an "ISIN leak detection" section and
the PII type list was updated. No new dependencies (stdlib `re` only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, US account number,
and US ABA routing number, but not the **ISIN** &mdash; the global securities
identifier and a brokerage-account PII leak class. Like the ABA (Rank 1), Luhn
(Rank 10), and IBAN (Rank 11) gates, the ISIN carries a public check digit
(ISO 6166, Luhn-over-expanded-letters), so gating on shape + check digit yields a
high-precision, zero-dependency detector. An ISIN echoed into a transaction memo
reveals which securities a customer holds &mdash; reportable on its own in fintech
bug-bounty programs.

**Research grounding:** ISO 6166 / the ISIN check-digit algorithm (letter
expansion + Luhn) is public domain, ~15 lines of Python and reuses the existing
`_luhn_valid` helper. Brokerage holdings disclosure (which securities, in what
size) is a recognised financial-privacy leak in investment-platform bug-bounty
programs; the project already parses INVSTMTRS investment statements (Rank 4),
making the free-text ISIN echo a natural, in-scope next detector.

**Estimated tokens:** 35–50K

---

## Rank 13 — CUSIP Leak Detection, modulus-10 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 14)

**Status:** Shipped. `checks/pii.py` gained a `_cusip_valid()` helper that gates a
CUSIP candidate behind two independent public checks: the 9-character shape
(8-character base of digits / `A`&ndash;`Z` / the legacy specials `*` `@` `#`,
plus one trailing decimal check digit) and the public CUSIP modulus-10
"double-add-double" check digit (a `_cusip_char_value()` table maps digits to
themselves, `A`=10&hellip;`Z`=35, `*`=36 `@`=37 `#`=38; every even-position value
is doubled, the decimal digits of each value are summed, and the check digit is
`(10 - sum mod 10) mod 10`). A `_CUSIP_RE` matcher finds 9-char candidates in
free text **but requires at least one letter in the base** (via a lookahead
asserting the 8-base + check-digit shape and a consuming pattern that forces a
letter), so a purely numeric 9-digit run &mdash; which belongs to the ABA
routing-number space &mdash; is never reclassified as a CUSIP and the
routing/`probable_routing_number` path is untouched. In `_scan_text`, CUSIP
detection runs **after** the 12-char ISIN (a US ISIN embeds a CUSIP as its NSIN,
so the longer ISIN match wins) and **before** the credit-card / routing / account
scanners, and every digit run inside a detected CUSIP is reserved under the
`account_number`/`credit_card`/`routing_number` dedupe namespaces so the same
identifier is never double-counted. Findings are `high` severity; evidence is
redacted to the leading two characters via `_redact_cusip()` so the base and
check digit never leave the tool. Crucially, a CUSIP sitting in its own
structured `SECID` field is **not** flagged (the narrow `_scan_secid` path is
unchanged) &mdash; only a CUSIP bleeding into a free-text memo/name, which
discloses a customer's securities holdings, is reported. New fixture
`tests/fixtures/cusip-leak.ofx` (a Cisco CUSIP and a Tesla CUSIP in two memos plus
a wrong-check-digit decoy, with the same CUSIPs sitting legitimately in their
`SECID` fields) plus 26 new tests in `tests/test_pii.py` cover the validator
(published registry CUSIPs incl. all-numeric and special-char value mapping,
wrong-check-digit / wrong-length / non-numeric-check-digit / garbage rejects,
lowercase acceptance), memo detection and redaction, the numeric-run /
routing-space guard, per-field dedupe, the no-double-count guarantee, ISIN
precedence over an embedded CUSIP, the invalid-CUSIP no-report case, the fixture,
and the clean-file no-CUSIP guarantee. README gained a "CUSIP leak detection"
section and the PII type list was updated. No new dependencies (stdlib `re`
only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, ISIN, US account
number, and US ABA routing number, but not the **CUSIP** &mdash; the nine-character
US/Canada securities identifier and a brokerage-account PII leak class. The CUSIP
is the NSIN at the core of a US ISIN; many OFX investment statements use a CUSIP
rather than an ISIN in their `SECID`. Like the ABA (Rank 1), Luhn (Rank 10), IBAN
(Rank 11), and ISIN (Rank 12) gates, the CUSIP carries a public check digit
(modulus-10 double-add-double), so gating on shape + check digit yields a
high-precision, zero-dependency detector. A CUSIP echoed into a transaction memo
reveals which securities a customer holds &mdash; reportable on its own in fintech
bug-bounty programs.

**Research grounding:** The CUSIP check-digit algorithm (CUSIP Global Services,
ISO 6166 NSIN for US & Canada) is public and documented, ~20 lines of Python with
no new dependency. It complements the existing ISIN detector: a US/Canada holding
is typically identified by a bare CUSIP, while the international form prefixes the
country code and re-checksums into an ISIN. The project already parses INVSTMTRS
investment statements (Rank 4) and detects ISIN free-text leaks (Rank 12), making
the bare-CUSIP free-text echo the natural, in-scope next detector.

**Estimated tokens:** 35–50K

---

## Rank 14 — SEDOL Leak Detection, weighted modulus-10 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-28, Phase 2 Rotation 15)

**Status:** Shipped. `checks/pii.py` gained a `_sedol_valid()` helper that gates a
SEDOL candidate behind two independent public checks: the 7-character shape
(6-character base of digits / consonants — the vowels `A E I O U` are never used
in a SEDOL base — plus one trailing decimal check digit) and the public SEDOL
weighted modulus-10 check digit (map each base character to its value, digit
as-itself / `B`=11…`Z`=35 via the same `ord-55` letter expansion the ISIN and
CUSIP gates use; multiply by the positional weights `(1, 3, 1, 7, 3, 9)`; the
check digit is `(10 - (weighted sum mod 10)) mod 10`). A `_SEDOL_RE` matcher finds
7-char candidates in free text **but requires at least one consonant in the
base** (the vowel-excluding character class plus a letter-forcing pattern), so a
purely numeric 7-digit run — a common coincidental value — is never reclassified
as a SEDOL. In `_scan_text`, SEDOL detection runs **after** the longer 12-char
ISIN and 9-char CUSIP (a UK/Ireland ISIN embeds a SEDOL as its NSIN, so the
longer match wins) and **before** the credit-card / routing / account scanners,
and every digit run inside a detected SEDOL is reserved under the
`account_number`/`credit_card`/`routing_number` dedupe namespaces so the same
identifier is never double-counted. Findings are `high` severity; evidence is
redacted to the leading character via `_redact_sedol()` so the base and check
digit never leave the tool. Crucially, a SEDOL sitting in its own structured
`SECID` field is **not** flagged (the narrow `_scan_secid` path is unchanged) —
only a SEDOL bleeding into a free-text memo/name, which discloses a customer's
securities holdings, is reported. New fixture `tests/fixtures/sedol-leak.ofx`
(two valid SEDOLs in two memos plus a wrong-check-digit decoy, with the same
SEDOLs sitting legitimately in their `SECID` fields) plus 25 new tests in
`tests/test_pii.py` cover the validator (published registry SEDOLs incl.
all-numeric helper-level acceptance, wrong-check-digit / vowel-in-base /
wrong-length / non-numeric-check-digit / garbage rejects, lowercase acceptance),
memo detection and redaction, the numeric-run guard, per-field dedupe, the
no-double-count guarantee, the no-interference-with-CUSIP/ISIN guard, the
invalid-SEDOL no-report case, the fixture, and the clean-file no-SEDOL guarantee.
README gained a "SEDOL leak detection" section and the PII type list was updated.
No new dependencies (stdlib `re` only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, ISIN, CUSIP, US
account number, and US ABA routing number, but not the **SEDOL** — the
seven-character UK/Ireland securities identifier and a brokerage-account PII leak
class. The SEDOL is the NSIN at the core of a UK/Ireland ISIN; many OFX
investment statements from UK brokers use a SEDOL rather than a CUSIP in their
`SECID`. Like the ABA (Rank 1), Luhn (Rank 10), IBAN (Rank 11), ISIN (Rank 12),
and CUSIP (Rank 13) gates, the SEDOL carries a public check digit (weighted
modulus-10), so gating on shape + no-vowel rule + check digit yields a
high-precision, zero-dependency detector. A SEDOL echoed into a transaction memo
reveals which securities a customer holds — reportable on its own in fintech
bug-bounty programs.

**Research grounding:** The SEDOL check-digit algorithm (London Stock Exchange,
ISO 6166 NSIN for UK & Ireland) is public and documented, ~15 lines of Python
with no new dependency. It completes the three major NSIN families ferryman now
detects: CUSIP (US/Canada), SEDOL (UK/Ireland), and ISIN (international, which
wraps the local NSIN). The project already parses INVSTMTRS investment statements
(Rank 4) and detects ISIN/CUSIP free-text leaks (Ranks 12–13), making the
free-text SEDOL echo the natural, in-scope next detector.

**Estimated tokens:** 35–50K

---

## Rank 15 — LEI Leak Detection, ISO 7064 mod-97-10 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 16)

**Status:** Shipped. `checks/pii.py` gained a `_lei_valid()` helper that gates an
LEI candidate behind two independent public checks: the 20-character shape (an
18-character alphanumeric entity portion plus two trailing decimal check digits)
and the ISO 7064 mod-97-10 check digits (expand every letter to its two-digit
value, `A`=10&hellip;`Z`=35, via the same `ord-55` expansion the IBAN/ISIN/CUSIP
gates use; interpret the whole 20-character value — check digits included — as an
integer; a valid LEI is `== 1 (mod 97)`). This is the same ISO 7064 scheme the
IBAN gate uses, but applied to the whole value with **no rearrangement** because
the LEI's check digits already sit at the end. An `_LEI_RE` matcher
(`[A-Za-z0-9]{18}\d{2}`, non-alphanumeric bounded) finds 20-char candidates in
free text. In `_scan_text`, LEI detection runs **before** the shorter ISIN (12),
CUSIP (9), and SEDOL (7) identifiers — the LEI is the longest gated identifier,
so claiming the full 20-char run first prevents a shorter detector from matching
a window inside it — and before the credit-card / routing / account scanners;
every digit run inside a detected LEI is reserved under the
`account_number`/`credit_card`/`routing_number` dedupe namespaces so the same
identifier is never double-counted. Findings are `high` severity; evidence is
redacted to the leading four-character LOU prefix via `_redact_lei()` so the
entity portion and check digits never leave the tool. Crucially, the reserved
positions 4–5 are **not** gated on being `00` — that convention is honoured only
by the earliest ROC-assigned prefixes, not by all later Local Operating Units, so
enforcing it would reject real LEIs (e.g. Deutsche Bank's `7LTWFZ…`); gating on
shape + the mod-97-10 check digits alone is the robust rule. New fixture
`tests/fixtures/lei-leak.ofx` (two valid GLEIF-registry LEIs in two memos plus a
wrong-check-digit decoy, with legitimate ISINs in the `SECID` fields) plus 24 new
tests in `tests/test_pii.py` cover the validator (published registry LEIs,
wrong-check-digit / wrong-length / non-numeric-check-digit / garbage / all-letter
rejects, lowercase acceptance), memo detection and four-prefix redaction, the
no-double-count guarantee, the no-interference-with-ISIN/CUSIP/SEDOL guard,
per-field dedupe, the invalid-LEI no-report case, the fixture, and the clean-file
no-LEI guarantee. README gained an "LEI leak detection" section and the PII type
list was updated. No new dependencies (stdlib `re` only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, ISIN, CUSIP,
SEDOL, US account number, and US ABA routing number — every prior identifier
naming an *account* or a *security*, but none naming the **legal entity** behind a
transaction. The LEI (ISO 17442) is the global identifier for that entity — a
counterparty, issuer, or fund manager — and is mandated in regulatory
transaction reporting (MiFID II, EMIR, Dodd-Frank). Like the ABA (Rank 1), Luhn
(Rank 10), IBAN (Rank 11), ISIN (Rank 12), CUSIP (Rank 13), and SEDOL (Rank 14)
gates, the LEI carries a public checksum (ISO 7064 mod-97-10), so gating on shape
+ check digits yields a high-precision, zero-dependency detector. An LEI echoed
into a transaction memo discloses *who* a customer transacted with — a
counterparty-confidentiality leak reportable on its own.

**Research grounding:** ISO 17442 / ISO 7064 mod-97-10 is public domain, ~12
lines of Python and reuses the same letter-expansion the IBAN/ISIN gates use. The
algorithm and a set of registry LEIs (Allianz `529900T8BM49AURSDO55`, Deutsche
Bank `7LTWFZYICNSX8D621K86`, NASDAQ `F3JS33DEI6XQ4ZBPTN86`) are published by GLEIF
and verifiable against the mod-97-10 rule. The LEI complements the
account/security identifier family ferryman already detects by adding the
entity-identity dimension: account (IBAN/account number), security
(ISIN/CUSIP/SEDOL), and now counterparty (LEI).

**Estimated tokens:** 35–50K

---

## Rank 16 — BIC / SWIFT Code Leak Detection, ISO 9362 structure + country-code gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 17)

**Status:** Shipped. `checks/pii.py` gained a `_bic_valid()` helper that gates a
BIC (Bank Identifier Code / SWIFT code) candidate behind three independent public
checks: the ISO 9362 shape (exactly 8 or 11 characters — four letters for the
institution/bank code, two letters for the country code, two alphanumerics for the
location code, and an optional three-alphanumeric branch code), a registered
**ISO 3166-1 alpha-2 country code** at positions 5–6 (the new `_ISO_3166_1`
frozenset, the primary precision lever, mirroring how the IBAN gate uses the
country registry), and the ISO 9362 **location-code rules** (the first location
character is never `0` or `1`, the second is never the letter `O`). ISO 9362
defines no arithmetic checksum, so precision comes from the strict structure plus
the registered country code rather than a check digit. A `_BIC_RE` matcher is
deliberately **upper-case only** (`[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?`,
non-alphanumeric bounded): a BIC is always transmitted in upper case, and matching
lower-case all-letter runs would flood reports with ordinary English words — the
canonical collision being `beneficiary` (eleven letters whose 5th–6th characters
are `FI`, Finland, with a passing location code). The `_bic_valid` helper itself
stays case-insensitive so it is safe to reuse. In `_scan_text`, BIC detection runs
**before** the securities identifiers and the credit-card / routing / account
scanners, and any digit run inside a detected BIC's location/branch code is
reserved under the `account_number`/`credit_card`/`routing_number` dedupe
namespaces so the same identifier is never double-counted. Findings are `high`
severity; evidence is redacted to the six-character bank-plus-country prefix via
`_redact_bic()` so the location and branch codes never leave the tool. New fixture
`tests/fixtures/bic-leak.ofx` (an 8-char and an 11-char valid BIC in two memos
plus a bad-country `DEUTXXFF` decoy) plus 32 new tests in `tests/test_pii.py` cover
the validator (real 8- and 11-char registry BICs, bad-country / reserved-location
/ forbidden-`O` / digit-in-country / wrong-length rejects, garbage guards,
lowercase-validator acceptance), upper-case-only memo detection and six-char
redaction, the lowercase-word (`beneficiary` / `deutdeff`) non-detection guards,
the no-double-count guarantee, the no-interference-with-ISIN/LEI guard, per-field
dedupe, the invalid-BIC no-report case, the fixture, and the clean-file no-BIC
guarantee. README gained a "BIC / SWIFT code leak detection" section and the PII
type lists were updated. No new dependencies (stdlib `re` only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, ISIN, CUSIP,
SEDOL, LEI, US account number, and US ABA routing number — identifiers naming an
*account*, a *security*, or a *legal entity*, but none naming the **financial
institution** that processes a transaction. The BIC (ISO 9362) is the global
identifier for that institution — the SWIFT code printed alongside an IBAN on a
wire instruction. Unlike the prior gates, ISO 9362 has no arithmetic checksum, so
the detector gates on structure + a registered ISO 3166-1 country code + the
ISO 9362 location-code rules, with upper-case-only matching as the precision lever
against English-word collisions. A BIC echoed into a transaction memo discloses
*which bank* a customer transacted with, and paired with a leaked IBAN it fully
identifies a counterparty account — a counterparty-confidentiality leak reportable
on its own.

**Research grounding:** ISO 9362 (BIC structure, the 8/11-char head-office /
branch forms) and ISO 3166-1 alpha-2 (the country-code registry) are public and
documented, ~15 lines of Python with no new dependency. The BIC completes the
counterparty/institution dimension alongside the LEI: account (IBAN / account
number), security (ISIN / CUSIP / SEDOL), legal entity (LEI), and now institution
(BIC). A leaked IBAN + BIC pair is the exact data a wire-fraud or
account-takeover attacker needs, making the free-text BIC echo a natural, in-scope
next detector.

**Estimated tokens:** 35–50K

---

## Rank 17 — UK Sort Code Leak Detection, NN-NN-NN structure + clearing-range gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 18)

**Status:** Shipped. `checks/pii.py` gained a `_uk_sort_code_valid()` helper that
gates a UK sort code candidate behind two independent public, dependency-free
checks: the canonical hyphenated **shape** (exactly `NN-NN-NN` — three
hyphen-separated pairs of decimal digits) and the assigned **clearing-range
prefix** (the leading pair must be in the range `01`–`97`; `00` is unassigned and
`98`/`99` are reserved for the Bank of England / non-clearing and test ranges, so
the all-zeros and the classic `99-99-99` decoy never validate). A UK sort code has
no published, self-contained check digit — the VocaLink modulus check that
validates a sort code requires the paired account number and a weight table — so
precision comes from the structure plus the clearing-range prefix rather than an
arithmetic checksum. The `_UK_SORT_CODE_RE` matcher (`\d{2}-\d{2}-\d{2}`,
non-digit/non-hyphen bounded) keys off the hyphenated presentation, which is the
dominant precision lever: the hyphens break the token into three two-digit pieces,
so it is structurally distinct from any contiguous digit run and never competes
with — nor is double-counted against — the account-number (`\d{8,}`), routing
(`\d{9}`), or payment-card scanners, and the SSN shape (`NNN-NN-NNNN`, a 3-2-4
split) cannot collide with it either. Findings are `high` severity; evidence is
redacted to the leading bank pair via `_redact_uk_sort_code()` (`20-XX-XX`) so the
branch-identifying pairs never leave the tool. New fixture
`tests/fixtures/uk-sort-code-leak.ofx` (two valid sort codes in two memos plus a
reserved `99-99-99` decoy) plus 35 new tests in `tests/test_pii.py` cover the
validator (real clearing sort codes including the min/max assigned leading pairs,
unassigned/reserved/out-of-range/wrong-shape rejects, garbage guards), memo
detection and leading-pair redaction, the reserved-value and all-zeros
non-detection guards, the contiguous-six-digit non-detection guard, the
no-interference-with-other-identifiers guard, the no-collision-with-digit-scanners
guarantee, the SSN-not-misread guard, per-field dedupe, the fixture, and the
clean-file no-sort-code guarantee. README gained a "UK sort code leak detection"
section and the PII type lists were updated. No new dependencies (stdlib `re`
only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, ISIN, CUSIP,
SEDOL, LEI, BIC, US account number, and US ABA routing number — identifiers
naming an account, a security, a legal entity, and the institution, plus the
**US** domestic routing code. The UK sort code is the **UK** domestic routing
code — the six-digit `NN-NN-NN` value that identifies a bank and branch and that,
paired with an account number, drives a Faster Payments / BACS / CHAPS transfer.
A sort code echoed into a transaction memo discloses *which UK bank and branch*
routes a customer's account; paired with a leaked account number it is the exact
data a UK wire-fraud or account-takeover attacker needs, making the free-text sort
code echo the natural domestic-routing companion to the already-shipped ABA
routing-number detector.

**Research grounding:** The UK sort code's `NN-NN-NN` structure and the assigned
clearing range (leading pair `01`–`97`, with `00` unassigned and `98`/`99`
reserved) are public and documented. The full VocaLink modulus check (the only
arithmetic validation) requires the paired account number and a published weight
table — out of scope for a single self-contained identifier — so the detector
gates on the hyphenated structure plus the clearing-range prefix, with the
hyphenated presentation itself the precision lever against coincidental digit
runs. ~15 lines of Python with no new dependency. The sort code completes the
domestic-routing dimension alongside the ABA number: US routing (ABA) and now UK
routing (sort code).

**Estimated tokens:** 35–50K

---

## Rank 18 — Canadian Routing Number Leak Detection, TTTTT-III MICR structure + assigned-institution gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 19)

**Status:** Shipped. `checks/pii.py` gained a `_ca_routing_valid()` helper that
gates a Canadian routing-number candidate behind two independent public,
dependency-free checks: the canonical MICR (cheque-encoding) **shape** (exactly
`TTTTT-III` — a five-digit branch transit number, a hyphen, and a three-digit
financial-institution number) and the assigned **institution number** (the
three-digit institution must fall in a Payments Canada assigned range:
`001`–`039` chartered Schedule I banks, `100`–`399` Schedule II/III foreign banks
and federal members, `600`–`699` trust & loan companies, `800`–`899` credit-union
/ caisse-populaire centrals; `000` is never a live institution and out-of-range
values such as `999` are the classic decoy). Like the UK sort code, a Canadian
routing number has no published, self-contained arithmetic checksum — the only
validation is the bank's own account-modulus check, which requires the paired
account number — so precision comes from the MICR structure plus the assigned
institution number rather than a checksum. The `_CA_ROUTING_RE` matcher
(`\d{5}-\d{3}`, non-digit/non-hyphen bounded) keys off the hyphenated 5-3
presentation, which is the dominant precision lever: the hyphen breaks the token
into a five- and a three-digit piece, so it is structurally distinct from any
contiguous digit run and never competes with — nor is double-counted against —
the account-number (`\d{8,}`), routing (`\d{9}`), or payment-card scanners. The
5-3 split is also distinct from the UK sort code's 2-2-2 split and the SSN's 3-2-4
split, so the three hyphenated detectors never collide. Findings are `high`
severity; evidence is redacted to the trailing institution number via
`_redact_ca_routing()` (`XXXXX-003`) so the branch-identifying transit number
never leaves the tool. New fixture `tests/fixtures/ca-routing-leak.ofx` (two valid
routing numbers in two memos plus an out-of-range `11111-999` decoy) plus 39 new
tests in `tests/test_pii.py` cover the validator (real-format routing numbers
across all four assigned institution ranges including range boundaries,
unassigned-gap/zero/out-of-range/wrong-shape rejects, garbage guards), memo
detection and institution-number redaction, the decoy and zero-institution
non-detection guards, the contiguous-digit non-detection guard, the
no-interference-with-other-identifiers guard, the no-collision-with-digit-scanners
guarantee, the no-collision-with-UK-sort-code guarantee, the SSN-not-misread
guard, per-field dedupe, the fixture, and the clean-file no-routing-number
guarantee. README gained a "Canadian routing number leak detection" section and
the PII type lists were updated. No new dependencies (stdlib `re` only).

**What:** The pii check covered SSN, payment card (PAN), IBAN, ISIN, CUSIP,
SEDOL, LEI, BIC, US account number, US ABA routing number, and the UK sort code.
The Canadian routing number is the **Canadian** domestic routing code — the
`TTTTT-III` MICR value that identifies a branch transit and a financial
institution and that drives a domestic Interac e-Transfer / EFT / pre-authorized
debit. A routing number echoed into a transaction memo discloses *which Canadian
bank and branch* routes a customer's account; paired with a leaked account number
it is the exact data a Canadian PAD-fraud or account-takeover attacker needs,
making the free-text routing-number echo the natural domestic-routing companion
to the already-shipped ABA routing-number and UK sort-code detectors. It
completes the North-American + UK domestic-routing dimension: US (ABA), UK (sort
code), and now Canada (routing number).

**Research grounding:** The Canadian routing number's `TTTTT-III` MICR structure
and the Payments Canada institution-number assignment ranges are public and
documented. The only arithmetic validation is the individual bank's
account-modulus check, which requires the paired account number and a per-bank
weight table — out of scope for a single self-contained identifier — so the
detector gates on the MICR structure plus the assigned institution number, with
the hyphenated 5-3 presentation itself the precision lever against coincidental
digit runs. ~20 lines of Python with no new dependency.

**Estimated tokens:** 35–50K

---

## Rank 19 — US ITIN Leak Detection, area + IRS-middle-group gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 21)

**Pivot note:** Ranks 1–18 were all shipped, so this rotation did a fresh gap
analysis (codebase read + 2026 financial-PII landscape research). The pii check
covered SSN, email, PAN, IBAN, ISIN, CUSIP, SEDOL, LEI, BIC, UK sort code,
Canadian routing, and US account/routing — but the **US ITIN** was both a
coverage gap *and* a precision bug: an ITIN is SSN-shaped (`NNN-NN-NNNN`), so the
existing SSN detector silently mislabelled every leaked ITIN as `ssn`. The ITIN
is direct US tax PII issued to the exact non-citizen / resident-alien population
a fintech serves, and it carries a clean public structural gate, so it was the
highest-value unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_itin_valid()` (gates on area
`900`–`999` — an SSN area never begins with `9`, the clean separator — plus the
IRS-assigned middle-group ranges `50`–`65`/`70`–`88`/`90`–`92`/`94`–`99`, with
the reserved gaps `66`–`69`/`89`/`93` rejected) and `_redact_itin()`. A new
`itin` (critical) finding runs **before** the SSN detector in both `_scan_text`
and `_scan_secid`, sharing the `ssn` dedupe namespace so a valid ITIN is reported
once as `itin` while a genuine SSN (area not `9XX`) falls through to the existing
`ssn` finding unchanged. Evidence is redacted to `9XX-XX-XXXX`. New fixture
`tests/fixtures/itin-leak.ofx` (two valid ITINs in two fields + one real SSN) and
27 new tests cover the validator (all four middle ranges + boundaries, reserved
gaps, non-9XX areas, garbage, stripped-digit behaviour), free-text detection,
the itin-not-ssn precision guarantee, the ssn-still-reported guarantee, the
reserved-middle non-detection guard, per-field dedupe, the fixture, and the
clean-file guard. README gained an ITIN section and the type lists were updated.
The SARIF mapping auto-generates the `pii/itin` rule with no changes. No new
dependencies (stdlib `re` only). Test count 403 → 430.

**Research grounding:** IRS Publication 4757 / IRM 3.21.263 — ITIN area is
900-999 and the middle group is restricted to the assigned ranges above, with
`89`/`93` reserved. Public, dependency-free, ~15 lines of Python.

**Estimated tokens:** 30–50K

---

## Rank 20 — Australian BSB Code Leak Detection, NNN-NNN structure + assigned bank-prefix gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 22)

**Pivot note:** Ranks 1–19 were all shipped. A fresh codebase read confirmed the
pii check covered the US (SSN, ITIN, ABA routing, account number), the UK (sort
code, SEDOL), Canada (routing number), Europe (IBAN), and the global securities /
entity / bank identifiers (ISIN, CUSIP, LEI, BIC) — but had **no domestic
routing detector for Australia**, a major English-speaking fintech market with a
distinctive, well-documented routing code. The Australian **BSB
(Bank-State-Branch)** code is the direct domestic-routing companion to the
already-shipped ABA / UK sort code / Canadian routing detectors, and it carries a
clean public structural gate, so it was the highest-value unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_au_bsb_valid()` (gates on the
`NNN-NNN` hyphenated 3-3 shape plus the assigned AusPayNet bank-prefix ranges
`01`–`19` / `20`–`79` / `80`–`89`, rejecting the unassigned `00` and the reserved
`90`–`99`) and `_redact_au_bsb()` (evidence redacted to the leading bank pair,
`06X-XXX`). A new `au_bsb` (high) finding runs in `_scan_text` alongside the other
hyphenated routing detectors. Its 3-3 split is distinct from the SSN's 3-2-4, the
UK sort code's 2-2-2, and the Canadian routing number's 5-3, so the four
hyphenated detectors never collide, and the hyphen keeps it clear of the
contiguous account / routing / card scanners. New fixture
`tests/fixtures/au-bsb-leak.ofx` (two valid BSBs in two memos + one out-of-range
`000-123` decoy) and 37 new test cases cover the validator (all three prefix
ranges + boundaries, the reserved/unassigned prefixes, wrong-shape and garbage
input), free-text detection, redaction, the decoy / zero-prefix / contiguous-run
non-detection guards, non-collision with the digit scanners and the other
hyphenated codes, the SSN non-misread guard, per-field dedupe, the fixture, and
the clean-file guard. README gained an Australian BSB section and the type lists
were updated. The SARIF mapping auto-generates the `pii/au_bsb` rule with no
changes. No new dependencies (stdlib `re` only). Test count 430 → 467.

**Research grounding:** AusPayNet (Australian Payments Network, formerly APCA)
BSB administration — a BSB is a six-digit `NNN-NNN` code whose leading two digits
are the assigned bank/institution code, with `00` unassigned and `90`–`99`
reserved. Public, dependency-free, ~15 lines of Python. It is the value a BECS
direct-entry / PayTo payment routes against, paired with an account number.

**Estimated tokens:** 30–50K

---

## Rank 21 — Indian IFSC Code Leak Detection, BBBB0BRANCH structure gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 23)

**Pivot note:** Ranks 1–20 were all shipped, and the originally-suggested R23
candidate (IBAN) was confirmed already implemented by a codebase read. A fresh
read of `checks/pii.py` showed the pii check covered the US (SSN, ITIN, ABA
routing, account number), the UK (sort code, SEDOL), Canada (routing number),
Australia (BSB), Europe (IBAN), and the global securities / entity / bank
identifiers (ISIN, CUSIP, LEI, BIC) — but had **no domestic routing detector for
India**, the world's largest real-time-payments market by volume (UPI). The
Indian **IFSC (Indian Financial System Code)** is the direct domestic-routing
companion to the already-shipped ABA / UK sort code / Canadian routing / Australian
BSB detectors, and it carries an exceptionally clean public structural gate (a
mandatory reserved zero in the fifth position), so it was the highest-value
genuinely-unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_ifsc_valid()` (gates on the exact
11-char `BBBB0BRANCH` shape: four-letter bank code, the mandatory reserved `0` in
the fifth position, and a six-char alphanumeric branch code) and `_redact_ifsc()`
(evidence redacted to the leading four-letter bank code, `SBINXXXXXXX`). A new
`ifsc` (high) finding runs in `_scan_text` before the contiguous-digit scanners,
reserving the branch digit run under the account/card/routing namespaces so a
slice of the same leak is never re-reported. The regex is upper-case-only and the
mandatory fifth-position zero is the dominant precision lever; the structure is
distinct from a BIC (first six chars all letters) and from the hyphenated routing
codes, so the detectors never collide. New fixture
`tests/fixtures/ifsc-leak.ofx` (two valid IFSCs in two memos + one no-reserved-zero
`HDFCX001234` decoy) and 29 new test cases cover the validator (real RBI bank
codes, alphanumeric and all-letter branch codes, lower-case acceptance, the
no-zero / short / long / non-letter-prefix / non-alnum-branch rejections, garbage
input), free-text detection, redaction, the no-reserved-zero non-detection guard,
non-collision with the digit scanners and the BIC detector, per-field dedupe, the
fixture, and the clean-file guard. README gained an Indian IFSC section and the
type lists were updated. The SARIF mapping auto-generates the `pii/ifsc` rule with
no changes. No new dependencies (stdlib `re` only). Test count 467 → 496.

**Research grounding:** Reserve Bank of India IFSC specification — an IFSC is an
11-character alphanumeric code, `BBBB0BRANCH`: the first four characters are the
bank code, the fifth is `0` (reserved for future use), and the last six are the
branch code. Public, dependency-free, ~10 lines of Python. It is the value a
NEFT / RTGS / IMPS / UPI transfer routes against, paired with an account number.

**Estimated tokens:** 30–50K

---

## Rank 22 — Mexican CLABE Leak Detection, 18-digit structure + mod-10 control-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 24)

**Pivot note:** Ranks 1–21 were all shipped. The suggested R24 candidates were
the **Mexican CLABE** and the **Japanese Zengin** bank codes. A fresh read of
`checks/pii.py` confirmed neither was present. The CLABE was chosen over the
Zengin code: a CLABE carries a public, self-contained mod-10 control digit (a
real arithmetic checksum, on a par with the IBAN / ABA / Luhn-gated detectors
already shipped), whereas a Japanese Zengin code (4-digit bank + 3-digit branch)
is short, has no self-contained check digit, and the bare 4/3-digit runs are too
collision-prone to detect with the precision ferryman holds itself to. The CLABE
is the highest-value, highest-precision unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_clabe_valid()` (gates on the
18-digit shape, a non-zero three-digit bank code — `000` is never assigned — and
the public mod-10 weighted control digit: each of the first 17 digits times the
repeating weights `(3, 7, 1)`, each product taken mod 10, summed, control digit
`(10 - sum mod 10) mod 10`) and `_redact_clabe()` (evidence redacted to the
leading three-digit bank code, `002XXXXXXXXXXXXXXX`). A new `clabe` (high)
finding runs in `_scan_text` **before** the credit-card (13–19 digit) and the
account-number (8+ digit) scanners — a CLABE is a contiguous 18-digit run, so
unlike the hyphenated routing codes it would otherwise be claimed by those
scanners — and reserves the run under the `credit_card` / `account_number` /
`routing_number` dedupe namespaces so the same leak is never double-counted. An
18-digit run that fails the control digit is not a CLABE but still falls through
to the `account_number` finding, so no leak is silently dropped. New fixture
`tests/fixtures/clabe-leak.ofx` (two valid CLABEs in two memos + one
wrong-control-digit decoy) plus 25 new test cases cover the validator (real-format
CLABEs across several bank codes, wrong-control-digit / zero-bank-code / all-ones
/ sequential rejects, wrong-length and garbage guards), free-text detection,
redaction, the wrong-control-digit and zero-bank-code non-detection guards, the
no-collision-with-digit-scanners guarantee, the invalid-CLABE-still-an-account
guarantee, the no-interference-with-other-identifiers guard, per-field dedupe,
the fixture, and the clean-file guard. README gained a Mexican CLABE section and
the type lists were updated. The SARIF mapping auto-generates the `pii/clabe`
rule with no changes. No new dependencies (stdlib `re` only). Test count
496 → 521.

**Research grounding:** Banxico CLABE specification — an 18-digit code,
`BBBPPPNNNNNNNNNNNC`: a three-digit bank/institution code, a three-digit
branch/plaza code, an eleven-digit account number, and one control digit. The
control digit is a public mod-10 weighted check (weights `3,7,1` repeating, each
product reduced mod 10) — public, dependency-free, ~12 lines of Python. It is the
single value needed to route a domestic SPEI transfer into an account, so a
free-text CLABE echo is a reportable Mexican bank-account disclosure.

**Estimated tokens:** 30–50K

---

## Rank 23 — South Korean Giro Number Leak Detection, NNNNN-NN structure + non-zero payee block + mod-10 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 25)

**Pivot note:** Ranks 1–22 were all shipped. The suggested R23 candidates were
the **South Korean Giro/Bank code** and the **South African SWIFT branch code**.
A fresh read of `checks/pii.py` confirmed neither was present. The South Korean
Giro number was chosen over the South African option: the South African
domestic identifier is either a SWIFT/BIC branch code (which collides with the
already-shipped Rank 16 BIC detector) or the bare six-digit universal branch
code (which has no self-contained check digit — the same precision problem that
got the Japanese Zengin code rejected in Rotation 24). The Korean Giro number,
by contrast, carries a public, self-contained **mod-10 weighted check digit**
(weights `3,1,3,1,3,1` over the six-digit payee block), and its canonical
**hyphenated `NNNNN-NN` (5-2) bill presentation** is structurally distinct from
every existing hyphenated detector — so it clears ferryman's precision bar with
both a structural gate and an arithmetic checksum, on a par with the IBAN / ABA /
Luhn / CLABE-gated identifiers. It is the highest-value, highest-precision
genuinely-unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_kr_giro_valid()` (gates on the
exact `NNNNN-NN` shape: five digits, a hyphen, two digits; a non-zero six-digit
payee block — `000000` is never a live payee; and the public mod-10 weighted
check digit: each of the first six digits times the repeating weights
`(3, 1, 3, 1, 3, 1)`, summed, check digit `(10 - sum mod 10) mod 10`, which the
seventh digit must equal) and `_redact_kr_giro()` (evidence redacted to the
leading two digits, `10XXX-XX`). A new `kr_giro` (high) finding runs in
`_scan_text`. The hyphenated 5-2 shape is distinct from any contiguous digit run
(so it never competes with the card / account / routing scanners) and from every
other hyphenated detector — the SSN's 3-2-4, the UK sort code's 2-2-2, the
Canadian routing number's 5-3, and the Australian BSB's 3-3 — so the five
hyphenated detectors never collide (a CA routing token `12345-003` is a 5-3 split
and is excluded by the trailing non-digit lookaround). New fixture
`tests/fixtures/kr-giro-leak.ofx` (two valid Giro numbers in two memos + one
wrong-check-digit `10005-21` decoy) plus 29 new test cases cover the validator
(real-format Giro numbers across several payee blocks, wrong-check-digit /
zero-payee-block / coincidental-token rejects, wrong-split / non-numeric /
double-hyphen / short-tail garbage guards), free-text detection, redaction, the
wrong-check-digit and zero-payee-block non-detection guards, the
no-collision-with-digit-scanners guarantee, the no-collision-with-other-
hyphenated-detectors guarantee, the no-interference-with-other-identifiers guard,
per-field dedupe, the fixture, and the clean-file guard. README gained a South
Korean Giro section and the type lists were updated. The SARIF mapping
auto-generates the `pii/kr_giro` rule with no changes. No new dependencies
(stdlib `re` only). Test count 521 → 550.

**Research grounding:** Korea Financial Telecommunications & Clearings Institute
Giro (지로) system — a Giro number is the seven-digit payee-routing code printed
on a domestic utility / tax / insurance bill, written `NNNNN-NN` (a six-digit
payee/biller block plus one trailing mod-10 weighted check digit). It is the
value a domestic Giro bill payment is routed against, so a free-text Giro echo is
a reportable South Korean biller-routing disclosure. Public, dependency-free,
~12 lines of Python.

**Estimated tokens:** 30–50K

---

## Rank 24 — Thai National ID / PromptPay Proxy-ID Leak Detection, N-NNNN-NNNNN-NN-N structure + 1-8 category digit + mod-11 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 26)

**Pivot note:** Ranks 1–23 were all shipped. The suggested R24 candidates were
the **South African IBAN** and the **Thai PromptPay ID**. A fresh read of
`checks/pii.py` confirmed neither was present (no `th_natid`, no `ZA` IBAN
handling beyond the generic gate). The South African candidate was **rejected as
unimplementable**: South Africa does not participate in the IBAN system at all —
there is no `ZA` country code in the ISO 13616 registry and no South African IBAN
to detect, so a "South African IBAN" detector would be fabricated. (South
Africa's real domestic routing identifier is a six-digit universal branch code
with no self-contained check digit — the same precision problem that got the
Japanese Zengin code and the bare South African branch code rejected in earlier
rotations.) The **Thai PromptPay proxy id** was chosen: the most common PromptPay
proxy id is the 13-digit Thai national ID, which carries a public, self-contained
**mod-11 weighted check digit** (weights 13…2 over the first twelve digits) plus
a structurally-constrained 1-8 category digit, and its canonical card
presentation `N-NNNN-NNNNN-NN-N` (1-4-5-2-1 split) is structurally distinct from
every existing hyphenated detector — so it clears ferryman's precision bar with
both a structural gate and an arithmetic checksum, on a par with the IBAN / ABA /
Luhn / CLABE / Giro-gated identifiers. It is the highest-value, highest-precision
genuinely-unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_th_natid_valid()` (gates on the
exact `N-NNNN-NNNNN-NN-N` 1-4-5-2-1 shape; a 1-8 category digit — `0` and `9`
are never issued first digits; and the public mod-11 weighted check digit: each
of the first twelve digits times the descending weights `13, 12, … , 2`, summed,
check digit `(11 - sum mod 11) mod 10`, which the thirteenth digit must equal)
and `_redact_th_natid()` (evidence redacted to the leading category digit,
`1-XXXX-XXXXX-XX-X`). A new `th_natid` (high) finding runs in `_scan_text`
**before** the credit-card scanner: the national ID's single-dash separators read
as the conventional digit grouping, so the whole token also satisfies the
13-19-digit card matcher — exactly the CLABE situation — so we check it first and
reserve the compact 13-digit run under the `credit_card` / `account_number` /
`routing_number` dedupe namespaces so the same leak is never double-counted. The
hyphenated 1-4-5-2-1 split is distinct from every other hyphenated detector — the
SSN's 3-2-4, the UK sort code's 2-2-2, the Canadian routing number's 5-3, the
Australian BSB's 3-3, and the South Korean Giro's 5-2 — so the six hyphenated
detectors never collide. New fixture `tests/fixtures/th-natid-leak.ofx` (two
valid national IDs in two memos + one wrong-check-digit `1-1017-00522-00-7`
decoy) plus 30 new test cases cover the validator (real-format IDs across several
category digits, wrong-check-digit / bad-category / coincidental-token rejects,
contiguous / wrong-split / non-numeric / extra-group / double-hyphen garbage
guards), free-text detection, redaction, the wrong-check-digit and
bad-category-digit non-detection guards, the no-collision-with-digit-scanners
guarantee (the card-reservation test), the no-collision-with-other-hyphenated-
detectors guarantee, the no-interference-with-other-identifiers guard, per-field
dedupe, the fixture, and the clean-file guard. README gained a Thai national ID /
PromptPay section and the type lists were updated. The SARIF mapping
auto-generates the `pii/th_natid` rule with no changes. No new dependencies
(stdlib `re` only). Test count 550 → 580.

**Research grounding:** Thai national identification number
(เลขประจำตัวประชาชน) — a 13-digit number printed `N-NNNN-NNNNN-NN-N` on every
Thai ID card, where the leading digit is the registration category (1-8) and the
final digit is a public mod-11 weighted check digit. Under the Bank of Thailand
PromptPay scheme it is the most common payee "proxy id" an instant interbank
transfer is routed against (the alternative proxies being a mobile number or an
e-wallet id), so a free-text national-ID echo discloses the exact value needed to
push funds to that person — a reportable Thai PII / payment-routing disclosure.
Public, dependency-free, ~12 lines of Python.

**Estimated tokens:** 30–50K

---

## Rank 25 — Brazilian CPF / Pix Key Leak Detection, NNN.NNN.NNN-NN structure + all-same-digit rejection + dual mod-11 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 27)

**Pivot note:** Ranks 1–24 were all shipped. The R25 candidates were the
**Indonesian NIK** and the **Brazilian CPF**. A fresh read of `checks/pii.py`
confirmed neither was present (no `br_cpf`, no `nik`, no Brazilian/Indonesian
handling). The **Indonesian NIK was rejected on the precision bar**: an NIK is a
16-digit contiguous run (province/regency/district codes + a `DDMMYY` birthdate,
with `+40` added to `DD` for females, + a daily sequence number) with **no
self-contained check digit** — its only gates would be a region table and a date
parse on a contiguous digit run, which collides head-on with the generic
account-number scanner (`\d{8,}`) and gives no arithmetic checksum, the same
precision problem that got the Japanese Zengin code and the bare branch codes
rejected in earlier rotations. The **Brazilian CPF was chosen**: it carries TWO
public, self-contained **mod-11 weighted check digits**, plus the standard
all-same-digit placeholder rejection, and its canonical card / Pix-receipt
presentation `NNN.NNN.NNN-NN` (3.3.3-2 split) is the **only** detector that uses
`.` separators — so it is structurally distinct from every existing hyphenated
detector and from any contiguous digit run. It clears ferryman's precision bar
with both a unique structural gate and a real double checksum, on a par with the
IBAN / ABA / Luhn / CLABE / Giro / national-ID-gated identifiers. It is the
highest-value, highest-precision genuinely-unimplemented item.

**Status:** Shipped. `checks/pii.py` gained `_br_cpf_valid()` (gates on the exact
`NNN.NNN.NNN-NN` 3.3.3-2 dotted-and-dashed shape — validated structurally, not
only in the regex, so a contiguous / hyphenated / wrong-split run is rejected by
the helper itself; an all-same-digit rejection for the eleven repeated-digit
placeholders that pass the arithmetic but are invalid CPFs; and the two public
mod-11 weighted check digits — the first over the first nine digits with weights
`10…2`, the second over the first ten with weights `11…2`, each
`(0 if r<2 else 11-r)` for `r = sum mod 11`, which the respective check digit must
equal) and `_redact_br_cpf()` (evidence redacted to the leading block,
`111.XXX.XXX-XX`). A new `br_cpf` (high) finding runs in `_scan_text` **before**
the credit-card scanner and reserves the compact 11-digit run under the
`account_number` / `routing_number` dedupe namespaces (the dotted presentation
already breaks the contiguous run, but the reservation keeps the
no-double-counting guarantee explicit). The dotted-and-dashed 3.3.3-2 presentation
is the only `.`-separated detector, so it never collides with the SSN's 3-2-4, the
UK sort code's 2-2-2, the Canadian routing number's 5-3, the Australian BSB's 3-3,
the South Korean Giro's 5-2, or the Thai national ID's 1-4-5-2-1. New fixture
`tests/fixtures/br-cpf-leak.ofx` (two valid CPFs in two memos + one
wrong-check-digit `111.444.777-34` decoy) plus 29 new test cases cover the
validator (real-format CPFs, wrong-check-digit / repeated-digit-placeholder /
off-by-one rejects, contiguous / hyphenated / wrong-split / non-numeric /
double-separator garbage guards), free-text detection, redaction, the
wrong-check-digit and repeated-digit-placeholder non-detection guards, the
no-collision-with-digit-scanners guarantee, the no-collision-with-other-separated-
detectors guarantee, the no-interference-with-other-identifiers guard, per-field
dedupe, the fixture, and the clean-file guard. README gained a Brazilian CPF / Pix
section and the type lists were updated. The SARIF mapping auto-generates the
`pii/br_cpf` rule with no changes. No new dependencies (stdlib `re` only).

**Research grounding:** Brazilian CPF (Cadastro de Pessoas Físicas) — an 11-digit
individual taxpayer registry number printed `NNN.NNN.NNN-NN`, where the final two
digits are public mod-11 weighted check digits. Under the Banco Central do Brasil
Pix scheme the CPF is the most common payee "chave" (key) an instant interbank
transfer is routed against (the other keys being a phone number, an email, or a
random EVP key), so a free-text CPF echo discloses the exact value needed to push
funds to that person — a reportable Brazilian PII / payment-routing disclosure.
The eleven repeated-digit values pass the checksum arithmetic but are well-known
invalid placeholder CPFs, so the official validator (and ferryman) rejects them.
Public, dependency-free, ~25 lines of Python.

**Estimated tokens:** 30–50K

---

## Rank 26 — Mexican CURP Leak Detection, 18-char structure + birth date + registered state code + mod-10 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 28)

**Pivot note:** Ranks 1–25 were all shipped. The R26 candidates named in the
rotation brief were the **Mexican CURP** and the **Russian INN / SNILS**. A fresh
read of `checks/pii.py` confirmed none of `curp`, `inn`, or `snils` was present.
All three carry a verifiable checksum, so the choice came down to PII value and
collision-precision:

- **Russian INN (12-digit individual)** — dual weighted mod-11 check digits, a
  genuinely strong arithmetic gate, *but* it is a **contiguous 12-digit run** that
  collides head-on with the generic account-number scanner (`\d{8,}`) and the
  card matcher (13–19 digits is close), and a bare 12-digit number carries no
  structural shape beyond the checksum — the same low-distinctiveness problem that
  kept the Indonesian NIK out at R25. The legal-entity 10-digit INN is even
  weaker (single check digit).
- **Russian SNILS** — 9 digits + a 2-digit weighted mod-101 check, again a
  contiguous run with the same digit-scanner-collision problem, and the
  ">100 ⇒ 00 / ==100 ⇒ 00" edge-case rule has documented variants.
- **Mexican CURP was chosen.** It is the strongest *identity*-PII item of the
  three: the value **encodes the person** (four name initials, full birth date,
  sex, birth state are all readable from the code itself), so a leak discloses a
  named individual, not merely an account. Crucially for ferryman's precision bar
  it has **three independent structural gates on top of the checksum** — the fixed
  18-character `AAAA NNNNNN S EE CCC X D` layout, a real embedded `YYMMDD` birth
  date, and a **registered two-letter state code** (the 31 states + `DF` + `NE`),
  the last of which is the dominant precision lever exactly as the BIC's ISO
  3166-1 country gate is — plus the public RENAPO **mod-10 check digit** over the
  base-37 alphabet. Because a CURP **leads with four letters** it is structurally
  distinct from the Mexican CLABE (18 *digits*), so the two 18-character Mexican
  identifiers never collide, and its only contiguous digit run (the six-digit
  birth date) is too short for the account / routing / card scanners. It clears
  the precision bar on structure *and* checksum — strictly stronger than the bare
  Russian contiguous-digit candidates.

**Status:** Shipped. `checks/pii.py` gained `_curp_check_digit()` (the RENAPO
mod-10 over the base-37 alphabet `0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ` with
descending positional weights `18…2`), `_curp_valid()` (gates on the exact
18-char `AAAA NNNNNN S EE CCC X D` shape — validated structurally in the helper,
not only the regex; a real embedded `MM`/`DD` birth date; the registered
`_CURP_STATES` two-letter code in positions 12–13; and the mod-10 check digit),
and `_redact_curp()` (evidence redacted to the four leading name initials,
`HEGGXXXXXXXXXXXXXX`). A new `curp` (high) finding runs in `_scan_text`
immediately after the CLABE block and reserves every embedded digit run under the
`account_number` / `credit_card` / `routing_number` dedupe namespaces (the
six-digit date can never reach the 8+/9/13+ scanners, but the reservation keeps
the no-double-counting guarantee explicit, exactly as the IFSC / LEI scans do).
The matcher `_CURP_RE` is **upper-case only** (the precision lever, mirroring the
BIC / IFSC gates), so a lower-case run in prose is left for the prose. New fixture
`tests/fixtures/mx-curp-leak.ofx` (two valid CURPs in two memos + one
wrong-check-digit `HEGG560427MVZRRL09` decoy) plus 27 new test cases cover the
validator (real-structure CURPs incl. a foreign-born `NE` + letter-homoclave case,
wrong-check-digit / bad-state / impossible-month / impossible-day / bad-sex /
digit-name-block rejects, length / wrong-position-type / non-letter-name garbage
guards), free-text detection, redaction, the wrong-check-digit and bad-state
non-detection guards, the lower-case non-detection guard, the
no-collision-with-CLABE guarantee, the no-collision-with-digit-scanners guarantee,
the no-interference-with-other-identifiers guard, per-field dedupe, the fixture,
and the clean-file guard. README gained a Mexican CURP section and the type lists
were updated. The SARIF mapping auto-generates the `pii/curp` rule with no
changes. No new dependencies (stdlib `re` only). Full suite: 636 passing.

**Research grounding:** Mexican CURP (Clave Única de Registro de Población) — the
18-character RENAPO-issued population-registry key: four name letters, a `YYMMDD`
birth date, a sex marker (`H`/`M`), a two-letter birth-state code, three internal
consonants, a homoclave (a disambiguator — a digit for people born before 2000, a
letter from 2000 onward), and a mod-10 check digit computed over the first 17
characters with the base-37 alphabet and descending weights. Unlike a routing /
account number a CURP is direct *identity* PII — the value names the person — so a
free-text CURP echo is a reportable Mexican PII disclosure. Public,
dependency-free, ~30 lines of Python.

**Estimated tokens:** 30–50K

---

## Rank 27 — South Korean RRN (Resident Registration Number) Leak Detection, YYMMDD-SNNNNNN structure + birth date + mod-11 check-digit gated (HIGH signal, low effort) — ✅ IMPLEMENTED (2026-05-29, Phase 2 Rotation 29)

**Pivot note:** Ranks 1–26 were all shipped. The R27 rotation brief named the
**South Korean RRN** and the **Polish PESEL** as the two candidates, with the
Russian INN / SNILS already deferred (low distinctiveness — contiguous digit runs
that collide with the generic `\d{8,}` account scanner). A fresh read of
`checks/pii.py` confirmed neither `kr_rrn`/`rrn` nor `pesel` was present. Both
carry a verifiable checksum and both are direct *identity* PII, so the choice came
down to ferryman's dominant precision criterion — **structural distinctiveness
beyond the checksum**:

- **Polish PESEL was rejected.** It is an 11-digit **contiguous run** (no
  separator in its canonical presentation), so it collides head-on with the
  account-number scanner (`\d{8,}`) and is close to the card matcher — the exact
  low-distinctiveness problem that deferred the Russian INN at R26 and the
  Indonesian NIK at R25. Its only structural shape beyond the mod-10 check digit is
  an embedded `YYMMDD` birth date (with a month-offset century encoding), which the
  RRN also carries. A contiguous 11-digit token that happens to encode a plausible
  date and pass a single weighted checksum is not distinctive enough for
  ferryman's precision bar.
- **South Korean RRN was chosen.** Its canonical printed form is the hyphenated
  **`YYMMDD-SNNNNNN` (6-7 split)** — a structural shape that is distinct from
  *every* existing detector: the SSN's 3-2-4, the UK sort code's 2-2-2, the
  Canadian routing number's 5-3, the Australian BSB's 3-3, the South Korean Giro's
  5-2, and the Thai national ID's 1-4-5-2-1. The hyphen breaks the token into a
  six- and a seven-digit piece, neither of which the 8+/9/13+ digit scanners
  match, so the detector never competes with the contiguous-digit scanners — the
  precise lever PESEL lacks. On top of the distinctive shape it carries a real
  embedded `YYMMDD` birth date and the public **mod-11 weighted check digit**
  (weights `2,3,4,5,6,7,8,9,2,3,4,5`, check `= (11 − (sum mod 11)) mod 10`). It is
  also the most sensitive identity PII of the two: the RRN is the master personal
  identifier in Korea (banking, medical, tax, employment all key off it), so a
  free-text RRN echo discloses a named individual, not merely an account.
  Structure *and* checksum clear the precision bar — strictly stronger than the
  contiguous PESEL.

**Worker decision (post-2020 check-digit note):** South Korea stopped encoding the
classic mod-11 check digit into *newly issued* RRNs from October 2020 onward (the
last seven digits of a new RRN are now randomized). The classic checksum therefore
gates pre-2020 RRNs at full strength and is only a partial gate for post-2020
numbers. This was judged acceptable and the checksum was kept as a gate because (a)
the overwhelming majority of RRNs in circulation — and thus in legacy bank
statements, the data ferryman scans — predate 2020, (b) ferryman's other two gates
(the highly distinctive 6-7 hyphenated shape and the embedded real birth date)
already clear the precision bar on their own, and (c) keeping the checksum can only
*reduce* false positives, never increase them, on the pre-2020 corpus. Documented
here and in the validator's docstring rather than surfaced to the operator.

**Status:** Shipped. `checks/pii.py` gained `_kr_rrn_valid()` (gates on the exact
`YYMMDD-SNNNNNN` 6-7 split — validated structurally in the helper, not only the
regex; a real embedded `MM`/`DD` birth date; and the mod-11 weighted check digit)
and `_redact_kr_rrn()` (evidence redacted to the single century/sex marker,
`XXXXXX-1XXXXXX`). A new `kr_rrn` (high) finding runs in `_scan_text` immediately
after the South Korean Giro block (logical grouping — both Korean) and reserves the
compact 13-digit run under the `credit_card` / `account_number` / `routing_number`
dedupe namespaces (the hyphen already breaks the run, but the reservation keeps the
no-double-counting guarantee explicit, exactly as the Thai national ID and CURP
scans do). The matcher `_KR_RRN_RE` is bounded by a non-digit/non-hyphen lookaround
so an RRN embedded in a longer digit-and-hyphen blob is not partially matched. New
fixture `tests/fixtures/kr-rrn-leak.ofx` (two valid RRNs in two memos + one
wrong-check-digit `900101-1123450` decoy) plus 31 new test cases cover the
validator (six valid RRNs spanning the citizen / foreign-resident century/sex
markers, wrong-check-digit / impossible-month / impossible-day / arbitrary-run
rejects, length / wrong-split / non-digit garbage guards), free-text detection,
redaction, the wrong-check-digit and bad-birth-date non-detection guards, the
no-collision-with-digit-scanners guarantee, the no-collision-with-other-hyphenated
detectors guarantee, the no-interference-with-other-identifiers guard, per-field
dedupe, the fixture, and the clean-file guard. README gained a South Korean RRN
section and the two type-summary lists were updated. The SARIF mapping
auto-generates the `pii/kr_rrn` rule with no changes. No new dependencies (stdlib
`re` only). Full suite: 667 passing.

**Research grounding:** South Korean RRN (주민등록번호) — the 13-digit
resident-registration number every Korean resident is issued: a `YYMMDD` birth
date, a century + sex marker (1-2 citizens born 1900s, 3-4 citizens born 2000s, 5-6
/ 7-8 foreign residents by century, 9-0 born 1800s), a region-of-registration
serial, and a mod-11 weighted check digit (classic algorithm; retired for newly
issued numbers from Oct 2020). Unlike a routing / account number an RRN is direct
*identity* PII — the value names the person's birth date and sex — and it is the
master personal identifier in Korea, so a free-text RRN echo is a reportable South
Korean PII disclosure. Public, dependency-free, ~30 lines of Python.

**Estimated tokens:** 30–50K

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
