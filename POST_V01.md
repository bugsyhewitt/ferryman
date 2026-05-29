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
