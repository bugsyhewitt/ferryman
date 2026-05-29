# ferryman

A security-focused scanner for **OFX (Open Financial Exchange)** files, built
for the bug-bounty fintech surface.

OFX is the format banks and brokerages use to export account data, and mature
parsers for it already exist. ferryman is **not** another parser. It is a
scanner that treats an OFX file as an attack surface and asks three questions:

- **Is this file trying to attack the parser that reads it?** XXE entity
  declarations, recursive entity-expansion (Billion Laughs) DoS chains,
  CDATA-terminator injection, SGML/XML format confusion, OFX v1 header
  injection / encoding mismatch, encoding tricks, oversized fields.
- **Is this file leaking PII it should not?** Email addresses, SSNs, ITINs (US
  tax IDs), payment-card numbers (PANs), IBANs, securities identifiers
  (ISIN/CUSIP/SEDOL),
  legal-entity identifiers (LEI), bank identifier codes (BIC/SWIFT), UK sort
  codes, Canadian routing numbers, Australian BSB codes, Indian IFSC codes,
  Mexican CLABE numbers, full
  account numbers, and routing numbers smuggled into free-text transaction names
  and memos.
- **Is this file anomalous?** Out-of-range posting dates, zero / sign-flipped /
  out-of-range transaction amounts, and other signs of tampering or a backend
  that accepts garbage.

Findings come out as structured JSON, ready to drop into a HackerOne report.

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/ferryman
cd ferryman
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

Run all checks against a file and get JSON findings:

```bash
ferryman --check all --format json statement.ofx
```

Options:

```
ferryman [--check {malformed,pii,anomaly,all}] [--format {json,text,h1md,sarif}]
         [--fail-on {info,low,medium,high,critical}] [--dir DIR]
         FILE [FILE ...]
```

- `--check` &mdash; which scan to run. Default `all`.
  - `malformed` &mdash; parser-confusion attacks (XXE, entity-expansion
    "Billion Laughs" DoS, CDATA injection, SGML/XML confusion, OFX v1 header
    injection / encoding mismatch, encoding tricks, oversized fields). Operates
    on raw bytes; never parses a hostile file.
  - `pii` &mdash; PII leaking into transaction free-text (email address, SSN,
    ITIN, payment-card number, IBAN, ISIN, CUSIP, SEDOL, LEI, BIC/SWIFT, UK sort
    code, Canadian routing number, Australian BSB code, Indian IFSC code, Mexican
    CLABE, account
    number, routing number), including investment memos and security ids.
    Evidence is always redacted before it leaves the tool.
  - `anomaly` &mdash; structurally valid but suspicious transactions
    (out-of-range dates; zero, sign-contradicting, or out-of-range transaction
    amounts; for investment statements, negative/implausible unit prices and
    negative quantities on non-sell transactions).
  - `all` &mdash; every check.
- `--format` &mdash; `json` (default), human-readable `text`, `h1md`
  (HackerOne-flavored markdown), or `sarif` (SARIF 2.1.0 for GitHub Code
  Scanning, VS Code, and SAST dashboards &mdash; see below).
- `--dir DIR` &mdash; scan every `*.ofx` file in `DIR` (non-recursive). Can be
  combined with positional `FILE` arguments.
- `--fail-on SEVERITY` &mdash; exit non-zero (`1`) when any finding is at or
  above `SEVERITY` (`info`, `low`, `medium`, `high`, or `critical`). Opt-in: a
  completed scan still exits `0` without this flag. Lets CI/CD pipelines gate on
  findings (see below).

Exit codes: `0` scan(s) completed and no `--fail-on` threshold met, `1`
`--fail-on` was set and a finding met or exceeded that severity, `2` usage
error, `3` a file could not be read (or `--dir` matched no files).

### Gating a pipeline on findings

By default ferryman exits `0` on any completed scan, so chaining it before an
upload would let a critical XXE through:

```bash
ferryman --check all statement.ofx && upload statement.ofx   # always uploads
```

`--fail-on` turns the scan into a gate. With `--fail-on high`, the chain only
proceeds when the file has no `high` or `critical` findings:

```bash
ferryman --check all --fail-on high statement.ofx && upload statement.ofx
```

In a CI step, a non-zero exit fails the job:

```yaml
- name: Scan exported OFX for leaks and parser attacks
  run: ferryman --check all --fail-on medium --dir ./exports/
```

The full report is still printed in every case &mdash; `--fail-on` changes only
the exit code, never the output.

### SARIF output for GitHub Code Scanning and IDEs

`--format sarif` emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
document &mdash; the standard interchange format for static-analysis results.
This lets ferryman findings surface natively in the GitHub **Security** tab, the
VS Code **Problems** panel, and SARIF-consuming SAST dashboards, alongside
professional security tooling.

```bash
ferryman --check all --format sarif statement.ofx > ferryman.sarif
```

In a GitHub Actions workflow, upload the file with the official action:

```yaml
- name: Scan OFX exports
  run: ferryman --check all --format sarif --dir ./exports/ > ferryman.sarif
- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ferryman.sarif
```

Mapping details: each `<check>/<type>` becomes a SARIF rule (`malformed/xxe`,
`pii/ssn`, ...). ferryman's five severities collapse to SARIF's coarser `level`
(`critical`/`high` &rarr; `error`, `medium` &rarr; `warning`, `low`/`info`
&rarr; `note`), but the exact ferryman severity is preserved in
`properties.severity` and reflected in the numeric `rank` so consumers order
findings the way ferryman does. When a finding carries a parseable line (the
malformed check does), a SARIF `region` with `startLine` is attached so the
result links to the right line. In multi-file / `--dir` mode every result's
`artifactLocation.uri` carries its source file.

### Batch scanning many files

Bug-bounty researchers typically receive a dump of many OFX files from a target.
ferryman accepts multiple files (shell globs expand naturally) or a whole
directory:

```bash
ferryman --check all *.ofx                    # every OFX in the cwd
ferryman --check all --dir ./statements/      # every *.ofx in a directory
ferryman --check all a.ofx b.ofx --dir ./more # positional files + a directory
```

A **single-file** invocation keeps the exact JSON/text/h1md shape documented
below (no envelope), so existing pipelines are unchanged. A **multi-file**
invocation (more than one file, or any use of `--dir`) wraps the per-file
results:

- `--format json` returns a `{"files": [ {<per-file result>}, ... ]}` envelope
  with a top-level `summary` carrying `file_count` and the combined `total`.
  Each entry under `files` is the same shape a single-file scan produces.
- `--format text` prints a one-line batch header followed by the compact
  per-file summary for each scanned file.
- `--format h1md` renders one combined HackerOne report, with the source file
  folded into each finding's `location` (e.g. `statements/a.ofx: line 4`) so
  attribution survives the merge.

```bash
$ ferryman --check all --format json --dir ./statements/
{
  "tool": "ferryman",
  "version": "0.1.0",
  "files": [
    { "tool": "ferryman", "file": "statements/a.ofx", "check": "all",
      "summary": { "total": 1, ... }, "findings": [ ... ] },
    { "tool": "ferryman", "file": "statements/b.ofx", "check": "all",
      "summary": { "total": 0, ... }, "findings": [] }
  ],
  "summary": { "file_count": 2, "total": 1 }
}
```

### Example: scan an XXE attempt

```bash
$ ferryman --check malformed --format json suspicious.ofx
{
  "tool": "ferryman",
  "version": "0.1.0",
  "file": "suspicious.ofx",
  "check": "malformed",
  "summary": { "total": 1, "by_severity": { "critical": 1 }, "by_type": { "xxe": 1 } },
  "findings": [
    {
      "check": "malformed",
      "type": "xxe",
      "severity": "critical",
      "message": "External entity declaration (SYSTEM) found -- classic XXE vector ...",
      "location": "line 4",
      "evidence": "<!ENTITY xxe SYSTEM \"file:///etc/passwd\"",
      "metadata": {}
    }
  ]
}
```

### Entity-expansion (Billion Laughs) detection

XXE-for-file-read and entity-expansion DoS are **separate** vulnerabilities and
ferryman reports them separately. While the `xxe` finding flags external
`SYSTEM` entities and DOCTYPE presence, the `entity_expansion` finding targets
the recursive [Billion Laughs](https://en.wikipedia.org/wiki/Billion_laughs_attack)
DoS chain &mdash; nested `<!ENTITY>` declarations that explode in memory when a
parser expands them.

A file is flagged `entity_expansion` (severity `critical`) when **both** hold:

1. It declares **3 or more** custom entities (`<!ENTITY ...>`), and
2. At least one entity body references **another declared entity** (the nested
   chain, e.g. `<!ENTITY c "&b;&b;">` where `b` is itself an entity).

Legitimate OFX defines zero custom entities, so flat or single declarations
never trip this check &mdash; only an actual recursive chain does. Detection is
pure regex over raw bytes; ferryman never hands the hostile file to an XML
parser:

```bash
$ ferryman --check malformed --format json entity-bomb.ofx
...
    {
      "check": "malformed",
      "type": "entity_expansion",
      "severity": "critical",
      "message": "Multiple entity declarations with nested cross-references found -- a recursive entity-expansion (Billion Laughs) DoS vector ...",
      "location": "line 4",
      "metadata": { "entity_count": 3 }
    }
```

**Remediation:** disable DTD/entity processing in the OFX/XML parser
(`resolve_entities=False`, and reject documents containing a DOCTYPE).

### OFX v1 SGML header injection / encoding mismatch

OFX v1 files open with a plaintext header block (`OFXHEADER:`, `DATA:`,
`VERSION:`, `ENCODING:`, `CHARSET:` …) terminated by a blank line, then the
SGML body. ferryman scans that header block on the raw bytes for three
parser-confusion vectors:

- **`header_injection`** (severity `high`) &mdash; a **second** `OFXHEADER:`
  block smuggled into the document body after the legitimate header/body
  separator. A parser that re-reads headers can be steered to a different
  encoding or version mid-stream &mdash; a header-injection / smuggling vector.
- **`encoding_mismatch`** (severity `medium`) &mdash; an `ENCODING` value
  outside the OFX-allowed set (`USASCII`, `UTF-8`, `UNICODE`) or a `CHARSET`
  that is neither a numeric code page (e.g. `1252`) nor a recognised name.
  A mismatched declaration provokes parser disagreement over how to decode the
  body (e.g. declaring `UTF-8` over Windows-1252 bytes).
- **`encoding_mismatch`** (severity `medium`) &mdash; a non-printable control
  byte inside the header section, where only `KEY:VALUE` plaintext lines belong.

These checks only fire on OFX v1 documents (those that open with `OFXHEADER:`);
pure-XML OFX v2 files are not affected.

```bash
$ ferryman --check malformed --format text crafted-v1.ofx
  [HIGH] malformed/header_injection @ line 12: A second OFX v1 SGML header block (OFXHEADER:) appears inside the document body ...
  [MEDIUM] malformed/encoding_mismatch @ line 5: OFX v1 ENCODING header declares 'WINDOWS-1252', which is outside the OFX-allowed set ...
```

**Remediation:** parse the OFX v1 header block exactly once, reject any
`OFXHEADER:` occurrence in the body, and validate `ENCODING`/`CHARSET` against
the OFX-allowed set before decoding.

### Transaction amount anomalies

OFX transaction amounts (`TRNAMT`) are decimal strings, and a crafted file can
smuggle business-logic / negative-balance probes into them. The **anomaly**
check flags three `anomalous_amount` cases on bank and credit-card transactions:

- **Zero amount** (severity `high`) &mdash; a posted transaction that moves no
  money. A no-op posting that a backend nonetheless accepts is a business-logic
  anomaly.
- **Sign contradicts type** (severity `medium`) &mdash; a *positive* amount on a
  debit-type transaction (`DEBIT`, `PAYMENT`, `FEE`, …) or a *negative* amount on
  a credit-type transaction (`CREDIT`, `DEP`, `INT`, …). OFX's sign convention is
  debits-negative / credits-positive, so a flipped sign can invert a charge into
  a credit (or vice versa) downstream.
- **Out-of-range magnitude** (severity `medium`) &mdash; an absolute amount above
  $10,000,000, beyond any plausible retail-banking transaction; a classic
  out-of-range / overflow probe.

Normal postings &mdash; a `-42.00` debit or a `+1500.00` credit &mdash; respect
the sign convention and are never flagged. Non-finite values (`NaN`, `Inf`) are
left to the `malformed` check, which owns the "this field is garbage" verdict.

```bash
$ ferryman --check anomaly --format text crafted-amounts.ofx
  [HIGH] anomaly/anomalous_amount @ statement[0].transaction[0].amount (fitid 0001): Transaction of type DEBIT has a zero amount ...
  [MEDIUM] anomaly/anomalous_amount @ statement[0].transaction[1].amount (fitid 0002): Transaction of type DEBIT carries a positive amount, contradicting the OFX sign convention ...
```

**Remediation:** validate `TRNAMT` against the declared transaction type's sign
convention, reject zero-value postings, and bound the per-transaction magnitude
before applying the amount to a balance.

### Email-address leak detection

An email address is the most common piece of direct PII to leak through a
statement export &mdash; "personal data" under GDPR and "personal information"
under CCPA, and a textbook reportable disclosure when it surfaces in a field that
should carry only a transaction description. The **pii** check flags an
`email_address` finding (severity `high`) when a free-text **name or memo**
contains a string shaped like an email: a `local@domain` whose domain is a
dotted, registrable name ending in a top-level domain of at least two letters
(e.g. `john.doe@example.com`, `billing+stmt@sub.corp.co.uk`).

Unlike the numeric identifiers, an email needs no checksum: the `@` plus the
dotted, letter-TLD domain make it structurally unambiguous, so the detector is
high-precision with near-zero false positives. A bare `@handle` mention, a
domain with no TLD (`user@localhost`), or a one-character TLD is **not** flagged.
The address never leaves the tool intact &mdash; evidence is redacted to the
first character of the local part plus the domain (`j*******@example.com`,
`*@example.com`) so a reporter can tell two leaks apart without exfiltrating the
identity.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/email_address @ statement[0].transaction[0].name (fitid 0001): Email address leaking into a free-text field -- direct PII (GDPR/CCPA personal data) that should not travel in a statement export.
```

**Remediation:** never echo a customer's (or counterparty's) email address into a
statement export or transaction memo; keep contact details in structured,
access-controlled fields rather than free text.

### ITIN (US Individual Taxpayer Identification Number) leak detection

An [ITIN](https://en.wikipedia.org/wiki/Individual_Taxpayer_Identification_Number)
is the nine-digit tax-processing number the IRS issues to people who must file a
US tax return but are not eligible for an SSN &mdash; resident and non-resident
aliens, their spouses and dependents. It is **direct US tax PII**, and it shares
the SSN `NNN-NN-NNNN` presentation exactly, so a plain SSN-shaped match cannot
tell the two apart. ferryman now reports a valid ITIN as the distinct identifier
it is rather than mislabelling it `ssn`. The **pii** check flags an `itin`
finding (severity `critical`) when a free-text **name or memo** contains a string
that clears **two** public, dependency-free structural gates:

1. **area** &mdash; the first three digits are `900`&ndash;`999`. An SSN area
   number never begins with `9`, so the leading `9` is what cleanly separates an
   ITIN from a real SSN with no overlap;
2. **middle group** &mdash; the 4th&ndash;5th digits fall only in the
   IRS-assigned ranges `50`&ndash;`65`, `70`&ndash;`88`, `90`&ndash;`92`, or
   `94`&ndash;`99`. The gaps (`66`&ndash;`69`, `89`, `93`) are reserved for other
   IRS programs (`93` is the ATIN range) and are never assigned to a live ITIN,
   so an out-of-range middle group is never reported as an ITIN.

The ITIN detector runs **before** the SSN detector and shares its dedupe channel:
a value that clears both gates is reported once as `itin`, while a genuine SSN
(area not `9XX`) fails the area gate and falls through to the existing `ssn`
finding unchanged. The raw number never leaves the tool &mdash; evidence is
redacted to the ITIN shape (`9XX-XX-XXXX`). The same gate runs over investment
security ids, so an ITIN smuggled into a `SECID` is caught too.

```bash
$ ferryman --check pii --format text leak.ofx
  [CRITICAL] pii/itin @ statement[0].transaction[0].name (fitid 0001): US Individual Taxpayer Identification Number (ITIN, valid 9XX area and IRS-assigned middle group) leaking into a free-text field -- direct US tax PII.
```

**Remediation:** never echo a customer's ITIN (or any tax identifier) into a
statement export or transaction memo; keep tax IDs in structured,
access-controlled fields rather than free text.

### Payment-card (PAN) leak detection

A statement export should never carry a customer's full payment-card number, yet
a backend that echoes order or billing data into a transaction memo can leak one.
The **pii** check flags a `credit_card` finding (severity `critical`, PCI-DSS
sensitive) when a free-text field contains a **13&ndash;19 digit** run &mdash;
written plainly or in the conventional groups separated by spaces or hyphens
&mdash; that passes the [Luhn](https://en.wikipedia.org/wiki/Luhn_algorithm)
mod-10 checksum every major card network uses.

Gating on Luhn mirrors the ABA-checksum gate on routing numbers: a 16-digit run
that passes Luhn is a near-certain real PAN, while one that fails is almost
always a coincidental digit blob (a long order id or padded account number) and
falls through to the existing `account_number` heuristic instead of crying
"credit card." As always, the raw number never leaves the tool &mdash; evidence
is redacted to the card's shape (`XXXX XXXX XXXX XXXX`).

```bash
$ ferryman --check pii --format text leak.ofx
  [CRITICAL] pii/credit_card @ statement[0].transaction[0].name (fitid 0001): Payment-card number (passing the Luhn checksum) leaking into a free-text field -- PCI-DSS sensitive.
```

**Remediation:** never write a full PAN into a statement export; mask all but the
last four digits (`**** **** **** 1111`) at the source, per PCI-DSS.

### IBAN leak detection

International Bank Account Numbers (IBANs) are the European/global equivalent of a
US account + routing number rolled into one string &mdash; a direct, high-value
PII leak. The **pii** check flags an `iban` finding (severity `high`) when a
free-text field contains a string that clears **all three** public
[ISO&nbsp;13616](https://en.wikipedia.org/wiki/International_Bank_Account_Number)
gates:

1. **shape** &mdash; two-letter country code, two check digits, then an
   alphanumeric account body, written contiguously or in the conventional
   space-separated groups of four;
2. **country length** &mdash; the total length matches the registered length for
   the declared country (a `DE` IBAN is always 22 characters, a `GB` IBAN 22, a
   `NO` IBAN 15&hellip;); and
3. **mod-97 checksum** &mdash; the rearranged, letter-to-number-mapped value is
   `== 1 (mod 97)`.

Gating on country + length + mod-97 mirrors the ABA-checksum and Luhn gates: a run
that clears all three is a near-certain real IBAN, while a coincidental
alphanumeric blob fails one of them with overwhelming probability and is left to
the existing heuristics. The raw account body never leaves the tool &mdash;
evidence is redacted to the country code plus masked digits (`DEXX XXXX
XXXX...`).

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/iban @ statement[0].transaction[0].memo: International Bank Account Number (IBAN, valid country/length/mod-97 checksum) leaking into a free-text field.
```

**Remediation:** never echo a full IBAN into a statement export or transaction
memo; mask all but the country code and the last few characters at the source.

### ISIN leak detection

An [ISIN](https://en.wikipedia.org/wiki/International_Securities_Identification_Number)
(International Securities Identification Number, ISO&nbsp;6166) uniquely identifies a
security &mdash; the value that legitimately belongs in an OFX investment `SECID`.
When an ISIN instead leaks into a free-text **memo or transaction name**, it
discloses exactly which securities a customer holds &mdash; a brokerage-account
privacy leak that is reportable on its own in fintech bug-bounty programs. The
**pii** check flags an `isin` finding (severity `high`) when a free-text field
contains a string that clears **both** public gates:

1. **shape** &mdash; exactly twelve characters: a two-letter country code (or `XS`
   for international issues), a nine-character alphanumeric NSIN, and one trailing
   decimal check digit;
2. **check digit** &mdash; expanding each letter to its two-digit value
   (`A`=10&hellip;`Z`=35) and applying the [Luhn](https://en.wikipedia.org/wiki/Luhn_algorithm)
   (mod-10) checksum over the whole expanded string yields zero.

Gating on the ISO&nbsp;6166 check digit mirrors the ABA, Luhn, and IBAN gates: a run
that clears both is a near-certain real ISIN, while a coincidental alphanumeric
blob fails the check digit with overwhelming probability and is left to the
existing heuristics. The NSIN body and check digit never leave the tool &mdash;
evidence is redacted to the two-letter country/issuer prefix (`USXXXXXXXXXX`). An
ISIN sitting in its own `SECID` field is *not* flagged; only one bleeding into
free text is.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/isin @ statement[0].transaction[0].memo: International Securities Identification Number (ISIN, valid ISO 6166 check digit) leaking into a free-text field.
```

**Remediation:** never echo a security's ISIN into a statement memo or
transaction name; keep security identifiers in the structured `SECID` field where
they belong.

### CUSIP leak detection

A [CUSIP](https://en.wikipedia.org/wiki/CUSIP) is the nine-character US/Canada
securities identifier &mdash; the NSIN that forms the core of a US `ISIN` and the
value that legitimately belongs in an OFX investment `SECID`. Like an ISIN, a
CUSIP that leaks into a free-text **memo or transaction name** discloses which
securities a customer holds &mdash; a brokerage-account privacy leak reportable on
its own. The **pii** check flags a `cusip` finding (severity `high`) when a
free-text field contains a string that clears **both** public gates:

1. **shape** &mdash; exactly nine characters: an eight-character base (digits,
   letters `A`&ndash;`Z`, or the legacy specials `*` `@` `#`) plus one trailing
   decimal check digit. The base must contain at least one letter, so a purely
   numeric nine-digit run &mdash; which lives in the ABA routing-number space
   &mdash; is never misclassified as a CUSIP;
2. **check digit** &mdash; the public CUSIP modulus-10 "double-add-double"
   algorithm: map each base character to its value (`A`=10&hellip;`Z`=35,
   `*`=36, `@`=37, `#`=38), double every value in an even position, sum the
   decimal digits, and the check digit is `(10 - (sum mod 10)) mod 10`.

Gating on the CUSIP check digit mirrors the ABA, Luhn, IBAN, and ISIN gates: a
run that clears both is a near-certain real CUSIP, while a coincidental
alphanumeric blob fails the check digit with overwhelming probability and is left
to the existing heuristics. The base and check digit never leave the tool &mdash;
evidence is redacted to the leading two characters (`17XXXXXXX`). A CUSIP sitting
in its own `SECID` field is *not* flagged; only one bleeding into free text is.
Because a US ISIN embeds a CUSIP as its NSIN, the longer twelve-character ISIN
match takes precedence when an ISIN is present.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/cusip @ statement[0].transaction[0].memo: CUSIP securities identifier (valid check digit) leaking into a free-text field -- discloses a customer's securities holding.
```

**Remediation:** never echo a security's CUSIP into a statement memo or
transaction name; keep security identifiers in the structured `SECID` field where
they belong.

### SEDOL leak detection

A [SEDOL](https://en.wikipedia.org/wiki/SEDOL) is the seven-character UK/Ireland
securities identifier issued by the London Stock Exchange &mdash; the NSIN that
sits at the core of a `GB`/`IE` `ISIN` and the value that legitimately belongs in
an OFX investment `SECID`. Like a CUSIP or ISIN, a SEDOL that leaks into a
free-text **memo or transaction name** discloses which securities a customer holds
&mdash; a brokerage-account privacy leak reportable on its own. The **pii** check
flags a `sedol` finding (severity `high`) when a free-text field contains a string
that clears **both** public gates:

1. **shape** &mdash; exactly seven characters: a six-character base of digits or
   **consonants** (the vowels `A` `E` `I` `O` `U` are never used in a SEDOL base)
   plus one trailing decimal check digit. The base must contain at least one
   letter, so a purely numeric seven-digit run &mdash; a common coincidental value
   &mdash; is never misclassified as a SEDOL;
2. **check digit** &mdash; the public SEDOL weighted modulus-10 algorithm: map
   each base character to its value (digit-as-itself, `B`=11&hellip;`Z`=35),
   multiply by the positional weights `(1, 3, 1, 7, 3, 9)`, and the check digit is
   `(10 - (weighted sum mod 10)) mod 10`.

Gating on the SEDOL check digit mirrors the ABA, Luhn, IBAN, ISIN, and CUSIP
gates: a run that clears both is a near-certain real SEDOL, while a coincidental
alphanumeric blob fails the no-vowel rule or the check digit with overwhelming
probability and is left to the existing heuristics. The base and check digit never
leave the tool &mdash; evidence is redacted to the leading character (`BXXXXXX`).
A SEDOL sitting in its own `SECID` field is *not* flagged; only one bleeding into
free text is. Because a UK/Ireland ISIN embeds a SEDOL as its NSIN, the longer
twelve-character ISIN match takes precedence when an ISIN is present.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/sedol @ statement[0].transaction[0].memo: SEDOL securities identifier (valid check digit) leaking into a free-text field -- discloses a customer's securities holding.
```

**Remediation:** never echo a security's SEDOL into a statement memo or
transaction name; keep security identifiers in the structured `SECID` field where
they belong.

### LEI leak detection

A [LEI](https://en.wikipedia.org/wiki/Legal_Entity_Identifier) (Legal Entity
Identifier, ISO 17442) is the global, public, twenty-character code that
identifies a legal entity party to a financial transaction &mdash; a
counterparty, an issuer, or a fund manager. An LEI echoed into a free-text
**memo or transaction name** discloses *who* a customer transacted with: a
counterparty-confidentiality leak that is reportable on its own in fintech
bug-bounty programs (and a regulatory-reporting field that should never travel in
free text). The **pii** check flags an `lei` finding (severity `high`) when a
free-text field contains a string that clears **both** public gates:

1. **shape** &mdash; exactly twenty characters: an eighteen-character
   alphanumeric entity portion (a four-character LOU prefix, a two-character
   reserved field, and a twelve-character entity-specific part) followed by two
   decimal check digits;
2. **check digits** &mdash; the public ISO 7064 mod-97-10 algorithm: expand every
   letter to its two-digit value (`A`=10&hellip;`Z`=35), interpret the whole
   twenty-character value (check digits included) as an integer, and verify it is
   `== 1 (mod 97)`.

Gating on the ISO 7064 check digits mirrors the IBAN gate (same mod-97-10 scheme,
applied to the whole value with no rearrangement): a run that clears both is a
near-certain real LEI, while a coincidental twenty-character alphanumeric blob
fails the check digits with overwhelming probability and is left to the existing
heuristics. The reserved positions are **not** gated on being `00` &mdash; that
convention is not honoured by all Local Operating Units, so enforcing it would
reject real LEIs. The entity portion and check digits never leave the tool
&mdash; evidence is redacted to the four-character LOU prefix (`5299XXXXXXXXXXXXXXXX`).
Because an LEI is the longest of the gated identifiers, it is matched before the
shorter ISIN, CUSIP, and SEDOL detectors so the full twenty-character run is
claimed first.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/lei @ statement[0].transaction[0].memo: Legal Entity Identifier (LEI, valid ISO 17442 mod-97-10 check digits) leaking into a free-text field -- discloses the legal entity behind a transaction.
```

**Remediation:** never echo a counterparty's or issuer's LEI into a statement
memo or transaction name; keep entity identifiers in structured, access-controlled
fields rather than free text.

### BIC / SWIFT code leak detection

A [BIC](https://en.wikipedia.org/wiki/ISO_9362) (Bank Identifier Code, also called
a SWIFT code, ISO 9362) is the public eight- or eleven-character code that
identifies a financial institution &mdash; the value printed alongside an IBAN on
a wire instruction. A BIC echoed into a free-text **memo or transaction name**
discloses the bank behind a transaction, and paired with an IBAN it fully
identifies a counterparty's account: a counterparty-confidentiality leak
reportable on its own. The **pii** check flags a `bic` finding (severity `high`)
when a free-text field contains an **upper-case** string that clears **three**
public gates:

1. **shape** &mdash; exactly eight or eleven characters: four letters (the
   institution / bank code), two letters (the country code), two alphanumerics
   (the location code), and &mdash; for the eleven-character form &mdash; three
   alphanumerics (the branch code);
2. **country** &mdash; the fifth and sixth characters must be a registered
   ISO 3166-1 alpha-2 country code (the same registry-gating idea the IBAN check
   uses, and the primary precision lever);
3. **location-code rules** &mdash; per ISO 9362, the first location character is
   never `0` or `1` (reserved) and the second is never the letter `O` (to avoid
   confusion with zero).

ISO 9362 defines no arithmetic checksum, so precision comes from the strict
structure plus the registered country code. Detection is deliberately **upper-case
only**: a BIC is always transmitted in upper case, and matching lower-case
all-letter runs would flood reports with ordinary English words (for instance
`beneficiary` is eleven letters whose fifth-sixth characters are `FI`, Finland).
The location and branch codes never leave the tool &mdash; evidence is redacted to
the six-character bank-plus-country prefix (`BOFAUSXX`, `DEUTDEXXXXX`).

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/bic @ statement[0].transaction[0].memo: Bank Identifier Code (BIC/SWIFT, valid ISO 9362 structure and country code) leaking into a free-text field -- identifies the financial institution behind a transaction.
```

**Remediation:** never echo a counterparty's BIC/SWIFT code into a statement memo
or transaction name; keep institution identifiers in structured,
access-controlled fields rather than free text.

### UK sort code leak detection

A [UK sort code](https://en.wikipedia.org/wiki/Sort_code) is the six-digit
routing code &mdash; written in three hyphen-separated pairs, `NN-NN-NN` &mdash;
that identifies a UK bank and branch. It is the domestic equivalent of an ABA
routing number, and paired with an account number it is the exact data a Faster
Payments / BACS / CHAPS transfer (or a wire-fraud attacker) needs. A sort code
echoed into a free-text **memo or transaction name** discloses the bank/branch
routing of an account. The **pii** check flags a `uk_sort_code` finding (severity
`high`) when a free-text field contains a string that clears **two** public,
dependency-free gates:

1. **shape** &mdash; exactly `NN-NN-NN`: three hyphen-separated pairs of decimal
   digits. The hyphenated presentation is the dominant precision lever: it is
   distinct from any contiguous digit run, so it never collides with the account
   number (`\d{8,}`), routing (`\d{9}`), or payment-card scanners, and ordinary
   prose almost never contains an `NN-NN-NN` token;
2. **clearing-range prefix** &mdash; the leading pair (the bank/clearing
   identifier) must be in the assigned range `01`&ndash;`97`. `00` is unassigned
   and `98`/`99` are reserved (Bank of England / non-clearing and test ranges),
   so an all-zeros, all-nines (`99-99-99`), or otherwise out-of-range leading
   pair is never reported.

Unlike the ABA number, a UK sort code has no published, self-contained check
digit &mdash; the VocaLink modulus check that validates a sort code requires the
paired account number and a weight table &mdash; so precision comes from the
hyphenated structure plus the assigned clearing-range prefix. Evidence is redacted
to the leading bank pair (`20-XX-XX`); the branch-identifying pairs never leave
the tool.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/uk_sort_code @ statement[0].transaction[0].memo: UK sort code (valid NN-NN-NN structure and assigned clearing-range prefix) leaking into a free-text field -- discloses the bank/branch routing of an account.
```

**Remediation:** never echo a customer's sort code into a statement memo or
transaction name; keep bank/branch routing identifiers in structured,
access-controlled fields rather than free text.

### Canadian routing number leak detection

A [Canadian routing number](https://en.wikipedia.org/wiki/Routing_number_(Canada))
is the value a domestic Interac e-Transfer / EFT / pre-authorized-debit (PAD)
payment is routed against &mdash; the Canadian equivalent of an ABA routing
number or a UK sort code. Its cheque-printed MICR presentation is `TTTTT-III`: a
five-digit branch **transit** number, a hyphen, and a three-digit Payments Canada
**institution** number (e.g. `003` = RBC, `004` = TD, `010` = CIBC). A routing
number echoed into a free-text **memo or transaction name** discloses the
bank/branch routing of an account. The **pii** check flags a `ca_routing_number`
finding (severity `high`) when a free-text field contains a string that clears
**two** public, dependency-free gates:

1. **shape** &mdash; exactly `TTTTT-III`: five decimal digits, a hyphen, and
   three decimal digits. The hyphenated 5-3 presentation is the dominant
   precision lever: it is distinct from any contiguous digit run, so it never
   collides with the account number (`\d{8,}`), routing (`\d{9}`), or
   payment-card scanners; it is also distinct from the UK sort code's 2-2-2 split
   and the SSN's 3-2-4 split, so the three hyphenated detectors never collide;
2. **assigned institution number** &mdash; the three-digit institution number
   must fall in a Payments Canada assigned range (`001`&ndash;`039` chartered
   banks, `100`&ndash;`399` foreign-bank / federal members, `600`&ndash;`699`
   trust & loan, `800`&ndash;`899` credit-union centrals). `000` is never a live
   institution, and an out-of-range value (e.g. `999`) is never reported.

Like the UK sort code, a Canadian routing number carries no published,
self-contained arithmetic checksum (the only validation is the bank's own
account-modulus check, which needs the paired account number), so precision comes
from the MICR structure plus the assigned institution number. Evidence is
redacted to the institution number (`XXXXX-003`); the branch-identifying transit
number never leaves the tool.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/ca_routing_number @ statement[0].transaction[0].memo: Canadian routing number (valid TTTTT-III MICR structure and assigned institution number) leaking into a free-text field -- discloses the bank/branch routing of an account.
```

**Remediation:** never echo a customer's routing number into a statement memo or
transaction name; keep bank/branch routing identifiers in structured,
access-controlled fields rather than free text.

### Australian BSB code leak detection

An [Australian BSB code](https://en.wikipedia.org/wiki/Bank_state_branch) is the
six-digit Bank-State-Branch routing code that identifies an Australian bank,
state, and branch &mdash; the value a domestic BECS direct-entry / PayTo /
direct-debit payment is routed against, the Australian equivalent of an ABA
routing number, a UK sort code, or a Canadian routing number. It is
conventionally written in two hyphen-separated triples, `NNN-NNN` (e.g. `062-000`
= Commonwealth Bank, `013-006` = ANZ): a leading bank/institution prefix, a state
digit, and a branch. A BSB echoed into a free-text **memo or transaction name**
discloses the bank/branch routing of an account. The **pii** check flags an
`au_bsb` finding (severity `high`) when a free-text field contains a string that
clears **two** public, dependency-free gates:

1. **shape** &mdash; exactly `NNN-NNN`: two hyphen-separated triples of decimal
   digits. The hyphenated 3-3 presentation is the dominant precision lever: it is
   distinct from any contiguous digit run, so it never collides with the account
   number (`\d{8,}`), routing (`\d{9}`), or payment-card scanners; it is also
   distinct from the SSN's 3-2-4 split, the UK sort code's 2-2-2 split, and the
   Canadian routing number's 5-3 split, so the four hyphenated detectors never
   collide;
2. **assigned bank prefix** &mdash; the leading two digits (the AusPayNet bank
   code) must fall in an assigned range (`01`&ndash;`19` the big-four / other
   ADIs, `20`&ndash;`79` the Reserve-Bank / government / other-ADI blocks,
   `80`&ndash;`89` the Cuscal-sponsored mutual / credit-union / fintech block).
   `00` is never assigned and the `90`&ndash;`99` range is reserved, so an
   all-zeros or out-of-range leading pair (e.g. `999-999`) is never reported.

Like the UK sort code and the Canadian routing number, a BSB carries no
published, self-contained arithmetic check digit, so precision comes from the
hyphenated structure plus the assigned bank prefix. Evidence is redacted to the
leading bank pair (`06X-XXX`); the state and branch digits never leave the tool.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/au_bsb @ statement[0].transaction[0].memo: Australian BSB code (valid NNN-NNN structure and assigned bank prefix) leaking into a free-text field -- discloses the bank/branch routing of an account.
```

**Remediation:** never echo a customer's BSB into a statement memo or transaction
name; keep bank/branch routing identifiers in structured, access-controlled
fields rather than free text.

### Indian IFSC code leak detection

An [Indian Financial System Code (IFSC)](https://en.wikipedia.org/wiki/Indian_Financial_System_Code)
is the RBI-defined eleven-character code that identifies a specific bank branch
&mdash; the value a domestic NEFT / RTGS / IMPS / UPI transfer is routed against,
the Indian equivalent of an ABA routing number, a UK sort code, an Australian
BSB, or a Canadian routing number. It is written `BBBB0BRANCH` (e.g. `SBIN0000123`
= State Bank of India, `HDFC0001234` = HDFC Bank): a four-letter bank code, a
single reserved character that is **always `0`**, and a six-character
alphanumeric branch code. An IFSC echoed into a free-text **memo or transaction
name** discloses the bank/branch routing of an account. The **pii** check flags an
`ifsc` finding (severity `high`) when a free-text field contains a string that
clears the public, dependency-free structural gate:

1. **shape** &mdash; exactly eleven characters: four letters (the bank code), the
   mandatory reserved `0` in the fifth position, and six alphanumeric branch
   characters. The mandatory zero is the dominant precision lever: almost no
   coincidental eleven-character token carries a `0` in exactly the fifth
   position, and the match is restricted to upper case so an ordinary
   mixed-case word never collides. The letter prefix plus the digit-in-fifth
   shape is distinct from the hyphenated routing codes (UK sort `2-2-2`,
   Canadian `5-3`, Australian BSB `3-3`) and from a BIC (first six characters
   all letters), so the detectors never collide.

Like the other domestic routing codes, an IFSC carries no published,
self-contained arithmetic check digit, so precision comes from the strict
structure. A token with the right letter prefix but no `0` in the fifth position
(e.g. `HDFCX001234`) is never reported. Evidence is redacted to the four-letter
bank code (`SBINXXXXXXX`); the reserved zero and the branch code never leave the
tool.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/ifsc @ statement[0].transaction[0].memo: Indian Financial System Code (IFSC, valid BBBB0BRANCH structure) leaking into a free-text field -- discloses the bank/branch routing of an account.
```

**Remediation:** never echo a customer's IFSC into a statement memo or transaction
name; keep bank/branch routing identifiers in structured, access-controlled
fields rather than free text.

### Mexican CLABE leak detection

A [CLABE (Clave Bancaria Estandarizada)](https://en.wikipedia.org/wiki/CLABE) is
the eighteen-digit standardized bank-account number that every domestic SPEI /
interbank transfer in Mexico is routed against &mdash; the Mexican equivalent of
an IBAN, and the value (on its own) needed to receive funds into a specific
account. It is `BBBPPPNNNNNNNNNNNC`: a three-digit bank (institution) code, a
three-digit branch/plaza code, an eleven-digit account number, and one trailing
control digit. A CLABE echoed into a free-text **memo or transaction name**
discloses a bank account routable for a SPEI transfer. The **pii** check flags a
`clabe` finding (severity `high`) when a free-text field contains a string that
clears two public, dependency-free gates:

1. **shape + bank code** &mdash; exactly eighteen decimal digits, with a non-zero
   leading three-digit bank code (`000` is never an assigned institution).
2. **control digit** &mdash; multiply each of the first seventeen digits by the
   repeating weights `(3, 7, 1)`, take each product mod 10, sum them, and the
   control digit is `(10 - (sum mod 10)) mod 10`. The eighteenth digit must equal
   that control digit.

Unlike the UK / Canadian / Australian / Indian domestic routing codes, a CLABE
carries a public, self-contained arithmetic control digit, so precision comes
from a real checksum &mdash; on a par with the IBAN / ABA / Luhn-gated
identifiers. Because a CLABE is a contiguous eighteen-digit run it is checked
**before** the payment-card and account-number scanners and its run is reserved,
so a valid CLABE is reported once as the account identifier it is rather than
being double-counted as a card or a generic account number. An eighteen-digit run
that fails the control digit is not a CLABE but is still reported as an
`account_number` (no leak is silently dropped). Evidence is redacted to the
three-digit bank code (`002XXXXXXXXXXXXXXX`); the branch, account, and control
digit never leave the tool.

```bash
$ ferryman --check pii --format text leak.ofx
  [HIGH] pii/clabe @ statement[0].transaction[0].memo: Mexican CLABE (valid 18-digit structure, non-zero bank code, and mod-10 control digit) leaking into a free-text field -- discloses a bank account routable for a SPEI transfer.
```

**Remediation:** never echo a customer's CLABE into a statement memo or
transaction name; keep bank-account identifiers in structured, access-controlled
fields rather than free text.

## From finding to HackerOne report

A ferryman finding maps directly onto a HackerOne submission. Given the XXE
finding above, the report writes itself:

> **Title:** XXE via external entity in OFX statement import
>
> **Severity:** Critical (CVSS 9.1)
>
> **Summary:** The OFX import endpoint resolves external XML entities. An
> uploaded OFX file containing `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and a
> reference to `&xxe;` causes the parser to read local files, enabling local
> file disclosure and SSRF.
>
> **Steps to reproduce:**
> 1. Run `ferryman --check malformed --format json poc.ofx` to confirm the
>    crafted entity (finding: `malformed/xxe`, severity `critical`, line 4).
> 2. Upload `poc.ofx` to the statement-import endpoint.
> 3. Observe the contents of `/etc/passwd` reflected in the imported account id.
>
> **Impact:** Local file read and SSRF against the import service.
>
> **Remediation:** Disable DTD processing / external entity resolution in the
> OFX/XML parser (`resolve_entities=False`, `no_network=True`).

### Investment (brokerage) account support

ferryman scans investment statements (`INVSTMTRS`) in addition to bank and
credit-card statements. Brokerage exports are exactly the high-value targets
fintech bug-bounty programs run, and they carry their own surface:

- The **pii** check scans investment transaction memos (free text) and the
  security identifier (`UNIQUEID` / CUSIP). The security id is scanned with a
  narrower rule — SSN-shaped values and over-long digit runs only — so a
  legitimate 9-digit numeric CUSIP is never flagged as a routing number.
- The **anomaly** check flags investment transactions with a **negative unit
  price** (`negative_unit_price`, high — a security cannot trade below zero), a
  **negative quantity on a non-sell transaction** (`negative_units`, high —
  only a sale legitimately reduces a holding), and an **implausibly large unit
  price** (`implausible_unit_price`, medium — an out-of-range / overflow probe).

```bash
$ ferryman --check all --format text brokerage.ofx
  [CRITICAL] pii/ssn @ statement[0].transaction[0].memo: SSN-shaped value found in a free-text field.
  [HIGH] anomaly/negative_unit_price @ statement[0].transaction[0].unitprice: Investment transaction has a negative unit price ...
```

## Scope

In scope: scanning OFX **files** on disk; BankAccount, CreditAccount, and
investment (`INVSTMTRS`) statements; the three check families above.

Out of scope: live/streaming bank-API scanning, downloading from financial
institutions, HackerOne submission automation.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT &mdash; see [LICENSE](LICENSE).
