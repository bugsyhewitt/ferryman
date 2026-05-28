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
- **Is this file leaking PII it should not?** SSNs, full account numbers, and
  routing numbers smuggled into free-text transaction names and memos.
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
ferryman [--check {malformed,pii,anomaly,all}] [--format {json,text}] FILE
```

- `--check` &mdash; which scan to run. Default `all`.
  - `malformed` &mdash; parser-confusion attacks (XXE, entity-expansion
    "Billion Laughs" DoS, CDATA injection, SGML/XML confusion, OFX v1 header
    injection / encoding mismatch, encoding tricks, oversized fields). Operates
    on raw bytes; never parses a hostile file.
  - `pii` &mdash; PII leaking into transaction free-text (SSN, account number,
    routing number), including investment memos and security ids. Evidence is
    always redacted before it leaves the tool.
  - `anomaly` &mdash; structurally valid but suspicious transactions
    (out-of-range dates; zero, sign-contradicting, or out-of-range transaction
    amounts; for investment statements, negative/implausible unit prices and
    negative quantities on non-sell transactions).
  - `all` &mdash; every check.
- `--format` &mdash; `json` (default) or human-readable `text`.

Exit codes: `0` scan completed, `2` usage error, `3` file could not be read.

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
