# ferryman

A security-focused scanner for **OFX (Open Financial Exchange)** files, built
for the bug-bounty fintech surface.

OFX is the format banks and brokerages use to export account data, and mature
parsers for it already exist. ferryman is **not** another parser. It is a
scanner that treats an OFX file as an attack surface and asks three questions:

- **Is this file trying to attack the parser that reads it?** XXE entity
  declarations, SGML/XML format confusion, encoding tricks, oversized fields.
- **Is this file leaking PII it should not?** SSNs, full account numbers, and
  routing numbers smuggled into free-text transaction names and memos.
- **Is this file anomalous?** Out-of-range posting dates and other signs of
  tampering or a backend that accepts garbage.

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
  - `malformed` &mdash; parser-confusion attacks (XXE, SGML/XML confusion,
    encoding tricks, oversized fields). Operates on raw bytes; never parses a
    hostile file.
  - `pii` &mdash; PII leaking into transaction free-text (SSN, account number,
    routing number). Evidence is always redacted before it leaves the tool.
  - `anomaly` &mdash; structurally valid but suspicious transactions
    (out-of-range dates).
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

## Scope (v0.1)

In scope: scanning OFX **files** on disk, BankAccount and CreditAccount
statements, three check families above.

Out of scope: live/streaming bank-API scanning, downloading from financial
institutions, investment-account support, HackerOne submission automation.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT &mdash; see [LICENSE](LICENSE).
