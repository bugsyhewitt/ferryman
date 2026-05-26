"""Malformed / parser-confusion check.

[Worker decision: this check operates strictly on raw bytes and NEVER hands
the content to an XML/SGML parser. The whole point is to detect files crafted
to attack a parser (XXE, SGML/XML confusion, encoding tricks). Parsing them
first would be the exact mistake we are trying to flag in downstream targets,
and would expose ferryman itself to the attack. Detection is therefore
structural pattern-matching over bytes, not semantic parsing.]

Detection classes:
- ``xxe``                : DOCTYPE/ENTITY declarations, especially SYSTEM
                           external entities (the classic XXE vector).
- ``sgml_xml_confusion`` : a document declaring itself both XML (``<?xml?>``)
                           and v1 SGML (``OFXHEADER``/``DATA:OFXSGML``).
- ``encoding_trick``     : null bytes / BOMs inside an ostensibly ASCII OFX
                           file, used to provoke parser disagreement.
- ``oversized_field``    : a single tag value far larger than any legitimate
                           OFX field, a memory/DoS and confusion vector.
"""

from __future__ import annotations

import re

from ferryman.findings import Finding, truncate_evidence

# Any OFX field above this many bytes is wildly out of spec; real account
# numbers, memos, names etc. are short. 64 KiB is a generous ceiling.
_OVERSIZED_FIELD_BYTES = 64 * 1024

_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)
_SYSTEM_ENTITY_RE = re.compile(
    rb"<!ENTITY\s+\S+\s+SYSTEM\s+[\"'][^\"']+[\"']", re.IGNORECASE | re.DOTALL
)
_XML_DECL_RE = re.compile(rb"<\?xml\b", re.IGNORECASE)
_SGML_MARKER_RE = re.compile(rb"OFXHEADER\s*:|DATA\s*:\s*OFXSGML", re.IGNORECASE)
# Tag value = text between a closing '>' and the next opening '<'.
_FIELD_VALUE_RE = re.compile(rb">([^<]+)<")


def _line_of(raw: bytes, index: int) -> int:
    """1-based line number of a byte offset, for finding locations."""
    return raw.count(b"\n", 0, index) + 1


def check_malformed(raw: bytes) -> list[Finding]:
    """Scan raw OFX bytes for parser-confusion / malformation attacks."""
    findings: list[Finding] = []

    # --- XXE: DOCTYPE + ENTITY, escalating on external SYSTEM entities ---
    sys_match = _SYSTEM_ENTITY_RE.search(raw)
    if sys_match:
        findings.append(
            Finding(
                check="malformed",
                type="xxe",
                severity="critical",
                message=(
                    "External entity declaration (SYSTEM) found -- classic XXE "
                    "vector capable of file read / SSRF if the target parser "
                    "resolves external entities."
                ),
                location=f"line {_line_of(raw, sys_match.start())}",
                evidence=truncate_evidence(sys_match.group(0).decode("latin-1")),
            )
        )
    elif _DOCTYPE_RE.search(raw) and _ENTITY_RE.search(raw):
        ent = _ENTITY_RE.search(raw)
        findings.append(
            Finding(
                check="malformed",
                type="xxe",
                severity="high",
                message=(
                    "Internal DOCTYPE entity declaration found. OFX has no "
                    "legitimate use for custom entities; this is a parser-"
                    "confusion / entity-expansion vector."
                ),
                location=f"line {_line_of(raw, ent.start())}" if ent else None,
            )
        )
    elif _DOCTYPE_RE.search(raw):
        dt = _DOCTYPE_RE.search(raw)
        findings.append(
            Finding(
                check="malformed",
                type="xxe",
                severity="medium",
                message=(
                    "DOCTYPE declaration present in an OFX document. OFX does "
                    "not define a DTD; presence suggests a crafted file."
                ),
                location=f"line {_line_of(raw, dt.start())}" if dt else None,
            )
        )

    # --- SGML/XML confusion: claims to be both formats at once ---
    if _XML_DECL_RE.search(raw) and _SGML_MARKER_RE.search(raw):
        findings.append(
            Finding(
                check="malformed",
                type="sgml_xml_confusion",
                severity="high",
                message=(
                    "Document declares both an XML prolog and v1 SGML OFX "
                    "headers. Parsers will disagree on how to read it -- a "
                    "content-type confusion attack."
                ),
                location="line 1",
            )
        )

    # --- Encoding tricks: null bytes / BOM inside the body ---
    if b"\x00" in raw:
        idx = raw.index(b"\x00")
        findings.append(
            Finding(
                check="malformed",
                type="encoding_trick",
                severity="high",
                message=(
                    "Null byte(s) present in the document body. Used to "
                    "truncate strings differently across parsers or smuggle "
                    "content past validators."
                ),
                location=f"byte {idx} (line {_line_of(raw, idx)})",
            )
        )
    else:
        # A UTF-16/32 BOM in a file that also carries SGML/ASCII headers.
        for bom in (b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf"):
            pos = raw.find(bom)
            if pos > 0:  # mid-document BOM, not a legitimate leading BOM
                findings.append(
                    Finding(
                        check="malformed",
                        type="encoding_trick",
                        severity="medium",
                        message=(
                            "Byte-order mark found mid-document -- an encoding-"
                            "confusion attempt to desync parsers."
                        ),
                        location=f"byte {pos}",
                    )
                )
                break

    # --- Oversized fields ---
    for m in _FIELD_VALUE_RE.finditer(raw):
        value = m.group(1)
        if len(value) > _OVERSIZED_FIELD_BYTES:
            findings.append(
                Finding(
                    check="malformed",
                    type="oversized_field",
                    severity="medium",
                    message=(
                        f"OFX field value of {len(value)} bytes far exceeds any "
                        "legitimate field size -- a memory-exhaustion / parser-"
                        "confusion vector."
                    ),
                    location=f"line {_line_of(raw, m.start())}",
                    metadata={"field_bytes": len(value)},
                )
            )
            break  # one oversized-field finding is enough to triage

    return findings
