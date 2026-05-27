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
- ``cdata_injection``    : a CDATA section whose content contains ``]]>``,
                           which prematurely terminates the section and allows
                           injection of raw XML markup into the parsed output
                           (CVE-2026-34601 / xmldom class of vulnerability).
"""

from __future__ import annotations

import re

from ferryman.findings import Finding, truncate_evidence

# Any OFX field above this many bytes is wildly out of spec; real account
# numbers, memos, names etc. are short. 64 KiB is a generous ceiling.
_OVERSIZED_FIELD_BYTES = 64 * 1024

# CDATA section: <![CDATA[ ... ]]>
# We use a non-greedy match to find each CDATA block individually.
# If the captured content (between <![CDATA[ and the first ]]>) itself
# contains ]]>, that means a nested/injected terminator was present before
# the legitimate close — a CDATA injection attempt.
_CDATA_BLOCK_RE = re.compile(rb"<!\[CDATA\[(.*?)]]>", re.DOTALL)
_CDATA_TERMINATOR_RE = re.compile(rb"]]>")

_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)
_SYSTEM_ENTITY_RE = re.compile(
    rb"<!ENTITY\s+\S+\s+SYSTEM\s+[\"'][^\"']+[\"']", re.IGNORECASE | re.DOTALL
)
# Capture the declared entity name and its quoted body. Used to detect the
# Billion-Laughs nested-reference pattern (one entity's body referencing
# another declared entity, e.g. <!ENTITY b "&a;&a;">).
_ENTITY_DECL_RE = re.compile(
    rb"<!ENTITY\s+(\S+)\s+[\"']([^\"']*)[\"']", re.IGNORECASE | re.DOTALL
)
# Minimum number of entity declarations before we treat a nested chain as a
# Billion-Laughs DoS. Legitimate OFX defines zero custom entities; three with
# cross-references is unambiguously hostile.
_ENTITY_EXPANSION_THRESHOLD = 3
_XML_DECL_RE = re.compile(rb"<\?xml\b", re.IGNORECASE)
_SGML_MARKER_RE = re.compile(rb"OFXHEADER\s*:|DATA\s*:\s*OFXSGML", re.IGNORECASE)
# Tag value = text between a closing '>' and the next opening '<'.
_FIELD_VALUE_RE = re.compile(rb">([^<]+)<")


def _line_of(raw: bytes, index: int) -> int:
    """1-based line number of a byte offset, for finding locations."""
    return raw.count(b"\n", 0, index) + 1


def _count_entities(raw: bytes) -> int:
    """Count ``<!ENTITY`` declarations in the raw bytes.

    Pure regex over bytes -- never parses the document. Case-insensitive so
    ``<!entity`` is counted the same as ``<!ENTITY``.
    """
    return len(_ENTITY_RE.findall(raw))


def _has_nested_entity_reference(raw: bytes) -> bool:
    """True if any declared entity's body references another declared entity.

    This is the Billion-Laughs signature: ``<!ENTITY b "&a;...">`` where ``a``
    is itself a declared entity. A flat set of entities that never reference
    one another does not expand recursively and is not flagged here.
    """
    decls: dict[bytes, bytes] = {}
    for m in _ENTITY_DECL_RE.finditer(raw):
        name, body = m.group(1), m.group(2)
        decls[name.lower()] = body

    for body in decls.values():
        for ref in re.finditer(rb"&([^;&\s]+);", body):
            if ref.group(1).lower() in decls:
                return True
    return False


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

    # --- Entity-expansion (Billion Laughs) DoS ---
    # A separately-reportable vector from XXE-for-file-read: >=3 entity
    # declarations where at least one entity body references another declared
    # entity (the recursive chain that explodes on expansion).
    if (
        _count_entities(raw) >= _ENTITY_EXPANSION_THRESHOLD
        and _has_nested_entity_reference(raw)
    ):
        ent = _ENTITY_RE.search(raw)
        findings.append(
            Finding(
                check="malformed",
                type="entity_expansion",
                severity="critical",
                message=(
                    "Multiple entity declarations with nested cross-references "
                    "found -- a recursive entity-expansion (Billion Laughs) DoS "
                    "vector. Expanding the chain exhausts parser memory. OFX has "
                    "no legitimate use for custom entities."
                ),
                location=f"line {_line_of(raw, ent.start())}" if ent else None,
                metadata={"entity_count": _count_entities(raw)},
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

    # --- CDATA injection (FERRYMAN-MALFORMED-004) ---
    # A CDATA block whose content contains ]]> prematurely closes the section,
    # allowing an attacker to inject raw XML markup into the parsed output.
    # Strategy: use a non-greedy regex to match each <![CDATA[...]]> block.
    # Because the regex is non-greedy, it captures up to the *first* ]]>.
    # We then search the raw document for any ]]> that occurs *inside* one of
    # those blocks -- i.e., before the legitimate close. Since our regex already
    # consumed up to the first ]]>, any additional ]]> in the surrounding raw
    # bytes that falls within the block's byte range is the injected terminator.
    #
    # Simpler equivalent: scan for every ]]> in the document.  For each one,
    # check whether it lies between the start of a CDATA opening marker and the
    # end of a CDATA block match that started before it.  If the CDATA block
    # match's content (group 1) is non-empty and the match ends *after* a
    # second ]]> in the raw bytes, injection is present.
    #
    # Practical implementation: for every CDATA match, check whether the raw
    # slice between the opening marker end and the match's ]]> contains
    # another ]]>.  The non-greedy regex guarantees the captured content is
    # the minimal prefix up to the first ]]>; any *subsequent* ]]> in the
    # same logical block is injection.  We find those by scanning forward from
    # the match end.
    cdata_open = b"<![CDATA["
    for cdata_m in _CDATA_BLOCK_RE.finditer(raw):
        content = cdata_m.group(1)
        # The content is the bytes between <![CDATA[ and the first ]]>.
        # If the content itself contains ]]> it would have been consumed by
        # the non-greedy match before reaching here -- so content is clean.
        # Instead, look for injection *after* this CDATA close: if the bytes
        # immediately after the match's ]]> (i.e. what would be "outside" the
        # CDATA) start with content that logically belongs to the block, the
        # document is malformed.  The clearest heuristic: check whether the
        # raw document contains a ]]> that is preceded by a <![CDATA[ with no
        # intervening ]]> -- but that's exactly what our non-greedy match
        # already handles.
        #
        # Real injection pattern: the raw document has something like:
        #   <![CDATA[safe]]>injected-xml]]>
        # The non-greedy RE matches <![CDATA[safe]]> as one block (content="safe").
        # The *injected-xml* part then sits outside CDATA in the document.
        # To catch this, we check: is the text between the end of this block
        # and the *next* ]]> (if any) preceded by NO new <![CDATA[ opener?
        # If so, there is a free-floating ]]> -- the signature of injection.
        block_end = cdata_m.end()  # byte offset just after this block's ]]>
        next_term = raw.find(b"]]>", block_end)
        if next_term == -1:
            continue
        between = raw[block_end:next_term]
        # If there is no new <![CDATA[ between the end of this block and the
        # next ]]>, that next ]]> is an orphan terminator injected after the
        # CDATA section closed -- CDATA injection confirmed.
        if cdata_open.lower() not in between.lower() and b"<![CDATA[" not in between:
            snippet_start = max(0, cdata_m.start())
            snippet = raw[snippet_start : next_term + 3]
            findings.append(
                Finding(
                    check="malformed",
                    type="cdata_injection",
                    severity="high",
                    message=(
                        "CDATA section contains an embedded ']]>' terminator "
                        "that prematurely closes the section and injects raw XML "
                        "markup into parsed output (CVE-2026-34601 class). An "
                        "attacker could inject arbitrary fields such as "
                        "<TRNAMT> or <approved> into the document tree."
                    ),
                    location=f"line {_line_of(raw, cdata_m.start())}",
                    evidence=truncate_evidence(
                        snippet.decode("latin-1"), limit=80
                    ),
                    metadata={"finding_id": "FERRYMAN-MALFORMED-004"},
                )
            )
            break  # one finding is sufficient to flag the file

    return findings
