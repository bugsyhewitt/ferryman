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
- ``header_injection``   : a second OFX v1 SGML header block smuggled into the
                           document after the legitimate header/body separator.
- ``encoding_mismatch``  : an OFX v1 header declaring an ENCODING/CHARSET value
                           outside the OFX-allowed set, or carrying non-printable
                           bytes in the header section -- a parser-confusion vector.
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

# --- OFX v1 SGML header-block detection ---
# An OFX v1 file opens with a plaintext header block of ``KEY:VALUE`` lines,
# then a blank line, then the SGML body. The first header key is OFXHEADER.
_OFXHEADER_RE = re.compile(rb"^OFXHEADER\s*:", re.IGNORECASE | re.MULTILINE)
# A header line: KEY:VALUE with an all-caps/alpha key.
_HEADER_LINE_RE = re.compile(
    rb"^([A-Za-z][A-Za-z0-9_]*)[ \t]*:[ \t]*(.*?)[ \t]*$", re.MULTILINE
)
# OFX v1 permits only these ENCODING values; CHARSET is a code-page number
# (e.g. 1252, NONE) or USASCII. Anything else is suspicious.
_ALLOWED_ENCODINGS = {b"USASCII", b"UTF-8", b"UNICODE"}
_ALLOWED_CHARSETS = {b"1252", b"NONE", b"ISO-8859-1", b"CSUNICODE", b"NONE"}


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


def _is_ofx_v1(raw: bytes) -> bool:
    """True if the document opens with an OFX v1 SGML header block.

    We look only at the leading bytes: a v1 file starts (after any whitespace)
    with the ``OFXHEADER:`` line. v2 files begin with an XML prolog or
    ``<OFX>`` directly. This is a cheap structural check, never a parse.
    """
    head = raw[:512].lstrip()
    return bool(re.match(rb"OFXHEADER\s*:", head, re.IGNORECASE))


def _split_header(raw: bytes) -> tuple[bytes, int]:
    """Return (header_block_bytes, body_offset) for an OFX v1 document.

    The header block is everything before the first blank line (``\\n\\n`` or
    ``\\r\\n\\r\\n``). ``body_offset`` is the byte index where the SGML body
    begins. If no separator is found, the whole document is treated as header
    and ``body_offset`` is ``len(raw)``.
    """
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], idx + len(sep)
    return raw, len(raw)


def _check_v1_header(raw: bytes) -> list[Finding]:
    """Detect OFX v1 SGML header-injection and encoding-mismatch attacks.

    Three sub-detections (Rank 5 of POST_V01.md):
      (a) a second ``OFXHEADER:`` block smuggled into the body after the
          header/body separator -> ``header_injection`` (high).
      (b) an ENCODING/CHARSET value outside the OFX-allowed set
          -> ``encoding_mismatch`` (medium).
      (c) non-printable control bytes inside the header section
          -> ``encoding_mismatch`` (medium).
    """
    if not _is_ofx_v1(raw):
        return []

    findings: list[Finding] = []
    header, body_offset = _split_header(raw)
    body = raw[body_offset:]

    # (a) Second header block smuggled into the body. A legitimate v1 file has
    # exactly one OFXHEADER: line, in the leading header block. Any OFXHEADER:
    # occurrence in the body is an injected second header.
    body_header = _OFXHEADER_RE.search(body)
    if body_header is not None:
        abs_idx = body_offset + body_header.start()
        findings.append(
            Finding(
                check="malformed",
                type="header_injection",
                severity="high",
                message=(
                    "A second OFX v1 SGML header block (OFXHEADER:) appears "
                    "inside the document body, after the header/body separator. "
                    "A parser that re-reads headers can be steered to a different "
                    "encoding or version mid-stream -- a header-injection / "
                    "request-smuggling vector."
                ),
                location=f"line {_line_of(raw, abs_idx)}",
                evidence=truncate_evidence(
                    body[body_header.start() : body_header.start() + 40].decode(
                        "latin-1"
                    )
                ),
            )
        )

    # (c) Non-printable control bytes in the header section. The header is
    # plaintext KEY:VALUE lines; the only legitimate control characters are
    # CR and LF. NUL is handled separately as encoding_trick; here we catch the
    # broader control-byte class confined to the header (a desync attempt).
    for i, b in enumerate(header):
        if b < 0x20 and b not in (0x09, 0x0A, 0x0D):
            findings.append(
                Finding(
                    check="malformed",
                    type="encoding_mismatch",
                    severity="medium",
                    message=(
                        "Non-printable control byte found inside the OFX v1 "
                        "header section. Headers are plaintext KEY:VALUE lines; "
                        "control bytes here are an encoding-confusion attempt to "
                        "desync parsers."
                    ),
                    location=f"byte {i} (line {_line_of(raw, i)})",
                    metadata={"byte_value": b},
                )
            )
            break

    # (b) ENCODING / CHARSET value outside the OFX-allowed set. Parse the
    # header lines structurally (no semantic parse of the document).
    for m in _HEADER_LINE_RE.finditer(header):
        key = m.group(1).upper()
        value = m.group(2).strip()
        if key == b"ENCODING" and value and value.upper() not in _ALLOWED_ENCODINGS:
            findings.append(
                Finding(
                    check="malformed",
                    type="encoding_mismatch",
                    severity="medium",
                    message=(
                        f"OFX v1 ENCODING header declares '{value.decode('latin-1')}', "
                        "which is outside the OFX-allowed set (USASCII, UTF-8, "
                        "UNICODE). A mismatched encoding declaration provokes "
                        "parser disagreement over how to decode the body."
                    ),
                    location=f"line {_line_of(raw, m.start())}",
                    evidence=truncate_evidence(m.group(0).decode("latin-1")),
                )
            )
        elif (
            key == b"CHARSET"
            and value
            and value.upper() not in _ALLOWED_CHARSETS
            and not value.isdigit()
        ):
            findings.append(
                Finding(
                    check="malformed",
                    type="encoding_mismatch",
                    severity="medium",
                    message=(
                        f"OFX v1 CHARSET header declares '{value.decode('latin-1')}', "
                        "an unexpected value. Legitimate OFX uses a numeric code "
                        "page (e.g. 1252) or NONE; an odd CHARSET is a parser-"
                        "confusion vector."
                    ),
                    location=f"line {_line_of(raw, m.start())}",
                    evidence=truncate_evidence(m.group(0).decode("latin-1")),
                )
            )

    return findings


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

    # --- OFX v1 SGML header injection / encoding mismatch (Rank 5) ---
    findings.extend(_check_v1_header(raw))

    return findings
