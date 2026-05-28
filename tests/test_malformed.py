"""Tests for the malformed/parser-confusion check.

These tests operate on raw bytes -- the malformed check must NEVER hand a
hostile file to a real parser, so detection is structural and pre-parse.
"""

from __future__ import annotations

from ferryman.checks.malformed import _count_entities, check_malformed


def test_xxe_doctype_entity_is_detected(xxe_file):
    findings = check_malformed(xxe_file.read_bytes())
    types = {f.type for f in findings}
    assert "xxe" in types, f"expected an xxe finding, got types: {types}"
    xxe = next(f for f in findings if f.type == "xxe")
    assert xxe.check == "malformed"
    assert xxe.severity in ("high", "critical")


def test_clean_file_has_no_xxe(clean_file):
    findings = check_malformed(clean_file.read_bytes())
    assert all(f.type != "xxe" for f in findings)


def test_external_general_entity_reference_flagged():
    # ENTITY pointing at a remote SYSTEM URI is the classic XXE vector.
    payload = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE OFX [<!ENTITY x SYSTEM "http://evil.example/x">]>\n'
        b"<OFX>&x;</OFX>"
    )
    findings = check_malformed(payload)
    assert any(f.type == "xxe" for f in findings)


def test_oversized_field_flagged():
    huge = b"<NAME>" + b"A" * 200_000 + b"</NAME>"
    payload = b"<OFX>" + huge + b"</OFX>"
    findings = check_malformed(payload)
    assert any(f.type == "oversized_field" for f in findings)


def test_sgml_xml_confusion_flagged():
    # An XML declaration alongside a v1 SGML OFXHEADER line is a confusion
    # attempt -- the document claims to be both at once.
    payload = (
        b'<?xml version="1.0"?>\n'
        b"OFXHEADER:100\n"
        b"DATA:OFXSGML\n"
        b"VERSION:102\n\n"
        b"<OFX></OFX>"
    )
    findings = check_malformed(payload)
    assert any(f.type == "sgml_xml_confusion" for f in findings)


def test_encoding_trick_flagged():
    # A BOM / null bytes inside an ostensibly USASCII OFX file is an
    # encoding-confusion trick aimed at parser disagreement.
    payload = b"OFXHEADER:100\nENCODING:USASCII\n\n<OFX>\x00\x00<ACCTID>1</ACCTID></OFX>"
    findings = check_malformed(payload)
    assert any(f.type == "encoding_trick" for f in findings)


# --- Entity-expansion (Billion Laughs) detection ---


def test_count_entities_counts_declarations():
    raw = (
        b"<!DOCTYPE OFX [\n"
        b'  <!ENTITY a "x">\n'
        b'  <!ENTITY b "&a;">\n'
        b'  <!entity c "&b;">\n'  # case-insensitive
        b"]>"
    )
    assert _count_entities(raw) == 3


def test_entity_bomb_detected(entity_bomb_file):
    findings = check_malformed(entity_bomb_file.read_bytes())
    types = {f.type for f in findings}
    assert "entity_expansion" in types, f"expected entity_expansion, got: {types}"
    bomb = next(f for f in findings if f.type == "entity_expansion")
    assert bomb.check == "malformed"
    assert bomb.severity == "critical"


def test_entity_bomb_inline_payload_detected():
    # 3-level nested chain: c -> b -> a. The recursive references are what
    # make this a Billion-Laughs DoS rather than a benign declaration.
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE OFX [\n"
        b'  <!ENTITY a "boom">\n'
        b'  <!ENTITY b "&a;&a;&a;">\n'
        b'  <!ENTITY c "&b;&b;&b;">\n'
        b"]>\n"
        b"<OFX>&c;</OFX>"
    )
    findings = check_malformed(payload)
    assert any(f.type == "entity_expansion" for f in findings)


def test_clean_file_no_entity_expansion(clean_file):
    # Legitimate OFX has zero custom entities -- no false positive.
    findings = check_malformed(clean_file.read_bytes())
    assert all(f.type != "entity_expansion" for f in findings)


def test_single_entity_no_entity_expansion():
    # One entity declaration is below the >=3 threshold; not a bomb.
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE OFX [\n"
        b'  <!ENTITY a "just a value">\n'
        b"]>\n"
        b"<OFX>&a;</OFX>"
    )
    findings = check_malformed(payload)
    assert all(f.type != "entity_expansion" for f in findings)


def test_two_entities_no_cross_reference_no_entity_expansion():
    # Two flat entities that never reference each other -- below the >=3
    # threshold AND no nested reference. No entity_expansion finding.
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE OFX [\n"
        b'  <!ENTITY a "alpha">\n'
        b'  <!ENTITY b "beta">\n'
        b"]>\n"
        b"<OFX>&a;&b;</OFX>"
    )
    findings = check_malformed(payload)
    assert all(f.type != "entity_expansion" for f in findings)


def test_three_flat_entities_no_cross_reference_no_entity_expansion():
    # Three entities but none reference another -- meets the count threshold
    # but lacks the nested-reference pattern, so it is not a Billion Laughs
    # chain. Must not false-positive.
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE OFX [\n"
        b'  <!ENTITY a "alpha">\n'
        b'  <!ENTITY b "beta">\n'
        b'  <!ENTITY c "gamma">\n'
        b"]>\n"
        b"<OFX>&a;&b;&c;</OFX>"
    )
    findings = check_malformed(payload)
    assert all(f.type != "entity_expansion" for f in findings)


# --- CDATA injection tests (FERRYMAN-MALFORMED-004) ---

def test_cdata_injection_fixture_is_detected(cdata_injection_file):
    """The bundled cdata-injection.ofx fixture must trigger a cdata_injection finding."""
    findings = check_malformed(cdata_injection_file.read_bytes())
    types = {f.type for f in findings}
    assert "cdata_injection" in types, f"expected cdata_injection finding, got: {types}"


def test_cdata_injection_severity_is_high(cdata_injection_file):
    findings = check_malformed(cdata_injection_file.read_bytes())
    inj = next(f for f in findings if f.type == "cdata_injection")
    assert inj.severity == "high"
    assert inj.check == "malformed"


def test_cdata_injection_finding_id_in_metadata(cdata_injection_file):
    findings = check_malformed(cdata_injection_file.read_bytes())
    inj = next(f for f in findings if f.type == "cdata_injection")
    assert inj.metadata.get("finding_id") == "FERRYMAN-MALFORMED-004"


def test_cdata_injection_inline_payload():
    """Inline payload: CDATA block terminated early with injected markup."""
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<OFX><STMTTRN>"
        b"<MEMO><![CDATA[innocent]]><TRNAMT>-99999</TRNAMT>]]></MEMO>"
        b"</STMTTRN></OFX>"
    )
    findings = check_malformed(payload)
    assert any(f.type == "cdata_injection" for f in findings)


def test_clean_cdata_not_flagged():
    """A well-formed CDATA section (no embedded ]]>) must not be flagged."""
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<OFX><STMTTRN>"
        b"<MEMO><![CDATA[Safe content with no injection]]></MEMO>"
        b"</STMTTRN></OFX>"
    )
    findings = check_malformed(payload)
    assert all(f.type != "cdata_injection" for f in findings)


def test_multiple_clean_cdata_blocks_not_flagged():
    """Multiple legitimate CDATA blocks without injection are not flagged."""
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<OFX>"
        b"<NAME><![CDATA[Alice & Bob]]></NAME>"
        b"<MEMO><![CDATA[Payment for <services>]]></MEMO>"
        b"</OFX>"
    )
    findings = check_malformed(payload)
    assert all(f.type != "cdata_injection" for f in findings)


def test_no_cdata_no_finding():
    """Documents with no CDATA sections at all produce no cdata_injection finding."""
    payload = b"<OFX><NAME>Alice</NAME><TRNAMT>-42.00</TRNAMT></OFX>"
    findings = check_malformed(payload)
    assert all(f.type != "cdata_injection" for f in findings)


# --- OFX v1 SGML header injection / encoding mismatch (Rank 5) ---

_V1_HEADER = (
    b"OFXHEADER:100\n"
    b"DATA:OFXSGML\n"
    b"VERSION:102\n"
    b"SECURITY:NONE\n"
    b"ENCODING:USASCII\n"
    b"CHARSET:1252\n"
    b"COMPRESSION:NONE\n"
    b"OLDFILEUID:NONE\n"
    b"NEWFILEUID:NONE\n"
)


def test_clean_v1_file_has_no_header_findings(clean_file):
    """The bundled clean v1 fixture must not trip header_injection/encoding_mismatch."""
    findings = check_malformed(clean_file.read_bytes())
    types = {f.type for f in findings}
    assert "header_injection" not in types
    assert "encoding_mismatch" not in types


def test_clean_v1_inline_header_no_findings():
    payload = _V1_HEADER + b"\n<OFX><BANKACCTFROM><ACCTID>9876</ACCTID></BANKACCTFROM></OFX>"
    findings = check_malformed(payload)
    types = {f.type for f in findings}
    assert "header_injection" not in types
    assert "encoding_mismatch" not in types


def test_second_header_block_in_body_is_header_injection():
    # A second OFXHEADER: block smuggled into the SGML body.
    payload = (
        _V1_HEADER
        + b"\n<OFX>\n"
        + b"OFXHEADER:100\nVERSION:102\nENCODING:UTF-8\n\n"
        + b"<BANKACCTFROM><ACCTID>9876</ACCTID></BANKACCTFROM></OFX>"
    )
    findings = check_malformed(payload)
    types = {f.type for f in findings}
    assert "header_injection" in types, f"got: {types}"
    inj = next(f for f in findings if f.type == "header_injection")
    assert inj.severity == "high"
    assert inj.check == "malformed"


def test_disallowed_encoding_value_is_encoding_mismatch():
    payload = (
        b"OFXHEADER:100\n"
        b"DATA:OFXSGML\n"
        b"VERSION:102\n"
        b"ENCODING:WINDOWS-1252\n"  # not in the allowed set
        b"CHARSET:1252\n"
        b"\n<OFX></OFX>"
    )
    findings = check_malformed(payload)
    mism = [f for f in findings if f.type == "encoding_mismatch"]
    assert mism, "expected an encoding_mismatch finding"
    assert mism[0].severity == "medium"


def test_allowed_encodings_not_flagged():
    for enc in (b"USASCII", b"UTF-8", b"UNICODE"):
        payload = (
            b"OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n"
            b"ENCODING:" + enc + b"\nCHARSET:1252\n\n<OFX></OFX>"
        )
        findings = check_malformed(payload)
        assert all(
            f.type != "encoding_mismatch" for f in findings
        ), f"{enc!r} should be allowed"


def test_odd_charset_is_encoding_mismatch():
    payload = (
        b"OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n"
        b"ENCODING:USASCII\nCHARSET:UTF-7\n\n<OFX></OFX>"
    )
    findings = check_malformed(payload)
    assert any(f.type == "encoding_mismatch" for f in findings)


def test_numeric_charset_not_flagged():
    payload = (
        b"OFXHEADER:100\nDATA:OFXSGML\nVERSION:102\n"
        b"ENCODING:USASCII\nCHARSET:1252\n\n<OFX></OFX>"
    )
    findings = check_malformed(payload)
    assert all(f.type != "encoding_mismatch" for f in findings)


def test_control_byte_in_header_is_encoding_mismatch():
    payload = (
        b"OFXHEADER:100\nDATA:OFXSGML\n"
        b"VERSION:\x01102\n"  # control byte smuggled into a header value
        b"ENCODING:USASCII\n\n<OFX></OFX>"
    )
    findings = check_malformed(payload)
    mism = [f for f in findings if f.type == "encoding_mismatch"]
    assert mism, "expected an encoding_mismatch finding for control byte"
    assert mism[0].metadata.get("byte_value") == 1


def test_v2_xml_file_not_treated_as_v1_header():
    # An OFX v2 (pure XML) document has no SGML header block -- the v1 header
    # checks must not fire on it.
    payload = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<?OFX OFXHEADER="200" VERSION="211"?>\n'
        b"<OFX><BANKACCTFROM><ACCTID>9876</ACCTID></BANKACCTFROM></OFX>"
    )
    findings = check_malformed(payload)
    types = {f.type for f in findings}
    assert "header_injection" not in types
    assert "encoding_mismatch" not in types
