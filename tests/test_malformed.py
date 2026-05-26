"""Tests for the malformed/parser-confusion check.

These tests operate on raw bytes -- the malformed check must NEVER hand a
hostile file to a real parser, so detection is structural and pre-parse.
"""

from __future__ import annotations

from ferryman.checks.malformed import check_malformed


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
