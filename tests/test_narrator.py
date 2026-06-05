from unittest.mock import MagicMock
import pytest
from aivas.narrator.narrator import narrate, _parse_narration


def test_parse_narration_valid_json():
    result = _parse_narration('{"en": "Risk found.", "sw": "Hatari imegunduliwa."}')
    assert result["en"] == "Risk found."
    assert result["sw"] == "Hatari imegunduliwa."


def test_parse_narration_json_with_preamble():
    text = 'Sure! Here is the JSON:\n{"en": "Critical risk.", "sw": "Hatari kubwa."}'
    result = _parse_narration(text)
    assert result["en"] == "Critical risk."


def test_parse_narration_bad_json_returns_empty():
    result = _parse_narration("Sorry, I cannot help with that.")
    assert result["en"] == ""
    assert result["sw"] == ""
    assert result["fix_en"] == ""
    assert result["fix_sw"] == ""


def test_narrate_enriches_findings():
    provider = MagicMock()
    provider.generate.return_value = '{"en": "Critical path traversal.", "sw": "Tatizo kubwa la njia."}'

    findings = [{
        "cve_id": "CVE-2021-41773",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "description": "Path traversal in Apache 2.4.49",
        "confidence": "probable",
    }]
    result = narrate(findings, provider)
    assert len(result) == 1
    assert result[0]["narration_en"] == "Critical path traversal."
    assert result[0]["narration_sw"] == "Tatizo kubwa la njia."


def test_narrate_preserves_original_fields():
    provider = MagicMock()
    provider.generate.return_value = '{"en": "test", "sw": "jaribio"}'

    findings = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                 "cvss_severity": "CRITICAL", "description": "desc", "confidence": "probable"}]
    result = narrate(findings, provider)
    assert result[0]["cve_id"] == "CVE-2021-41773"
    assert result[0]["cvss_score"] == 9.8


def test_narrate_falls_back_on_provider_error():
    provider = MagicMock()
    provider.generate.side_effect = RuntimeError("connection refused")

    findings = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                 "cvss_severity": "CRITICAL", "description": "Original desc.", "confidence": "probable"}]
    result = narrate(findings, provider)
    assert result[0]["narration_en"] == "Original desc."
    assert result[0]["narration_sw"] == ""


def test_narrate_multiple_findings():
    provider = MagicMock()
    provider.generate.return_value = '{"en": "Risk.", "sw": "Hatari."}'

    findings = [
        {"cve_id": "CVE-A", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
         "description": "desc A", "confidence": "probable"},
        {"cve_id": "CVE-B", "cvss_score": 5.0, "cvss_severity": "MEDIUM",
         "description": "desc B", "confidence": "possible"},
    ]
    result = narrate(findings, provider)
    assert len(result) == 2
    assert provider.generate.call_count == 2


def test_parse_narration_extracts_fix_fields():
    text = '{"en": "Risk desc.", "sw": "Hatari.", "fix_en": "Update now.", "fix_sw": "Sasisha sasa."}'
    result = _parse_narration(text)
    assert result["fix_en"] == "Update now."
    assert result["fix_sw"] == "Sasisha sasa."


def test_parse_narration_fix_fields_default_empty():
    text = '{"en": "Risk.", "sw": "Hatari."}'
    result = _parse_narration(text)
    assert result["fix_en"] == ""
    assert result["fix_sw"] == ""


def test_narrate_adds_fix_fields():
    provider = MagicMock()
    provider.generate.return_value = (
        '{"en": "Risk.", "sw": "Hatari.", "fix_en": "Patch it.", "fix_sw": "Rekebisha."}'
    )
    findings = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                 "cvss_severity": "CRITICAL", "description": "test", "confidence": "probable"}]
    result = narrate(findings, provider)
    assert result[0]["fix_en"] == "Patch it."
    assert result[0]["fix_sw"] == "Rekebisha."
