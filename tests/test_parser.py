# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

from pathlib import Path

from app.parser import parse_cve_record

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_published_basic_parses_full_record():
    parsed = parse_cve_record(_load("published_basic.json"))
    assert parsed is not None
    assert parsed.cve_id == "CVE-2024-12345"
    assert parsed.title == "Example Buffer Overflow"
    assert "buffer overflow" in parsed.description.lower()
    assert parsed.severity == "CRITICAL"
    assert parsed.cvss_score == 9.8
    assert parsed.cvss_vector.startswith("CVSS:3.1")
    assert parsed.advisory_url == "https://example.com/advisory"
    assert len(parsed.references) == 2


def test_published_basic_dedupes_vendors_and_skips_na():
    parsed = parse_cve_record(_load("published_basic.json"))
    assert parsed.vendors == ["ExampleCorp"]
    assert parsed.products == ["Gadget", "Widget"]
    assert parsed.catalog_pairs == [
        ("ExampleCorp", "Widget"),
        ("ExampleCorp", "Gadget"),
    ]


def test_rejected_state_is_skipped():
    assert parse_cve_record(_load("rejected.json")) is None


def test_empty_cve_id_is_skipped():
    parsed = parse_cve_record(_load("published_basic.json").replace(b"CVE-2024-12345", b""))
    assert parsed is None


def test_falls_back_to_first_available_description():
    parsed = parse_cve_record(_load("no_en_description.json"))
    assert parsed is not None
    assert parsed.description == "Une description en francais."


def test_falls_back_to_adp_metrics_when_cna_has_none():
    parsed = parse_cve_record(_load("adp_fallback_cvss.json"))
    assert parsed is not None
    assert parsed.cvss_score == 5.5
    assert parsed.severity == "MEDIUM"


def test_falls_back_to_first_reference_when_no_preferred_tag():
    parsed = parse_cve_record(_load("adp_fallback_cvss.json"))
    assert parsed.advisory_url == "https://example.com/only-ref"


def test_empty_affected_yields_no_vendors_or_products():
    parsed = parse_cve_record(_load("empty_affected.json"))
    assert parsed is not None
    assert parsed.vendors == []
    assert parsed.products == []
    assert parsed.catalog_pairs == []


def test_severity_derived_from_score_when_missing():
    parsed = parse_cve_record(_load("empty_affected.json"))
    assert parsed.severity == "NONE"
    assert parsed.cvss_score == 0.0


def test_prefers_cvss_v3_1_over_v3_0_and_v4_0():
    parsed = parse_cve_record(_load("cvss_version_preference.json"))
    assert parsed is not None
    assert parsed.cvss_score == 8.1
    assert parsed.severity == "HIGH"
    assert parsed.cvss_vector.startswith("CVSS:3.1")
