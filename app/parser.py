# Copyright (c) 2026 Florian Fischer
# SPDX-License-Identifier: MIT

"""Pure CVE 5.0 record parser: bytes in, ParsedCVE out. No I/O."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
)

_CVSS_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0")


@dataclass
class ParsedCVE:
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published_date: datetime | None
    modified_date: datetime | None
    vendors: list[str]
    products: list[str]
    cpes: list[str]
    references: list[dict]
    advisory_url: str
    source: str = "cveorg"
    catalog_pairs: list[tuple[str, str]] = field(default_factory=list)


def _parse_flex_time(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _extract_best_cvss(metrics: list[dict]) -> tuple[float, str, str]:
    for metric in metrics or []:
        for key in _CVSS_KEYS:
            cvss = metric.get(key)
            if cvss and cvss.get("baseScore", 0) > 0:
                return (
                    float(cvss["baseScore"]),
                    cvss.get("vectorString", ""),
                    cvss.get("baseSeverity", ""),
                )
    return 0.0, "", ""


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def parse_cve_record(data: bytes) -> ParsedCVE | None:
    """Convert one CVE 5.0 JSON document into a ParsedCVE, or None to skip it.

    Skipped: state != "PUBLISHED" (RESERVED, REJECTED, ...), or empty CVE ID.
    """
    rec = json.loads(data)

    metadata = rec.get("cveMetadata", {})
    if metadata.get("state") != "PUBLISHED":
        return None
    cve_id = (metadata.get("cveId") or "").strip()
    if not cve_id:
        return None

    containers = rec.get("containers", {})
    cna = containers.get("cna", {})
    adp_list = containers.get("adp", []) or []

    published_date = _parse_flex_time(metadata.get("datePublished", ""))
    modified_date = _parse_flex_time(metadata.get("dateUpdated", ""))

    description = ""
    descriptions = cna.get("descriptions", []) or []
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    vendor_set: set[str] = set()
    product_set: set[str] = set()
    cpes: list[str] = []
    catalog_pairs: list[tuple[str, str]] = []

    for affected in cna.get("affected", []) or []:
        vendor = (affected.get("vendor") or "").strip()
        product = (affected.get("product") or "").strip()
        if vendor and vendor != "n/a":
            vendor_set.add(vendor)
        if product and product != "n/a":
            product_set.add(product)
        cpes.extend(affected.get("cpes", []) or [])
        if vendor and product and vendor != "n/a" and product != "n/a":
            catalog_pairs.append((vendor, product))

    cpes = sorted(set(cpes))

    score, vector, severity = _extract_best_cvss(cna.get("metrics", []) or [])
    if score == 0:
        for adp in adp_list:
            s, v, sev = _extract_best_cvss(adp.get("metrics", []) or [])
            if s > 0:
                score, vector, severity = s, v, sev
                break
    if not severity:
        severity = _score_to_severity(score)

    references = cna.get("references", []) or []
    advisory_url = ""
    for ref in references:
        tags = ref.get("tags", []) or []
        if "vendor-advisory" in tags or "patch" in tags:
            advisory_url = ref.get("url", "")
            break
    if not advisory_url and references:
        advisory_url = references[0].get("url", "")

    return ParsedCVE(
        cve_id=cve_id.upper(),
        title=cna.get("title", ""),
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        published_date=published_date,
        modified_date=modified_date,
        vendors=sorted(vendor_set),
        products=sorted(product_set),
        cpes=cpes,
        references=[{"url": r.get("url", ""), "tags": r.get("tags", [])} for r in references],
        advisory_url=advisory_url,
        source="cveorg",
        catalog_pairs=catalog_pairs,
    )
