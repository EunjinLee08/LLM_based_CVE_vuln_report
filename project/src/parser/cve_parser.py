"""Normalize NVD CVE payloads."""

from __future__ import annotations

from typing import Any

from src.models import CveRecord


def parse_nvd_payload(payload: dict[str, Any]) -> list[CveRecord]:
    """Convert an NVD API response into normalized CVE records."""

    records: list[CveRecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = _first_cvss_metric(metrics)

        records.append(
            CveRecord(
                cve_id=cve.get("id", "UNKNOWN-CVE"),
                summary=_english_description(cve.get("descriptions", [])),
                published=cve.get("published"),
                modified=cve.get("lastModified"),
                severity=cvss.get("baseSeverity"),
                score=cvss.get("baseScore"),
                references=tuple(ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")),
            )
        )

    return records


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _first_cvss_metric(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            return values[0].get("cvssData", {})
    return {}

