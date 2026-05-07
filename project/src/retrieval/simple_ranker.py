"""Simple keyword-based ranking for CVE records."""

from __future__ import annotations

from src.models import CveRecord


def rank_by_keyword(records: list[CveRecord], keyword: str) -> list[CveRecord]:
    """Rank records by keyword frequency and CVSS score."""

    normalized_keyword = keyword.lower()

    def score(record: CveRecord) -> tuple[int, float]:
        text = f"{record.cve_id} {record.summary}".lower()
        keyword_hits = text.count(normalized_keyword)
        cvss_score = record.score or 0.0
        return keyword_hits, cvss_score

    return sorted(records, key=score, reverse=True)

