"""Basic validation rules for report generation."""

from __future__ import annotations


def validate_keyword(keyword: str) -> None:
    """Raise ValueError when the search keyword is not usable."""

    if not keyword or not keyword.strip():
        raise ValueError("검색 키워드를 입력해야 합니다.")


def validate_report(report: str) -> None:
    """Raise ValueError when a generated report is too small to be useful."""

    if len(report.strip()) < 50:
        raise ValueError("생성된 리포트가 너무 짧습니다.")
