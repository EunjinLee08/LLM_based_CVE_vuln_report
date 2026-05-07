"""Build prompts for LLM-based CVE report generation."""

from __future__ import annotations

from src.models import CveRecord


def build_report_prompt(keyword: str, records: list[CveRecord]) -> str:
    """Create a compact prompt that can be sent to an LLM."""

    evidence = "\n\n".join(_format_record(record) for record in records)
    return (
        "You are a security analyst. Write a concise Korean vulnerability report.\n"
        f"Target keyword: {keyword}\n\n"
        "Use the CVE evidence below. Include impact, risk level, affected clues, "
        "recommended mitigations, and references.\n\n"
        f"{evidence}"
    )


def _format_record(record: CveRecord) -> str:
    references = "\n".join(f"- {url}" for url in record.references[:5]) or "- No references"
    return (
        f"CVE: {record.cve_id}\n"
        f"Severity: {record.severity or 'UNKNOWN'} ({record.score if record.score is not None else 'N/A'})\n"
        f"Published: {record.published or 'N/A'}\n"
        f"Summary: {record.summary}\n"
        f"References:\n{references}"
    )

