"""Aggregate scanner for C vulnerability family evidence."""

from __future__ import annotations

from pathlib import Path

from .base import CPatternFinding, iter_source_files
from .buffer_overflow import BufferOverflowScanner
from .command_injection import CommandInjectionScanner
from .file_path import FilePathScanner
from .format_string import FormatStringScanner
from .oob_read import OutOfBoundsReadScanner


DEFAULT_SCANNERS = [
    FormatStringScanner(),
    BufferOverflowScanner(),
    OutOfBoundsReadScanner(),
    CommandInjectionScanner(),
    FilePathScanner(),
]


def scan_c_code_path(path: str | Path) -> list[CPatternFinding]:
    root = Path(path)
    findings: list[CPatternFinding] = []

    for source_file in iter_source_files(root):
        try:
            text = source_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for scanner in DEFAULT_SCANNERS:
            findings.extend(scanner.scan_text(text, str(source_file)))

    return sorted(
        findings,
        key=lambda item: (item.file_path, item.line_no, -item.confidence),
    )

def scan_c_source_texts(source_files) -> list[CPatternFinding]:
    findings: list[CPatternFinding] = []

    for source_file in source_files:
        for scanner in DEFAULT_SCANNERS:
            findings.extend(scanner.scan_text(source_file.content, source_file.path))

    return sorted(
        findings,
        key=lambda item: (item.file_path, item.line_no, -item.confidence),
    )


def collect_query_terms(findings: list[CPatternFinding]) -> list[str]:
    terms: list[str] = []
    seen: set[str] = set()

    for finding in findings:
        for term in finding.query_terms:
            if term not in seen:
                seen.add(term)
                terms.append(term)

    return terms


def summarize_families(findings: list[CPatternFinding]) -> dict[str, int]:
    summary: dict[str, int] = {}

    for finding in findings:
        summary[finding.family] = summary.get(finding.family, 0) + 1

    return summary

def collect_family_queries(findings: list[CPatternFinding]) -> list[str]:
    family_terms: dict[str, list[str]] = {}

    for finding in findings:
        if finding.family not in family_terms:
            family_terms[finding.family] = []

        for term in finding.query_terms:
            if term not in family_terms[finding.family]:
                family_terms[finding.family].append(term)

    queries: list[str] = []

    for family, terms in family_terms.items():
        # 너무 긴 query는 NVD 검색 품질을 떨어뜨릴 수 있으므로 앞 2~3개만 사용
        if family == "format_string":
            queries.append("format string vulnerability CWE-134")
        elif family == "command_injection":
            queries.append("OS command injection CWE-78")
        elif family == "buffer_overflow":
            queries.append("buffer overflow out-of-bounds write CWE-787")
        elif family == "out_of_bounds_read":
            queries.append("out-of-bounds read CWE-125")
        elif family == "unsafe_file_path":
            queries.append("path traversal directory traversal CWE-22")
        else:
            queries.append(" ".join(terms[:3]))

    return queries