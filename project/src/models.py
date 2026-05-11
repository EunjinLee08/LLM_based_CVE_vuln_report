"""Shared data models used across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CveRecord:
    """Normalized CVE information used by parser, retrieval, and reporting."""

    cve_id: str
    summary: str
    published: str | None = None
    modified: str | None = None
    severity: str | None = None
    score: float | None = None
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReportSection:
    """A single rendered section in the final report."""

    title: str
    body: str


@dataclass(frozen=True)
class SourceFile:
    """Source code file fetched from a URL without cloning a repository."""

    url: str
    path: str
    content: str


@dataclass(frozen=True)
class VulnerabilityPattern:
    """Evidence for a previously reported vulnerability."""

    pattern_id: str
    title: str
    text: str
    code: str | None = None
    severity: str | None = None
    score: float | None = None
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CodeSnippet:
    """A source-code region used as a similarity-search candidate."""

    file_path: str
    start_line: int
    end_line: int
    text: str


@dataclass(frozen=True)
class SimilarityFinding:
    """A possible vulnerability inferred from similarity to known evidence."""

    pattern: VulnerabilityPattern
    snippet: CodeSnippet
    similarity: float
    matched_terms: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class LlmJudgment:
    """LLM review result for one similarity finding."""

    finding_index: int
    risk: str
    confidence: float | None
    rationale: str
    attack_conditions: str
    verification_steps: str
    recommended_fix: str
    false_positive_notes: str
    raw_response: str
