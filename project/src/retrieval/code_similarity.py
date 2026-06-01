"""Similarity search between known vulnerability evidence and source code."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from src.models import CodeSnippet, CveRecord, SimilarityFinding, SourceFile, VulnerabilityPattern


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".ts",
}

RISK_TERMS = {
    "alloc",
    "atoi",
    "auth",
    "buffer",
    "copy",
    "decode",
    "escape",
    "free",
    "gets",
    "html",
    "integer",
    "length",
    "malloc",
    "memcpy",
    "null",
    "overflow",
    "pointer",
    "random",
    "realloc",
    "session",
    "size",
    "sprintf",
    "sql",
    "strcat",
    "strcpy",
    "xss",
}

STOPWORDS = {
    "and",
    "are",
    "before",
    "could",
    "does",
    "from",
    "have",
    "into",
    "that",
    "the",
    "this",
    "through",
    "via",
    "when",
    "with",
}

def _code_tokens(text: str) -> list[str]:
    """Normalize code into language-agnostic tokens for similarity matching."""
    text = re.sub(r"//.*?$|/\*.*?\*/|#.*?$", " ", text, flags=re.MULTILINE | re.DOTALL)
    text = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " STR ", text)
    text = re.sub(r"\b\d+\b", " NUM ", text)

    raw_tokens = re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|&&|\|\||[{}()\[\];,.*+\-/%=<>]",
        text,
    )

    normalized = []
    for token in raw_tokens:
        if re.match(r"[A-Za-z_][A-Za-z0-9_]*", token):
            pieces = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", token).replace("_", " ").split()
            normalized.extend(piece.lower() for piece in pieces if len(piece) > 1)
        else:
            normalized.append(token)

    return [token for token in normalized if token not in STOPWORDS]


def _ngrams(tokens: list[str], n: int = 5) -> set[tuple[str, ...]]:
    if len(tokens) < n:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[index : index + n]) for index in range(len(tokens) - n + 1)}


def _jaccard(left: set, right: set) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _code_similarity(left_text: str, right_text: str) -> float:
    left_tokens = _code_tokens(left_text)
    right_tokens = _code_tokens(right_text)

    token_score = _jaccard(set(left_tokens), set(right_tokens))
    ngram_score = _jaccard(_ngrams(left_tokens, 5), _ngrams(right_tokens, 5))
    line_score = _line_overlap_score(left_text, right_text)

    # 코드 구조 유사도를 가장 크게 반영
    return min(
        1.0,
        0.25 * token_score
        + 0.55 * ngram_score
        + 0.20 * line_score,
    )

def patterns_from_cves(records: list[CveRecord]) -> list[VulnerabilityPattern]:
    """Use CVE summaries as fallback vulnerability patterns."""

    return [
        VulnerabilityPattern(
            pattern_id=record.cve_id,
            title=record.cve_id,
            text=record.summary,
            severity=record.severity,
            score=record.score,
            references=record.references,
        )
        for record in records
    ]


def patterns_from_code_dir(directory: Path) -> list[VulnerabilityPattern]:
    """Load previously reported vulnerable code samples from a directory."""

    patterns: list[VulnerabilityPattern] = []
    for path in sorted(_iter_source_paths(directory)):
        code = path.read_text(encoding="utf-8", errors="replace")
        pattern_id = path.stem
        patterns.append(
            VulnerabilityPattern(
                pattern_id=pattern_id,
                title=pattern_id.replace("_", " "),
                text=f"Previously reported vulnerable code sample: {path.name}",
                code=code,
            )
        )
    return patterns


def load_source_files(directory: Path) -> list[SourceFile]:
    """Read source-like files under a local directory."""

    source_files: list[SourceFile] = []
    for path in sorted(_iter_source_paths(directory)):
        source_files.append(
            SourceFile(
                url=str(path),
                path=str(path.relative_to(directory)),
                content=path.read_text(encoding="utf-8", errors="replace"),
            )
        )
    return source_files


def find_similar_vulnerable_code(
    patterns: list[VulnerabilityPattern],
    source_files: list[SourceFile],
    threshold: float = 0.18,
    max_findings: int = 20,
) -> list[SimilarityFinding]:
    """Rank source snippets by similarity to known vulnerability patterns."""

    findings: list[SimilarityFinding] = []
    pattern_vectors = [(_pattern_text(pattern), _token_counter(_pattern_text(pattern))) for pattern in patterns]

    for source_file in source_files:
        for snippet in split_source(source_file):
            snippet_counter = _token_counter(snippet.text)
            if not snippet_counter:
                continue

            for pattern, (pattern_text, pattern_counter) in zip(patterns, pattern_vectors):
                similarity = _weighted_similarity(pattern_counter, snippet_counter)

                if pattern.code:
                    code_score = _code_similarity(pattern.code, snippet.text)
                    similarity = max(similarity, code_score)

                if similarity < threshold:
                    continue

                matched_terms = _matched_terms(pattern_text, snippet.text)
                findings.append(
                    SimilarityFinding(
                        pattern=pattern,
                        snippet=snippet,
                        similarity=similarity,
                        matched_terms=matched_terms,
                        reason=_reason(matched_terms, pattern.code is not None),
                    )
                )

    findings.sort(key=lambda finding: finding.similarity, reverse=True)
    return findings[:max_findings]


def split_source(source_file: SourceFile, max_lines: int = 80) -> list[CodeSnippet]:
    """Split code into function-like chunks, falling back to fixed windows."""

    lines = source_file.content.splitlines()
    chunks: list[CodeSnippet] = []
    start = 0
    brace_depth = 0
    in_function = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        looks_like_function = bool(re.search(r"\w[\w\s\*]+\([^;]*\)\s*\{?\s*$", stripped))
        if not in_function and looks_like_function:
            start = index
            in_function = True

        brace_depth += line.count("{") - line.count("}")
        if in_function and brace_depth <= 0 and "}" in line:
            chunks.append(_make_snippet(source_file.path, lines, start, index))
            in_function = False

    if not chunks:
        for start_index in range(0, len(lines), max_lines):
            end_index = min(start_index + max_lines, len(lines)) - 1
            chunks.append(_make_snippet(source_file.path, lines, start_index, end_index))

    return [chunk for chunk in chunks if chunk.text.strip()]


def _iter_source_paths(directory: Path) -> list[Path]:
    if not directory.exists():
        raise ValueError(f"Directory does not exist: {directory}")
    if not directory.is_dir():
        raise ValueError(f"Expected a directory: {directory}")
    return [
        path
        for path in directory.rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS
    ]


def _make_snippet(file_path: str, lines: list[str], start: int, end: int) -> CodeSnippet:
    return CodeSnippet(
        file_path=file_path,
        start_line=start + 1,
        end_line=end + 1,
        text="\n".join(lines[start : end + 1]),
    )


def _pattern_text(pattern: VulnerabilityPattern) -> str:
    return "\n".join(part for part in (pattern.text, pattern.code or "") if part)


def _token_counter(text: str) -> Counter[str]:
    tokens = []
    for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", text):
        pieces = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", raw).replace("_", " ").split()
        tokens.extend(piece.lower() for piece in pieces)
    return Counter(token for token in tokens if len(token) > 2 and token not in STOPWORDS)


def _weighted_similarity(left: Counter[str], right: Counter[str]) -> float:
    shared = set(left) & set(right)
    if not shared:
        return 0.0

    dot = sum(left[token] * right[token] for token in shared)
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    cosine = dot / (left_norm * right_norm) if left_norm and right_norm else 0.0

    risk_overlap = len(shared & RISK_TERMS) / max(len(RISK_TERMS), 1)
    return min(1.0, cosine + risk_overlap)


def _line_overlap_score(left_text: str, right_text: str) -> float:
    left_lines = _normalized_code_lines(left_text)
    right_lines = _normalized_code_lines(right_text)
    if not left_lines or not right_lines:
        return 0.0
    return len(left_lines & right_lines) / len(left_lines | right_lines)


def _normalized_code_lines(text: str) -> set[str]:
    lines = set()
    for line in text.splitlines():
        normalized = re.sub(r"\s+", " ", line.strip())
        if normalized and not normalized.startswith(("//", "/*", "*")):
            lines.add(normalized)
    return lines


def _matched_terms(pattern_text: str, snippet_text: str) -> tuple[str, ...]:
    pattern_tokens = set(_token_counter(pattern_text))
    snippet_tokens = set(_token_counter(snippet_text))
    terms = sorted((pattern_tokens & snippet_tokens), key=lambda token: (token not in RISK_TERMS, token))
    return tuple(terms[:12])


def _reason(matched_terms: tuple[str, ...], used_code_sample: bool) -> str:
    if used_code_sample:
        return "known vulnerable code sample shares code/token structure"
    if matched_terms:
        return "CVE vulnerability description shares risk terms with this code"
    return "source snippet is similar to known vulnerability evidence"
