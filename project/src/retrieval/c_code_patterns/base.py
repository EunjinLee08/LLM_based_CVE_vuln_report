"""Base models and helpers for lightweight C vulnerability family scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Iterable, Protocol


@dataclass(frozen=True)
class CPatternFinding:
    """A lightweight evidence item found in C/C++ source code."""

    family: str
    cwe: list[str]
    file_path: str
    line_no: int
    sink: str
    evidence: str
    reason: str
    query_terms: list[str]
    confidence: float = 0.5
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CPatternSpec:
    """Definition of a C vulnerability family."""

    family: str
    cwe: list[str]
    query_terms: list[str]
    description: str


class CPatternScanner(Protocol):
    """Interface implemented by each vulnerability family scanner."""

    spec: CPatternSpec

    def scan_text(self, text: str, file_path: str) -> list[CPatternFinding]:
        ...


C_SOURCE_EXTENSIONS = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".hh",
}


COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
COMMENT_LINE_RE = re.compile(r"//.*")


def is_c_source(path: Path) -> bool:
    return path.suffix.lower() in C_SOURCE_EXTENSIONS


def strip_comments(text: str) -> str:
    """Remove simple C/C++ comments.

    This is intentionally lightweight. It is enough for initial evidence
    extraction, but not a full C lexer.
    """
    text = COMMENT_BLOCK_RE.sub("", text)
    text = COMMENT_LINE_RE.sub("", text)
    return text


def iter_source_files(root: Path) -> Iterable[Path]:
    if root.is_file() and is_c_source(root):
        yield root
        return

    if not root.exists():
        return

    for path in root.rglob("*"):
        if path.is_file() and is_c_source(path):
            yield path


def line_number_at(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def get_line(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def is_string_literal(expr: str) -> bool:
    expr = expr.strip()
    return bool(re.fullmatch(r'L?"([^"\\]|\\.)*"', expr))


def split_c_args(arg_text: str) -> list[str]:
    """Split C function arguments at top-level commas.

    Handles simple nesting and string literals well enough for first-pass scanning.
    """
    args: list[str] = []
    current: list[str] = []

    depth = 0
    in_string = False
    in_char = False
    escaped = False

    for ch in arg_text:
        if escaped:
            current.append(ch)
            escaped = False
            continue

        if ch == "\\":
            current.append(ch)
            escaped = True
            continue

        if in_string:
            current.append(ch)
            if ch == '"':
                in_string = False
            continue

        if in_char:
            current.append(ch)
            if ch == "'":
                in_char = False
            continue

        if ch == '"':
            current.append(ch)
            in_string = True
            continue

        if ch == "'":
            current.append(ch)
            in_char = True
            continue

        if ch in "([{":
            depth += 1
            current.append(ch)
            continue

        if ch in ")]}":
            depth = max(0, depth - 1)
            current.append(ch)
            continue

        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue

        current.append(ch)

    if current:
        args.append("".join(current).strip())

    return args


def find_function_calls(text: str, names: Iterable[str]) -> Iterable[tuple[str, int, str]]:
    """Yield (function_name, start_index, argument_text) for simple C calls."""
    escaped_names = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    if not escaped_names:
        return

    call_re = re.compile(rf"\b({escaped_names})\s*\(")

    for match in call_re.finditer(text):
        name = match.group(1)
        open_paren = match.end() - 1
        close_paren = find_matching_paren(text, open_paren)
        if close_paren is None:
            continue

        arg_text = text[open_paren + 1 : close_paren]
        yield name, match.start(), arg_text


def find_matching_paren(text: str, open_index: int) -> int | None:
    depth = 0
    in_string = False
    in_char = False
    escaped = False

    for i in range(open_index, len(text)):
        ch = text[i]

        if escaped:
            escaped = False
            continue

        if ch == "\\":
            escaped = True
            continue

        if in_string:
            if ch == '"':
                in_string = False
            continue

        if in_char:
            if ch == "'":
                in_char = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "'":
            in_char = True
            continue

        if ch == "(":
            depth += 1
            continue

        if ch == ")":
            depth -= 1
            if depth == 0:
                return i

    return None


def looks_like_external_input(expr: str) -> bool:
    """Heuristic for external or attacker-influenced input in C code."""
    lowered = expr.lower()

    suspicious_terms = [
        "argv",
        "getenv",
        "scanf",
        "fscanf",
        "sscanf",
        "gets",
        "fgets",
        "recv",
        "read",
        "input",
        "user",
        "param",
        "query",
        "request",
        "buf",
        "buffer",
        "data",
        "msg",
        "message",
        "name",
        "path",
        "filename",
        "cmd",
    ]

    return any(term in lowered for term in suspicious_terms)


def contains_suspicious_path_token(expr: str) -> bool:
    lowered = expr.lower()
    return any(token in lowered for token in ["..", "path", "file", "filename", "dir", "argv", "input", "user"])


def clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))