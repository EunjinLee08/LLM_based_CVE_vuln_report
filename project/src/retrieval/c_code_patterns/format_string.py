"""Lightweight scanner for CWE-134 format string candidates."""

from __future__ import annotations

from .base import (
    CPatternFinding,
    CPatternSpec,
    find_function_calls,
    get_line,
    is_string_literal,
    line_number_at,
    looks_like_external_input,
    split_c_args,
    strip_comments,
)


SPEC = CPatternSpec(
    family="format_string",
    cwe=["CWE-134"],
    query_terms=[
        "format string vulnerability",
        "externally controlled format string",
        "CWE-134",
    ],
    description="Externally controlled format string in printf-like functions.",
)


FORMAT_ARG_INDEX = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "vprintf": 0,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "syslog": 1,
}


class FormatStringScanner:
    spec = SPEC

    def scan_text(self, text: str, file_path: str) -> list[CPatternFinding]:
        cleaned = strip_comments(text)
        findings: list[CPatternFinding] = []

        for sink, index, arg_text in find_function_calls(cleaned, FORMAT_ARG_INDEX.keys()):
            args = split_c_args(arg_text)
            fmt_index = FORMAT_ARG_INDEX[sink]

            if len(args) <= fmt_index:
                continue

            fmt_arg = args[fmt_index].strip()

            if is_string_literal(fmt_arg):
                continue

            line_no = line_number_at(cleaned, index)
            evidence = get_line(text, line_no)

            confidence = 0.65
            reason = "format string argument is not a string literal"

            if looks_like_external_input(fmt_arg):
                confidence = 0.85
                reason = "format string argument appears externally influenced and is not a string literal"

            findings.append(
                CPatternFinding(
                    family=SPEC.family,
                    cwe=SPEC.cwe,
                    file_path=file_path,
                    line_no=line_no,
                    sink=sink,
                    evidence=evidence,
                    reason=reason,
                    query_terms=SPEC.query_terms,
                    confidence=confidence,
                    metadata={"format_argument": fmt_arg},
                )
            )

        return findings