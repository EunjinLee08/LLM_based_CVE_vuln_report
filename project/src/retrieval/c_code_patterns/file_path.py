"""Lightweight scanner for unsafe file/path access candidates."""

from __future__ import annotations

from .base import (
    CPatternFinding,
    CPatternSpec,
    contains_suspicious_path_token,
    find_function_calls,
    get_line,
    is_string_literal,
    line_number_at,
    split_c_args,
    strip_comments,
)


SPEC = CPatternSpec(
    family="unsafe_file_path",
    cwe=["CWE-22"],
    query_terms=[
        "path traversal",
        "directory traversal",
        "unsafe file access",
        "CWE-22",
    ],
    description="Externally influenced path passed to file-system APIs.",
)


PATH_SINKS = {
    "fopen": 0,
    "open": 0,
    "creat": 0,
    "remove": 0,
    "unlink": 0,
    "rename": 0,
    "stat": 0,
    "lstat": 0,
    "access": 0,
}


class FilePathScanner:
    spec = SPEC

    def scan_text(self, text: str, file_path: str) -> list[CPatternFinding]:
        cleaned = strip_comments(text)
        findings: list[CPatternFinding] = []

        for sink, index, arg_text in find_function_calls(cleaned, PATH_SINKS.keys()):
            args = split_c_args(arg_text)
            path_index = PATH_SINKS[sink]

            if len(args) <= path_index:
                continue

            path_arg = args[path_index].strip()

            if is_string_literal(path_arg):
                continue

            if not contains_suspicious_path_token(path_arg):
                continue

            line_no = line_number_at(cleaned, index)
            evidence = get_line(text, line_no)

            findings.append(
                CPatternFinding(
                    family=SPEC.family,
                    cwe=SPEC.cwe,
                    file_path=file_path,
                    line_no=line_no,
                    sink=sink,
                    evidence=evidence,
                    reason="file path argument appears variable or externally influenced",
                    query_terms=SPEC.query_terms,
                    confidence=0.65,
                    metadata={"path_argument": path_arg},
                )
            )

        return findings