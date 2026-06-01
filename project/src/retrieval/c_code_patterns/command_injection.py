"""Lightweight scanner for CWE-78 OS command injection candidates."""

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
    family="command_injection",
    cwe=["CWE-78"],
    query_terms=[
        "OS command injection",
        "command injection",
        "CWE-78",
    ],
    description="Externally influenced command passed to system execution functions.",
)


COMMAND_SINKS = {
    "system": 0,
    "popen": 0,
    "execl": 0,
    "execlp": 0,
    "execle": 0,
    "execv": 0,
    "execvp": 0,
    "execve": 0,
}


class CommandInjectionScanner:
    spec = SPEC

    def scan_text(self, text: str, file_path: str) -> list[CPatternFinding]:
        cleaned = strip_comments(text)
        findings: list[CPatternFinding] = []

        for sink, index, arg_text in find_function_calls(cleaned, COMMAND_SINKS.keys()):
            args = split_c_args(arg_text)
            cmd_index = COMMAND_SINKS[sink]

            if len(args) <= cmd_index:
                continue

            cmd_arg = args[cmd_index].strip()

            if is_string_literal(cmd_arg) and sink.startswith("exec"):
                continue

            confidence = 0.5
            reason = "command execution sink is used"

            if not is_string_literal(cmd_arg):
                confidence = 0.7
                reason = "command argument is not a fixed string literal"

            if looks_like_external_input(cmd_arg):
                confidence = 0.85
                reason = "command argument appears externally influenced"

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
                    reason=reason,
                    query_terms=SPEC.query_terms,
                    confidence=confidence,
                    metadata={"command_argument": cmd_arg},
                )
            )

        return findings