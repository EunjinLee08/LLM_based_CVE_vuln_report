"""Lightweight scanner for C buffer overflow / out-of-bounds write candidates."""

from __future__ import annotations

import re

from .base import (
    CPatternFinding,
    CPatternSpec,
    find_function_calls,
    get_line,
    line_number_at,
    looks_like_external_input,
    split_c_args,
    strip_comments,
)


SPEC = CPatternSpec(
    family="buffer_overflow",
    cwe=["CWE-787", "CWE-120"],
    query_terms=[
        "buffer overflow",
        "out-of-bounds write",
        "CWE-787",
        "CWE-120",
    ],
    description="Potential unsafe write to fixed-size or unchecked buffer.",
)


UNSAFE_COPY_SINKS = {
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
}

SIZE_BASED_COPY_SINKS = {
    "memcpy",
    "memmove",
    "strncpy",
    "strncat",
    "snprintf",
}


FIXED_BUFFER_DECL_RE = re.compile(
    r"\b(?:char|unsigned\s+char|signed\s+char|int|long|short)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]"
)


class BufferOverflowScanner:
    spec = SPEC

    def scan_text(self, text: str, file_path: str) -> list[CPatternFinding]:
        cleaned = strip_comments(text)
        findings: list[CPatternFinding] = []

        fixed_buffers = {
            match.group(1): int(match.group(2))
            for match in FIXED_BUFFER_DECL_RE.finditer(cleaned)
        }

        for sink, index, arg_text in find_function_calls(cleaned, UNSAFE_COPY_SINKS):
            args = split_c_args(arg_text)
            line_no = line_number_at(cleaned, index)
            evidence = get_line(text, line_no)

            confidence = 0.65
            reason = f"{sink} is an unsafe unbounded write/copy function"

            if sink == "gets":
                confidence = 0.95
                reason = "gets reads input without a size bound"

            if args:
                dst = args[0].strip()
                if dst in fixed_buffers:
                    confidence = max(confidence, 0.8)
                    reason += f"; destination appears to be fixed-size buffer {dst}[{fixed_buffers[dst]}]"

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
                    metadata={"arguments": arg_text},
                )
            )

        for sink, index, arg_text in find_function_calls(cleaned, SIZE_BASED_COPY_SINKS):
            args = split_c_args(arg_text)
            if not args:
                continue

            line_no = line_number_at(cleaned, index)
            evidence = get_line(text, line_no)

            reason_parts = []
            confidence = 0.4

            dst = args[0].strip()
            if dst in fixed_buffers:
                reason_parts.append(f"destination appears to be fixed-size buffer {dst}[{fixed_buffers[dst]}]")
                confidence = 0.55

            if len(args) >= 3:
                size_expr = args[2].strip()
                if looks_like_external_input(size_expr):
                    reason_parts.append("copy size appears externally influenced")
                    confidence = max(confidence, 0.7)

                if re.fullmatch(r"\d+", size_expr) and dst in fixed_buffers:
                    if int(size_expr) > fixed_buffers[dst]:
                        reason_parts.append("constant copy size is larger than destination buffer")
                        confidence = max(confidence, 0.9)

            if not reason_parts:
                continue

            findings.append(
                CPatternFinding(
                    family=SPEC.family,
                    cwe=SPEC.cwe,
                    file_path=file_path,
                    line_no=line_no,
                    sink=sink,
                    evidence=evidence,
                    reason="; ".join(reason_parts),
                    query_terms=SPEC.query_terms,
                    confidence=confidence,
                    metadata={"arguments": arg_text},
                )
            )

        return findings