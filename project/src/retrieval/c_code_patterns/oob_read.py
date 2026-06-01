"""Lightweight scanner for C out-of-bounds read candidates."""

from __future__ import annotations

import re

from .base import CPatternFinding, CPatternSpec, get_line, line_number_at, strip_comments


SPEC = CPatternSpec(
    family="out_of_bounds_read",
    cwe=["CWE-125"],
    query_terms=[
        "out-of-bounds read",
        "OOB read",
        "CWE-125",
    ],
    description="Potential array read using externally influenced index or unchecked length.",
)


ARRAY_ACCESS_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*|\d+)\s*\]")


class OutOfBoundsReadScanner:
    spec = SPEC

    def scan_text(self, text: str, file_path: str) -> list[CPatternFinding]:
        cleaned = strip_comments(text)
        findings: list[CPatternFinding] = []

        for match in ARRAY_ACCESS_RE.finditer(cleaned):
            array_name = match.group(1)
            index_expr = match.group(2)

            if index_expr.isdigit():
                continue

            lower_index = index_expr.lower()
            if lower_index not in {"i", "idx", "index", "pos", "offset", "len", "length", "n"}:
                continue

            line_no = line_number_at(cleaned, match.start())
            evidence = get_line(text, line_no)

            if "=" in evidence and evidence.find("=") < evidence.find("["):
                # Likely write-side assignment, leave it to OOB write/buffer family.
                continue

            findings.append(
                CPatternFinding(
                    family=SPEC.family,
                    cwe=SPEC.cwe,
                    file_path=file_path,
                    line_no=line_no,
                    sink=f"{array_name}[]",
                    evidence=evidence,
                    reason="array read uses variable index; bounds check should be verified",
                    query_terms=SPEC.query_terms,
                    confidence=0.45,
                    metadata={"array": array_name, "index": index_expr},
                )
            )

        return findings