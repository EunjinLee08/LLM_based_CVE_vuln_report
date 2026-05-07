"""Retrieval utilities select relevant evidence for reports."""

from .code_similarity import (
    find_similar_vulnerable_code,
    load_source_files,
    patterns_from_code_dir,
    patterns_from_cves,
)
from .simple_ranker import rank_by_keyword

__all__ = [
    "find_similar_vulnerable_code",
    "load_source_files",
    "patterns_from_code_dir",
    "patterns_from_cves",
    "rank_by_keyword",
]
