"""Collectors fetch raw vulnerability data from external or local sources."""

from .github_web import GitHubWebCollector
from .nvd import NvdCollector

__all__ = ["GitHubWebCollector", "NvdCollector"]
