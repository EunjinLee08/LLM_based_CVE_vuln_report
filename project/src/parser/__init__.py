"""Parsers normalize raw collector payloads into project models."""

from .cve_parser import parse_nvd_payload

__all__ = ["parse_nvd_payload"]

