"""NVD CVE API collector."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class NvdCollector:
    """Fetch raw CVE records from the NVD 2.0 API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None, timeout: int = 20) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        query = urlencode(params)
        request = Request(f"{self.BASE_URL}?{query}")

        if self.api_key:
            request.add_header("apiKey", self.api_key)

        with urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def search(self, keyword: str, limit: int = 5) -> dict[str, Any]:
        """Search CVEs by keyword and return the raw NVD JSON payload."""
        return self._get(
            {
                "keywordSearch": keyword,
                "resultsPerPage": limit,
            }
        )

    def fetch_by_id(self, cve_id: str) -> dict[str, Any]:
        """Fetch one CVE by CVE ID and return the raw NVD JSON payload."""
        return self._get(
            {
                "cveId": cve_id,
            }
        )

    def fetch_by_ids(self, cve_ids: list[str]) -> dict[str, Any]:
        """Fetch multiple CVEs by ID and merge them into one NVD-like payload."""
        vulnerabilities: list[dict[str, Any]] = []

        for cve_id in cve_ids:
            payload = self.fetch_by_id(cve_id)
            vulnerabilities.extend(payload.get("vulnerabilities", []))

        return {
            "resultsPerPage": len(vulnerabilities),
            "startIndex": 0,
            "totalResults": len(vulnerabilities),
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": vulnerabilities,
        }