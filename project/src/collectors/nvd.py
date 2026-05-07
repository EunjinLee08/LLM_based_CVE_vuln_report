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

    def search(self, keyword: str, limit: int = 5) -> dict[str, Any]:
        """Search CVEs by keyword and return the raw NVD JSON payload."""

        params = urlencode({"keywordSearch": keyword, "resultsPerPage": limit})
        request = Request(f"{self.BASE_URL}?{params}")
        if self.api_key:
            request.add_header("apiKey", self.api_key)

        with urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

