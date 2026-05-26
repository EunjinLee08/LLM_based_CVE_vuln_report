"""Application configuration helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Runtime settings loaded from environment variables."""

    nvd_api_key: str | None

    mindlogic_api_key: str | None
    mindlogic_base_url: str
    mindlogic_model: str

    output_dir: Path
    max_results: int = 5

    @classmethod
    def from_env(cls) -> "Settings":
        project_root = Path(__file__).resolve().parents[1]
        return cls(
            nvd_api_key=os.getenv("NVD_API_KEY"),

            mindlogic_api_key = os.getenv("API_KEY"),
            mindlogic_base_url= os.getenv("BASE_URL", "https://factchat-cloud.mindlogic.ai/v1/gateway"),
            mindlogic_model=os.getenv("MODEL", "gpt=5.4"),

            output_dir=Path(os.getenv("REPORT_OUTPUT_DIR", project_root / "reports")),
            max_results=int(os.getenv("MAX_CVE_RESULTS", "5")),
        )
