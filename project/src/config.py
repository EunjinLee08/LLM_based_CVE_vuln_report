"""Application configuration helpers."""

from __future__ import annotations
from dotenv import load_dotenv
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
    llm_max_findings: int = 5

    @classmethod
    def from_env(cls) -> "Settings":
        project_root = Path(__file__).resolve().parents[1]

        # debug code
        env_path = project_root / ".env"
        print("ENV PATH:", env_path)
        print("ENV EXISTS:", env_path.exists())

        load_dotenv(env_path)

        print("MINDLOGIC_API_KEY LOADED:", bool(os.getenv("MINDLOGIC_API_KEY")))

        return cls(
            nvd_api_key=os.getenv("NVD_API_KEY"),

            mindlogic_api_key = os.getenv("MINDLOGIC_API_KEY"),
            mindlogic_base_url= os.getenv("MINDLOGIC_BASE_URL", "https://factchat-cloud.mindlogic.ai/v1/gateway"),
            mindlogic_model=os.getenv("MINDLOGIC_MODEL", "gpt-5.4"),

            output_dir=Path(os.getenv("REPORT_OUTPUT_DIR", project_root / "reports")),
            max_results=int(os.getenv("MAX_CVE_RESULTS", "5")),
            llm_max_findings=int(os.getenv("LLM_MAX_FINDINGS", "5"))
        )