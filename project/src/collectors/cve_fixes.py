from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class CveFixCode:
    cvd_id: str
    summary: str
    repo_url: str | None
    commit_hash: str | None
    file_path: str | None
    vulnerable_code: str
    fixed_code: str | None = None
    cwe_id: str | None = None
    reference_url: str | None = None

class CveFixesCollector:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
    
    def search(
            self,
            keyword: str | None = None,
            *,
            limit: int = 50,
            min_code_length: int = 80,
    ) -> list[CveFixCode]:
        if not self.db_path.exists():
            raise ValueError(f"CVEfixes DB not found: {self.db_path}")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            query = """
            SELECT
                c.cve_id AS cve_id,
                COALESCE(c.summary, c.description, '') AS summary,
                r.url AS repo_url,
                cm.hash AS commit_hash,
                fc.filename AS file_path,
                COALESCE(fc.code_before, fc.previous_code, fc.before_change, '') AS vulnerable_code,
                COALESCE(fc.code_after, fc.new_code, fc.after_change, '') AS fixed_code,
                cw.cwe_id AS cwe_id
            FROM cve c
            LEFT JOIN fixes f ON f.cve_id = c.cve_id
            LEFT JOIN commits cm ON cm.hash = f.hash
            LEFT JOIN repository r ON r.repo_id = cm.repo_id
            LEFT JOIN file_change fc ON fc.hash = cm.hash
            LEFT JOIN cwe_classification cw ON cw.cve_id = c.cve_id
            WHERE
                LENGTH(COALESCE(fc.code_before, fc.previous_code, fc.before_change, '')) >= ?
            """

            params: list[object]