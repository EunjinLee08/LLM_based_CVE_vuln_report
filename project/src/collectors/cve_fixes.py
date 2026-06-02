from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CveFixesCodeRecord:
    cve_id: str
    cwe_id: str | None
    repo_url: str | None
    commit_hash: str | None
    file_path: str | None
    vulnerable_code: str
    fixed_code: str | None
    language: str | None


def load_cvefixes_vulnerable_code(
    db_path: Path,
    *,
    limit: int | None = None,
    language: str | None = None,
) -> list[CveFixesCodeRecord]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    query = """
    SELECT
        c.cve_id AS cve_id,
        cw.cwe_id AS cwe_id,
        f.repo_url AS repo_url,
        cc.hash AS commit_hash,
        mf.filename AS file_path,
        mfc.code_before AS vulnerable_code,
        mfc.code_after AS fixed_code,
        mf.programming_language AS language
    FROM fixes f
    JOIN commits cc ON f.hash = cc.hash
    JOIN cve c ON f.cve_id = c.cve_id
    LEFT JOIN cwe_classification cw ON c.cve_id = cw.cve_id
    JOIN file_change mf ON cc.hash = mf.hash
    JOIN method_change mfc ON mf.file_change_id = mfc.file_change_id
    WHERE mfc.code_before IS NOT NULL
      AND LENGTH(TRIM(mfc.code_before)) > 0
    """

    params: list[object] = []

    if language:
        query += " AND LOWER(mf.programming_language) = LOWER(?)"
        params.append(language)

    query += " ORDER BY c.cve_id DESC"

    if limit:
        query += " LIMIT ?"
        params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return [
        CveFixesCodeRecord(
            cve_id=row["cve_id"],
            cwe_id=row["cwe_id"],
            repo_url=row["repo_url"],
            commit_hash=row["commit_hash"],
            file_path=row["file_path"],
            vulnerable_code=row["vulnerable_code"],
            fixed_code=row["fixed_code"],
            language=row["language"],
        )
        for row in rows
    ]