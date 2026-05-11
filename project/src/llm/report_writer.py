"""Deterministic report writers."""

from __future__ import annotations

from src.models import CveRecord, LlmJudgment, ReportSection, SimilarityFinding


def draft_report(keyword: str, records: list[CveRecord]) -> str:
    """Generate a Markdown report from normalized CVE records."""

    sections = [
        ReportSection("검색 키워드", keyword),
        ReportSection("요약", _summary(records)),
        ReportSection("주요 CVE", _cve_table(records)),
        ReportSection("권장 조치", _mitigations()),
    ]
    return "\n\n".join(f"## {section.title}\n\n{section.body}" for section in sections)


def draft_similarity_report(
    keyword: str,
    records: list[CveRecord],
    findings: list[SimilarityFinding],
    source_count: int,
    pattern_count: int,
    llm_judgments: list[LlmJudgment] | None = None,
    llm_model: str | None = None,
) -> str:
    """Generate a vulnerability prediction report from similarity findings."""

    sections = [
        ReportSection(
            "분석 대상",
            f"- 키워드: {keyword}\n- 분석한 소스 파일: {source_count}\n- 비교한 취약점 근거: {pattern_count}",
        ),
        ReportSection("예측 요약", _prediction_summary(findings)),
        ReportSection("유사도 기반 취약 후보", _finding_table(findings)),
        ReportSection("해석 방법", _interpretation()),
    ]
    if llm_judgments:
        sections.insert(3, ReportSection("LLM 재판단", _llm_judgment_table(llm_judgments, llm_model)))
    sections.insert(-1, ReportSection("근거 CVE", _cve_table(records[:10])))
    return "\n\n".join(f"## {section.title}\n\n{section.body}" for section in sections)


def _summary(records: list[CveRecord]) -> str:
    if not records:
        return "검색된 CVE가 없습니다. 키워드나 수집 조건을 확인하세요."

    highest = max((record.score or 0.0 for record in records), default=0.0)
    return f"총 {len(records)}건의 CVE 정보를 확인했습니다. 최고 CVSS 점수는 {highest:.1f}입니다."


def _cve_table(records: list[CveRecord]) -> str:
    if not records:
        return "결과 없음"

    lines = ["| CVE | 심각도 | 점수 | 설명 |", "| --- | --- | ---: | --- |"]
    for record in records:
        summary = record.summary.replace("|", "\\|")
        lines.append(
            f"| {record.cve_id} | {record.severity or 'UNKNOWN'} | "
            f"{record.score if record.score is not None else 'N/A'} | {summary} |"
        )
    return "\n".join(lines)


def _mitigations() -> str:
    return (
        "- 벤더 보안 공지와 패치 버전을 확인합니다.\n"
        "- 노출된 서비스가 취약 버전을 사용하는지 자산 목록에서 대조합니다.\n"
        "- 즉시 패치가 어렵다면 접근 제어, WAF 정책, 임시 차단 규칙을 적용합니다.\n"
        "- 조치 후 재스캔하여 취약점이 해소되었는지 검증합니다."
    )


def _prediction_summary(findings: list[SimilarityFinding]) -> str:
    if not findings:
        return "설정한 기준을 넘는 유사 취약 코드 후보를 찾지 못했습니다."

    high = sum(1 for finding in findings if finding.similarity >= 0.45)
    medium = sum(1 for finding in findings if 0.30 <= finding.similarity < 0.45)
    low = len(findings) - high - medium
    return f"총 {len(findings)}개의 후보를 찾았습니다. 높음 {high}개, 중간 {medium}개, 낮음 {low}개입니다."


def _finding_table(findings: list[SimilarityFinding]) -> str:
    if not findings:
        return "후보 없음"

    lines = [
        "| 위험도 | 유사도 | 위치 | 유사 근거 | 매칭 용어 |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for finding in findings:
        risk = _risk_label(finding.similarity)
        location = f"{finding.snippet.file_path}:{finding.snippet.start_line}-{finding.snippet.end_line}"
        terms = ", ".join(finding.matched_terms) or "N/A"
        basis = finding.pattern.pattern_id
        lines.append(f"| {risk} | {finding.similarity:.2f} | `{location}` | {basis} | {terms} |")
    return "\n".join(lines)


def _llm_judgment_table(judgments: list[LlmJudgment], model: str | None) -> str:
    model_line = f"모델: `{model}`\n\n" if model else ""
    lines = [
        "| 후보 | GPT 위험도 | 신뢰도 | 판단 근거 | 확인 방법 | 권장 조치 |",
        "| ---: | --- | ---: | --- | --- | --- |",
    ]
    for judgment in judgments:
        confidence = f"{judgment.confidence:.2f}" if judgment.confidence is not None else "N/A"
        lines.append(
            "| "
            f"{judgment.finding_index} | "
            f"{_clean_cell(judgment.risk)} | "
            f"{confidence} | "
            f"{_clean_cell(judgment.rationale)} | "
            f"{_clean_cell(judgment.verification_steps)} | "
            f"{_clean_cell(judgment.recommended_fix)} |"
        )
    return model_line + "\n".join(lines)


def _risk_label(similarity: float) -> str:
    if similarity >= 0.45:
        return "높음"
    if similarity >= 0.30:
        return "중간"
    return "낮음"


def _interpretation() -> str:
    return (
        "이 결과는 확정 진단이 아니라, 이미 제보된 취약 코드 또는 CVE 설명과의 유사도를 이용한 우선순위 후보입니다. "
        "상위 후보부터 입력 검증, 경계값 검사, 메모리 크기 계산, 인증/세션 처리, 인코딩/디코딩 흐름을 수동 검토하세요."
    )


def _clean_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", "<br>").strip() or "N/A"
