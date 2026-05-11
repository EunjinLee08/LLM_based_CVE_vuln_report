"""LLM-backed review of similarity findings."""

from __future__ import annotations

import json
import re
from urllib.error import URLError
from urllib.request import Request, urlopen

from src.models import LlmJudgment, SimilarityFinding


def judge_findings_with_llm(
    findings: list[SimilarityFinding],
    provider: str,
    model: str,
    max_findings: int,
    ollama_url: str = "http://localhost:11434",
) -> list[LlmJudgment]:
    """Ask an LLM provider to review the highest-ranked similarity findings."""

    if max_findings <= 0 or not findings:
        return []

    provider = provider.lower()
    judgments: list[LlmJudgment] = []
    for index, finding in enumerate(findings[:max_findings], start=1):
        prompt = _build_judgment_prompt(index, finding)
        if provider == "openai":
            raw_response = _call_openai(model, prompt)
        elif provider == "ollama":
            raw_response = _call_ollama(model, prompt, ollama_url)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
        judgments.append(_parse_judgment(index, raw_response))
    return judgments


def _call_openai(model: str, prompt: str) -> str:
    try:
        from openai import OpenAI
    except ImportError as error:
        raise RuntimeError("OpenAI SDK is not installed. Run: pip install openai") from error

    response = OpenAI().responses.create(model=model, input=prompt)
    return response.output_text


def _call_ollama(model: str, prompt: str, ollama_url: str) -> str:
    url = ollama_url.rstrip("/") + "/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=180) as response:
            data = json.loads(response.read().decode("utf-8"))
    except URLError as error:
        raise RuntimeError(
            f"Could not connect to Ollama at {ollama_url}. "
            "Start Ollama and run: ollama pull qwen2.5-coder"
        ) from error

    raw_response = data.get("response")
    if not isinstance(raw_response, str):
        raise RuntimeError("Ollama returned an unexpected response payload.")
    return raw_response


def _build_judgment_prompt(index: int, finding: SimilarityFinding) -> str:
    snippet = _truncate(finding.snippet.text, 6000)
    pattern_code = _truncate(finding.pattern.code or "", 3000)
    references = "\n".join(f"- {url}" for url in finding.pattern.references[:5]) or "- N/A"
    matched_terms = ", ".join(finding.matched_terms) or "N/A"

    return f"""You are a senior application security reviewer.

Review whether the target code is plausibly vulnerable based on the known vulnerability evidence.
This is a defensive code-audit task. Do not provide exploit steps or weaponized payloads.

Return only valid JSON with this shape:
{{
  "risk": "high | medium | low | false_positive",
  "confidence": 0.0,
  "rationale": "short technical reason",
  "attack_conditions": "conditions required for this to be exploitable, without exploit payloads",
  "verification_steps": "safe code-review or test steps to confirm",
  "recommended_fix": "specific remediation guidance",
  "false_positive_notes": "why this may not be vulnerable"
}}

Finding index: {index}
Similarity score: {finding.similarity:.3f}
Matched terms: {matched_terms}
Similarity reason: {finding.reason}

Known vulnerability evidence:
- ID: {finding.pattern.pattern_id}
- Title: {finding.pattern.title}
- Severity: {finding.pattern.severity or "UNKNOWN"}
- Score: {finding.pattern.score if finding.pattern.score is not None else "N/A"}
- Description: {finding.pattern.text}
- References:
{references}

Known vulnerable code sample, if available:
```text
{pattern_code or "N/A"}
```

Target code:
- File: {finding.snippet.file_path}
- Lines: {finding.snippet.start_line}-{finding.snippet.end_line}
```text
{snippet}
```
"""


def _parse_judgment(index: int, raw_response: str) -> LlmJudgment:
    payload = _load_json_object(raw_response)
    return LlmJudgment(
        finding_index=index,
        risk=str(payload.get("risk", "unknown")),
        confidence=_as_float(payload.get("confidence")),
        rationale=str(payload.get("rationale", "")).strip(),
        attack_conditions=str(payload.get("attack_conditions", "")).strip(),
        verification_steps=str(payload.get("verification_steps", "")).strip(),
        recommended_fix=str(payload.get("recommended_fix", "")).strip(),
        false_positive_notes=str(payload.get("false_positive_notes", "")).strip(),
        raw_response=raw_response,
    )


def _load_json_object(raw_response: str) -> dict[str, object]:
    try:
        value = json.loads(raw_response)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw_response, flags=re.DOTALL)
        if not match:
            return {"risk": "unknown", "rationale": raw_response}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {"risk": "unknown", "rationale": raw_response}

    return value if isinstance(value, dict) else {"risk": "unknown", "rationale": raw_response}


def _as_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]"
