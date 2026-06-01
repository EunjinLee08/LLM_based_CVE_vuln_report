"""Command line entry point for CVE-based vulnerability prediction."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from src.retrieval.c_code_patterns import (
    collect_family_queries,
    scan_c_code_path,
    scan_c_source_texts,
    summarize_families,
)
from src.collectors import GitHubWebCollector, NvdCollector
from src.config import Settings
from src.llm import build_report_prompt, draft_report, draft_similarity_report, judge_findings_with_llm
from src.parser import parse_nvd_payload
from src.retrieval import (
    find_similar_vulnerable_code,
    load_source_files,
    patterns_from_code_dir,
    patterns_from_cves,
    rank_by_keyword,
)
from src.validation import validate_keyword, validate_report


def main() -> None:
    try:
        _run()
    except (RuntimeError, ValueError) as error:
        raise SystemExit(f"Error: {error}")


def _run() -> None:
    args = _parse_args()
    settings = Settings.from_env()

    if args.github_url and args.save_sources:
        source_files = GitHubWebCollector().fetch_from_url(args.github_url, max_files=args.github_max_files)
        output_paths = [_write_source_file(settings.output_dir, source_file.path, source_file.content) for source_file in source_files]
        print(f"Source files written: {len(output_paths)}")
        for output_path in output_paths:
            print(f"- {output_path}")
        return

    keyword = args.keyword or _infer_keyword_from_github_url(args.github_url)

    ranked_records = []

    if keyword:
        validate_keyword(keyword)
        payload = NvdCollector(settings.nvd_api_key).search(
            keyword,
            args.limit or settings.max_results,
        )
        records = parse_nvd_payload(payload)
        ranked_records = rank_by_keyword(records, keyword)

    if args.source_dir or args.github_url:
        if args.github_url:
            source_files = GitHubWebCollector().fetch_from_url(
                args.github_url,
                max_files=args.github_max_files,
            )
        else:
            source_files = load_source_files(Path(args.source_dir))

        if not source_files:
            raise ValueError(
                "No source files found to analyze.\n"
                "Check --source-dir or --github-url.\n"
                "Supported source extensions include .c, .h, .cpp, .py, .js, .ts, .java, .php, .go, .rs, and .rb."
            )

        c_pattern_findings = []

        if args.github_url:
            c_pattern_findings = scan_c_source_texts(source_files)
        elif args.source_dir:
            c_pattern_findings = scan_c_code_path(Path(args.source_dir))

        if c_pattern_findings:
            print("[+] Static C pattern evidence found:")
            for family, count in summarize_families(c_pattern_findings).items():
                print(f"    - {family}: {count}")

            extra_queries = collect_family_queries(c_pattern_findings)

            # debug
            print("[+] Augmented NVD queries:")
            for query in extra_queries:
                print(f"    - {query}")

            extra_records = []
            for query in extra_queries:
                payload = NvdCollector(settings.nvd_api_key).search(
                    query,
                    args.limit or settings.max_results,
                )
                term_records = parse_nvd_payload(payload)

                # debug
                                # debug
                print(f"[+] NVD results for '{query}': {len(term_records)}")
                for record in term_records[:5]:
                    text = getattr(record, "description", None) or getattr(record, "summary", "")
                    print(f"    - {record.cve_id}: {text[:80]}")

                extra_records.extend(term_records)

            # CVE ID 기준 중복 제거
            merged = {record.cve_id: record for record in ranked_records}
            for record in extra_records:
                merged.setdefault(record.cve_id, record)

            ranked_records = list(merged.values())

        patterns = []

        if args.vuln_code_dir:
            patterns.extend(patterns_from_code_dir(Path(args.vuln_code_dir)))

        # keyword가 있을 때만 CVE 설명문 fallback 사용
        if ranked_records:
            patterns.extend(patterns_from_cves(ranked_records))

        if not patterns:
            raise ValueError(
                "No vulnerability patterns found. "
                "Use --vuln-code-dir for code-similarity based CVE matching, "
                "or provide a keyword for NVD description fallback."
            )
                
        findings = find_similar_vulnerable_code(
            patterns=patterns,
            source_files=source_files,
            threshold=args.threshold,
            max_findings=args.max_findings,
        )

        if not settings.mindlogic_api_key:
            raise ValueError("MINDLOGIC_API_KEY is required.")

        llm_judgments = judge_findings_with_llm(
            findings=findings,
            model=settings.mindlogic_model,
            max_findings=settings.llm_max_findings,
            api_key=settings.mindlogic_api_key,
            base_url=settings.mindlogic_base_url,
        )

        report_keyword = keyword or "code_similarity"

        report = draft_similarity_report(
            report_keyword,
            ranked_records,
            findings,
            len(source_files),
            len(patterns),
            llm_judgments=llm_judgments,
            llm_model=settings.mindlogic_model,
            c_pattern_findings=c_pattern_findings,
        )

        validate_report(report)
        output_path = _write_report(settings.output_dir, f"{keyword}_similarity", report)
        print(f"Similarity report written: {output_path}")
        return

    report = draft_report(keyword, ranked_records)
    validate_report(report)

    output_path = _write_report(settings.output_dir, keyword, report)
    if args.show_prompt:
        print(build_report_prompt(keyword, ranked_records))
    print(f"Report written: {output_path}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict vulnerable code candidates from known CVE evidence.")
    parser.add_argument("keyword", nargs="?", help="Product, vendor, or vulnerability keyword to search")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of CVEs to collect")
    parser.add_argument("--show-prompt", action="store_true", help="Print the LLM prompt evidence block")
    parser.add_argument("--source-dir", help="Local source directory to analyze for CVE similarity")
    parser.add_argument("--vuln-code-dir", help="Directory of previously reported vulnerable code samples")
    parser.add_argument("--threshold", type=float, default=0.18, help="Minimum similarity score for candidates")
    parser.add_argument("--max-findings", type=int, default=20, help="Maximum vulnerable-code candidates to report")
    parser.add_argument("--github-url", help="Analyze source file(s) by GitHub web/raw URL without cloning")
    parser.add_argument("--github-max-files", type=int, default=20, help="Maximum files to fetch from a repo/tree URL")
    parser.add_argument("--save-sources", action="store_true", help="Only save fetched GitHub source files instead of analyzing them")
    return parser.parse_args()


def _write_report(output_dir: Path, keyword: str, report: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_keyword = "".join(char if char.isalnum() else "_" for char in keyword).strip("_") or "cve"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"{timestamp}_{safe_keyword}.md"
    output_path.write_text(report, encoding="utf-8")
    return output_path


def _write_source_file(output_dir: Path, source_path: str, content: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = source_path.replace("\\", "/").strip("/").replace("/", "__") or "source"
    output_path = output_dir / f"source__{safe_name}"
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _infer_keyword_from_github_url(github_url: str | None) -> str | None:
    if not github_url:
        return None

    parsed = urlparse(github_url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if parsed.netloc in {"github.com", "www.github.com", "raw.githubusercontent.com"} and len(parts) >= 2:
        repo = parts[1].removesuffix(".git")
        return repo.replace("-", " ").replace("_", " ").strip() or None

    return None


if __name__ == "__main__":
    main()
