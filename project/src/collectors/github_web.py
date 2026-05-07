"""URL-based GitHub source collector without cloning repositories."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from src.models import SourceFile


class GitHubWebCollector:
    """Fetch source files through GitHub file, tree, or repository URLs."""

    SOURCE_EXTENSIONS = {
        ".ac",
        ".am",
        ".c",
        ".cc",
        ".cmake",
        ".conf",
        ".cpp",
        ".cs",
        ".go",
        ".gradle",
        ".h",
        ".hpp",
        ".in",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".md",
        ".php",
        ".properties",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".ts",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
    SOURCE_FILENAMES = {"dockerfile", "makefile", "pom.xml"}

    def __init__(self, timeout: int = 20) -> None:
        self.timeout = timeout

    def fetch_file(self, url: str) -> SourceFile:
        """Fetch a single source file from a GitHub or raw URL."""

        raw_url, path = self._to_raw_url(url)
        request = Request(raw_url, headers={"User-Agent": "LLM-based-CVE-vuln-report"})

        try:
            with urlopen(request, timeout=self.timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                content = response.read().decode(charset, errors="replace")
        except URLError as error:
            raise RuntimeError(f"Could not fetch source file from URL: {raw_url}") from error

        return SourceFile(url=url, path=path, content=content)

    def fetch_files(self, urls: list[str]) -> list[SourceFile]:
        """Fetch multiple source files from URL strings."""

        return [self.fetch_file(url) for url in urls]

    def fetch_from_url(self, url: str, max_files: int = 20) -> list[SourceFile]:
        """Fetch one file or selected source files from a GitHub URL."""

        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")

        if parsed.netloc in {"github.com", "www.github.com"} and len(parts) >= 2:
            if len(parts) >= 3 and parts[2] == "blob":
                return [self.fetch_file(url)]
            if len(parts) == 2 or parts[2] == "tree":
                return self.fetch_repository_files(url, max_files=max_files)

        return [self.fetch_file(url)]

    def fetch_repository_files(self, url: str, max_files: int = 20) -> list[SourceFile]:
        """Fetch selected source files from a GitHub repo or tree URL."""

        owner, repo, ref, prefix = self._parse_repository_url(url)
        ref = ref or self._fetch_default_branch(owner, repo)
        tree = self._fetch_tree(owner, repo, ref)
        source_paths = self._select_source_paths(tree, prefix, max_files)
        if not source_paths:
            raise ValueError(f"No source-like files found in {owner}/{repo}@{ref}/{prefix}")

        return [
            self.fetch_file(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}")
            for path in source_paths
        ]

    def _to_raw_url(self, url: str) -> tuple[str, str]:
        parsed = urlparse(url)

        if parsed.netloc == "raw.githubusercontent.com":
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) < 4:
                raise ValueError(f"Unsupported raw GitHub URL: {url}")
            file_path = "/".join(path_parts[3:])
            return url, file_path

        if parsed.netloc in {"github.com", "www.github.com"}:
            return self._github_blob_to_raw(parsed.path, url)

        if parsed.scheme in {"http", "https"}:
            file_name = parsed.path.rsplit("/", maxsplit=1)[-1] or "downloaded_source"
            return url, file_name

        raise ValueError(f"Unsupported URL format: {url}")

    def _github_blob_to_raw(self, path: str, original_url: str) -> tuple[str, str]:
        parts = path.strip("/").split("/")
        if len(parts) < 5 or parts[2] != "blob":
            raise ValueError(
                "Unsupported GitHub file URL. Use a file URL like "
                "https://github.com/owner/repo/blob/main/path/to/file.py "
                "or a repo/tree URL like https://github.com/owner/repo/tree/main"
            )

        owner, repo, _, branch = parts[:4]
        file_path = "/".join(parts[4:])
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
        return raw_url, file_path or original_url.rsplit("/", maxsplit=1)[-1]

    def _parse_repository_url(self, url: str) -> tuple[str, str, str | None, str]:
        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if parsed.netloc not in {"github.com", "www.github.com"} or len(parts) < 2:
            raise ValueError(f"Unsupported GitHub repository URL: {url}")

        owner, repo = parts[:2]
        if len(parts) == 2:
            return owner, repo, None, ""

        if len(parts) >= 4 and parts[2] == "tree":
            ref = parts[3]
            prefix = "/".join(parts[4:])
            return owner, repo, ref, prefix

        raise ValueError(f"Unsupported GitHub repository URL: {url}")

    def _fetch_default_branch(self, owner: str, repo: str) -> str:
        payload = self._fetch_json(f"https://api.github.com/repos/{owner}/{repo}")
        default_branch = payload.get("default_branch")
        if not default_branch:
            raise ValueError(f"Could not find default branch for {owner}/{repo}")
        return default_branch

    def _fetch_tree(self, owner: str, repo: str, ref: str) -> list[dict[str, object]]:
        try:
            payload = self._fetch_json(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1")
        except HTTPError:
            resolved_ref = self._resolve_ref(owner, repo, ref)
            payload = self._fetch_json(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{resolved_ref}?recursive=1"
            )

        tree = payload.get("tree")
        if not isinstance(tree, list):
            raise ValueError(f"Could not fetch repository tree for {owner}/{repo}@{ref}")
        return tree

    def _fetch_json(self, url: str) -> dict[str, object]:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "LLM-based-CVE-vuln-report",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError:
            raise
        except URLError as error:
            raise RuntimeError(f"Could not connect to GitHub API: {url}") from error

    def _resolve_ref(self, owner: str, repo: str, ref: str) -> str:
        for kind in ("heads", "tags"):
            try:
                payload = self._fetch_json(f"https://api.github.com/repos/{owner}/{repo}/git/ref/{kind}/{ref}")
            except HTTPError:
                continue

            ref_object = payload.get("object", {})
            if not isinstance(ref_object, dict):
                continue

            if ref_object.get("type") == "tag" and isinstance(ref_object.get("url"), str):
                tag_payload = self._fetch_json(str(ref_object["url"]))
                tag_object = tag_payload.get("object", {})
                if isinstance(tag_object, dict) and isinstance(tag_object.get("sha"), str):
                    return str(tag_object["sha"])

            sha = ref_object.get("sha")
            if isinstance(sha, str):
                return sha

        raise ValueError(f"Could not resolve GitHub ref: {owner}/{repo}@{ref}")

    def _select_source_paths(
        self,
        tree: list[dict[str, object]],
        prefix: str,
        max_files: int,
    ) -> list[str]:
        normalized_prefix = prefix.strip("/")
        paths: list[str] = []

        for item in tree:
            if item.get("type") != "blob":
                continue

            path = str(item.get("path", ""))
            if normalized_prefix and not path.startswith(f"{normalized_prefix}/"):
                continue
            if self._looks_like_source(path):
                paths.append(path)
            if len(paths) >= max_files:
                break

        return paths

    def _looks_like_source(self, path: str) -> bool:
        lower_path = path.lower()
        file_name = lower_path.rsplit("/", maxsplit=1)[-1]
        if file_name in self.SOURCE_FILENAMES:
            return True
        return any(lower_path.endswith(extension) for extension in self.SOURCE_EXTENSIONS)
