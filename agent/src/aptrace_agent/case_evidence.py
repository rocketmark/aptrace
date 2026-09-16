from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel


class CaseEvidenceMatch(BaseModel):
    source: str
    line: int
    kind: str
    excerpt: str
    score: int


class CaseEvidenceSearchResult(BaseModel):
    query: str
    matches: list[CaseEvidenceMatch]
    files_scanned: int
    truncated: bool


class CaseEvidenceSearch:
    """Bounded read-only search over Performing Rigs evidence."""

    ALLOWED_EXTENSIONS = {
        ".md",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".csv",
        ".tsv",
        ".txt",
    }

    MAX_FILE_BYTES = 5_000_000
    MAX_QUERY_TERMS = 12
    MAX_EXCERPT_CHARS = 1400
    CONTEXT_LINES = 2

    def __init__(self, repo_root: Path | None = None):
        if repo_root is None:
            repo_root = Path(__file__).resolve().parents[3]

        self.repo_root = repo_root.resolve()
        self.case_root = (
            self.repo_root / "cases" / "performing-rigs"
        ).resolve()

        self.allowed_roots = [
            self.case_root / "docs",
            self.case_root / "research" / "generated",
            self.case_root / "research" / "workflows",
            self.case_root / "research" / "provenance",
        ]

        self.allowed_files = [
            self.case_root / "status.md",
            self.case_root / "roadmap.md",
        ]

    def search(
        self,
        query: str,
        max_results: int = 8,
    ) -> CaseEvidenceSearchResult:
        query = query.strip()

        if not query:
            raise ValueError("query must not be empty")

        if not 1 <= max_results <= 20:
            raise ValueError(
                "max_results must be between 1 and 20"
            )

        terms = self._query_terms(query)

        if not terms:
            raise ValueError(
                "query contains no searchable terms"
            )

        matches: list[CaseEvidenceMatch] = []
        files_scanned = 0

        for path in self._iter_allowed_files():
            try:
                if path.stat().st_size > self.MAX_FILE_BYTES:
                    continue

                text = path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError:
                continue

            files_scanned += 1
            lines = text.splitlines()

            for index, line in enumerate(lines):
                window_text = self._window_text(
                    lines,
                    index,
                )

                score = self._score_text(
                    text=window_text,
                    query=query,
                    terms=terms,
                )

                if score <= 0:
                    continue

                matches.append(
                    CaseEvidenceMatch(
                        source=str(
                            path.relative_to(self.repo_root)
                        ),
                        line=index + 1,
                        kind=self._kind_for(path),
                        excerpt=self._make_excerpt(
                            lines,
                            index,
                            terms,
                        ),
                        score=score,
                    )
                )

        matches.sort(
            key=lambda m: (
                -m.score,
                m.source,
                m.line,
            )
        )

        deduped = self._dedupe_nearby(matches)

        return CaseEvidenceSearchResult(
            query=query,
            matches=deduped[:max_results],
            files_scanned=files_scanned,
            truncated=len(deduped) > max_results,
        )

    def _iter_allowed_files(self) -> Iterable[Path]:
        seen: set[Path] = set()

        for root in self.allowed_roots:
            if not root.exists():
                continue

            for path in root.rglob("*"):
                if not path.is_file():
                    continue

                if (
                    path.suffix.lower()
                    not in self.ALLOWED_EXTENSIONS
                ):
                    continue

                resolved = path.resolve()

                if not self._inside_case_root(resolved):
                    continue

                if resolved in seen:
                    continue

                seen.add(resolved)
                yield resolved

        for path in self.allowed_files:
            if not path.exists():
                continue

            resolved = path.resolve()

            if not self._inside_case_root(resolved):
                continue

            if resolved in seen:
                continue

            seen.add(resolved)
            yield resolved

    def _inside_case_root(self, path: Path) -> bool:
        try:
            path.relative_to(self.case_root)
            return True
        except ValueError:
            return False

    def _query_terms(self, query: str) -> list[str]:
        raw_terms = re.findall(
            r"[A-Za-z0-9_+.\-]+",
            query.lower(),
        )

        stopwords = {
            "a",
            "an",
            "and",
            "are",
            "as",
            "at",
            "be",
            "by",
            "does",
            "for",
            "from",
            "in",
            "is",
            "it",
            "of",
            "on",
            "or",
            "the",
            "to",
            "what",
            "with",
        }

        terms: list[str] = []

        for term in raw_terms:
            if term in stopwords:
                continue

            if term not in terms:
                terms.append(term)

            if len(terms) >= self.MAX_QUERY_TERMS:
                break

        return terms

    def _window_text(
        self,
        lines: list[str],
        index: int,
    ) -> str:
        start = max(
            0,
            index - self.CONTEXT_LINES,
        )

        end = min(
            len(lines),
            index + self.CONTEXT_LINES + 1,
        )

        return "\n".join(lines[start:end])

    def _score_text(
        self,
        text: str,
        query: str,
        terms: list[str],
    ) -> int:
        lowered = text.lower()

        matched = [
            term
            for term in terms
            if term in lowered
        ]

        if not matched:
            return 0

        score = len(matched)

        if query.lower() in lowered:
            score += 10

        coverage = len(matched) / len(terms)

        if coverage == 1.0:
            score += 10
        elif coverage >= 0.75:
            score += 6
        elif coverage >= 0.5:
            score += 2

        for term in matched:
            if (
                term.startswith("fun_")
                or term.startswith("0x")
                or re.fullmatch(
                    r"p[ab]\d{2}",
                    term,
                    re.IGNORECASE,
                )
            ):
                score += 4

        return score

    def _make_excerpt(
        self,
        lines: list[str],
        index: int,
        terms: list[str],
    ) -> str:
        start = max(
            0,
            index - self.CONTEXT_LINES,
        )

        end = min(
            len(lines),
            index + self.CONTEXT_LINES + 1,
        )

        pieces: list[str] = []

        for i in range(start, end):
            line = lines[i]

            if len(line) > 700:
                lowered = line.lower()

                positions = [
                    lowered.find(term)
                    for term in terms
                    if lowered.find(term) >= 0
                ]

                if positions:
                    center = min(positions)
                    left = max(0, center - 250)
                    right = min(
                        len(line),
                        center + 450,
                    )

                    fragment = line[left:right]

                    if left:
                        fragment = "..." + fragment

                    if right < len(line):
                        fragment += "..."

                    line = fragment
                else:
                    line = line[:700] + "..."

            pieces.append(
                f"{i + 1}: {line}"
            )

        excerpt = "\n".join(pieces)

        if len(excerpt) > self.MAX_EXCERPT_CHARS:
            excerpt = (
                excerpt[: self.MAX_EXCERPT_CHARS]
                + "\n...[excerpt truncated]"
            )

        return excerpt

    def _dedupe_nearby(
        self,
        matches: list[CaseEvidenceMatch],
    ) -> list[CaseEvidenceMatch]:
        result: list[CaseEvidenceMatch] = []

        for candidate in matches:
            if any(
                existing.source == candidate.source
                and abs(
                    existing.line - candidate.line
                )
                <= self.CONTEXT_LINES * 2
                for existing in result
            ):
                continue

            result.append(candidate)

        return result

    def _kind_for(self, path: Path) -> str:
        relative = path.relative_to(self.case_root)
        parts = relative.parts

        if (
            len(parts) >= 2
            and parts[0] == "docs"
            and parts[1] == "investigations"
        ):
            return "investigation"

        if (
            len(parts) >= 2
            and parts[0] == "research"
            and parts[1] == "generated"
        ):
            return "generated_evidence"

        if (
            len(parts) >= 2
            and parts[0] == "research"
            and parts[1] == "workflows"
        ):
            return "workflow"

        if (
            len(parts) >= 2
            and parts[0] == "research"
            and parts[1] == "provenance"
        ):
            return "provenance"

        if relative == Path("status.md"):
            return "status"

        if relative == Path("roadmap.md"):
            return "roadmap"

        return "documentation"


def performing_rigs_case_evidence() -> CaseEvidenceSearch:
    return CaseEvidenceSearch()
