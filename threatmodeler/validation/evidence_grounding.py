"""Deterministic evidence grounding against source text."""

from __future__ import annotations

import re

from pydantic import BaseModel

from threatmodeler.contracts.source import Evidence
from threatmodeler.shared.constants import StopWord

_WHITESPACE = re.compile(r"\s+")
_TOKEN = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(member.value for member in StopWord)
_DEFAULT_OVERLAP_RATIO = 0.6


class EvidenceGroundingChecker:
    """Check whether cited evidence appears in the supplied source corpus."""

    def __init__(self, *, overlap_ratio: float = _DEFAULT_OVERLAP_RATIO) -> None:
        if not 0.0 < overlap_ratio <= 1.0:
            raise ValueError("overlap_ratio must be in (0.0, 1.0]")
        self._overlap_ratio = overlap_ratio

    def is_grounded(self, item: BaseModel, source_text: str) -> bool:
        """Return whether any evidence snippet is present in ``source_text``.

        Items without evidence are treated as grounded because there is nothing to
        verify. Matches use token-overlap ratios so paraphrased citations can still
        count as grounded. Grounding never blocks acceptance.

        Args:
            item: Candidate model that may carry ``evidence``.
            source_text: Architecture source or serialized upstream payload.

        Returns:
            True when evidence is absent or at least one snippet overlaps enough.
        """
        evidence = getattr(item, "evidence", None)
        if not evidence:
            return True
        corpus_tokens = _tokens(source_text)
        if not corpus_tokens:
            return False
        for entry in evidence:
            snippets = _snippets(entry)
            if any(
                _is_overlapping(snippet, corpus_tokens, self._overlap_ratio) for snippet in snippets
            ):
                return True
        return False


def _snippets(entry: object) -> list[str]:
    if isinstance(entry, Evidence):
        values = [entry.summary, *[reference.excerpt for reference in entry.source_references]]
        return [value for value in values if value]
    if isinstance(entry, str):
        return [entry]
    return []


def _tokens(value: str) -> set[str]:
    normalized = _WHITESPACE.sub(" ", value).strip().lower()
    return {token for token in _TOKEN.findall(normalized) if token not in _STOPWORDS}


def _is_overlapping(snippet: str, corpus_tokens: set[str], ratio: float) -> bool:
    snippet_tokens = _tokens(snippet)
    if not snippet_tokens:
        return False
    overlap = len(snippet_tokens & corpus_tokens)
    return (overlap / len(snippet_tokens)) >= ratio
