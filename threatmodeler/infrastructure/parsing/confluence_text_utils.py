"""Shared text-normalization helpers for Confluence document parsing."""


def join_text_parts(parts: list[str]) -> str:
    """Collapse whitespace in collected HTML or markdown fragments."""
    return " ".join(" ".join(parts).split())
