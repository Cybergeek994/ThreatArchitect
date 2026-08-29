"""Markdown extraction for Confluence exports."""

import re

from pydantic import BaseModel, ConfigDict, Field

from threatmodeler.contracts.integration import ImageReference, ParsedHeading, ParsedParagraph, ParsedTable
from threatmodeler.infrastructure.parsing.confluence_text_utils import join_text_parts


class ConfluenceMarkdownExtraction(BaseModel):
    """Structured content extracted from a Markdown document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str
    headings: tuple[ParsedHeading, ...] = Field(default_factory=tuple)
    paragraphs: tuple[ParsedParagraph, ...] = Field(default_factory=tuple)
    tables: tuple[ParsedTable, ...] = Field(default_factory=tuple)
    image_references: tuple[ImageReference, ...] = Field(default_factory=tuple)
    raw_text: str


class ConfluenceMarkdownExtractor:
    """Extract headings, paragraphs, tables, and images from Markdown."""

    def extract(self, content: str, *, fallback_title: str) -> ConfluenceMarkdownExtraction:
        """Parse Markdown content into structured document fields."""
        lines = content.splitlines()
        headings = self._headings(lines)
        tables, table_lines = self._tables(lines)
        paragraphs = self._paragraphs(lines, table_lines)
        images = self._images(content)
        title = next((heading.text for heading in headings if heading.level == 1), None)
        if title is None and headings:
            title = headings[0].text
        raw_parts = [self._clean_text(line) for line in lines]
        raw_text = " ".join(part for part in raw_parts if part)
        return ConfluenceMarkdownExtraction(
            title=title or fallback_title,
            headings=tuple(headings),
            paragraphs=tuple(paragraphs),
            tables=tuple(tables),
            image_references=tuple(images),
            raw_text=raw_text,
        )

    def _headings(self, lines: list[str]) -> list[ParsedHeading]:
        headings: list[ParsedHeading] = []
        for line in lines:
            match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
            if match:
                headings.append(
                    ParsedHeading(level=len(match.group(1)), text=match.group(2).strip())
                )
        return headings

    def _tables(self, lines: list[str]) -> tuple[list[ParsedTable], set[int]]:
        tables: list[ParsedTable] = []
        consumed_lines: set[int] = set()
        index = 0
        while index + 1 < len(lines):
            if "|" not in lines[index] or not re.match(
                r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$",
                lines[index + 1],
            ):
                index += 1
                continue
            headers = self._split_row(lines[index])
            rows: list[list[str]] = []
            consumed_lines.update({index, index + 1})
            row_index = index + 2
            while row_index < len(lines) and "|" in lines[row_index] and lines[row_index].strip():
                rows.append(self._split_row(lines[row_index]))
                consumed_lines.add(row_index)
                row_index += 1
            tables.append(ParsedTable(headers=headers, rows=rows))
            index = row_index
        return tables, consumed_lines

    def _paragraphs(
        self,
        lines: list[str],
        excluded_lines: set[int],
    ) -> list[ParsedParagraph]:
        paragraphs: list[ParsedParagraph] = []
        current: list[str] = []

        def flush() -> None:
            text = " ".join(part for part in current if part).strip()
            if text:
                paragraphs.append(ParsedParagraph(text=text))
            current.clear()

        for index, line in enumerate(lines):
            if index in excluded_lines or re.match(r"^#{1,6}\s+", line):
                flush()
                continue
            cleaned = self._clean_text(line)
            if not cleaned:
                flush()
            else:
                current.append(cleaned)
        flush()
        return paragraphs

    def _images(self, content: str) -> list[ImageReference]:
        images: list[ImageReference] = []
        pattern = r"!\[(?P<alt>[^]]*)\]\((?P<src>[^\s)]+)(?:\s+[\"'](?P<title>.*?)[\"'])?\)"
        for match in re.finditer(pattern, content):
            source = match.group("src")
            alt_text = match.group("alt") or None
            title = match.group("title") or None
            descriptor = f"{source} {alt_text or ''} {title or ''}".lower()
            images.append(
                ImageReference(
                    source=source,
                    alt_text=alt_text,
                    title=title,
                    is_diagram=any(
                        marker in descriptor for marker in ("diagram", "drawio", "gliffy")
                    ),
                )
            )
        return images

    def _split_row(self, row: str) -> list[str]:
        return [cell.strip() for cell in row.strip().strip("|").split("|")]

    def _clean_text(self, text: str) -> str:
        cleaned = re.sub(r"!\[([^]]*)\]\([^)]*\)", r"\1", text)
        cleaned = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", cleaned)
        cleaned = re.sub(r"^#{1,6}\s+", "", cleaned)
        cleaned = re.sub(r"[*_`~>]", "", cleaned)
        if re.match(r"^\s*\|?\s*:?-{3,}", cleaned):
            return ""
        if "|" in cleaned:
            cleaned = " ".join(self._split_row(cleaned))
        return join_text_parts([cleaned])
