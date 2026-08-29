"""HTMLParser-based extraction of Confluence page structure."""

from html.parser import HTMLParser

from threatmodeler.contracts.integration import (
    ImageReference,
    ParsedHeading,
    ParsedParagraph,
    ParsedTable,
)
from threatmodeler.infrastructure.parsing.confluence_text_utils import join_text_parts
from threatmodeler.infrastructure.parsing.diagram_content import extract_diagram_labels


class ConfluenceHtmlExtractor(HTMLParser):
    """Collect the small structured subset required by the MVP."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.headings: list[ParsedHeading] = []
        self.paragraphs: list[ParsedParagraph] = []
        self.tables: list[ParsedTable] = []
        self.image_references: list[ImageReference] = []
        self.raw_parts: list[str] = []
        self._in_title = False
        self._heading_level: int | None = None
        self._heading_parts: list[str] = []
        self._paragraph_parts: list[str] | None = None
        self._table_rows: list[tuple[list[str], bool]] | None = None
        self._row: list[str] | None = None
        self._row_has_header = False
        self._cell_parts: list[str] | None = None
        self._ignored_depth = 0
        self._list_tag: str | None = None
        self._list_item_parts: list[str] | None = None
        self._ordered_list_index = 0
        self._macro_body_parts: list[str] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Start collecting supported HTML elements."""
        attributes = dict(attrs)
        if tag in {"script", "style"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag == "title":
            self._in_title = True
        elif len(tag) == 2 and tag[0] == "h" and tag[1].isdigit():
            self._heading_level = int(tag[1])
            self._heading_parts = []
        elif tag == "p":
            self._paragraph_parts = []
        elif tag in {"ul", "ol"}:
            self._list_tag = tag
            self._ordered_list_index = 0
        elif tag == "li" and self._list_tag is not None:
            self._list_item_parts = []
        elif tag == "table":
            self._table_rows = []
        elif tag == "tr" and self._table_rows is not None:
            self._row = []
            self._row_has_header = False
        elif tag in {"th", "td"} and self._row is not None:
            self._cell_parts = []
            self._row_has_header = self._row_has_header or tag == "th"
        elif tag == "img":
            self._add_image(
                source=attributes.get("src"),
                alt_text=attributes.get("alt"),
                title=attributes.get("title"),
            )
        elif tag == "object":
            self._add_image(
                source=attributes.get("data"),
                alt_text=attributes.get("aria-label"),
                title=attributes.get("title"),
            )
        elif tag == "ri:attachment":
            self._add_image(
                source=attributes.get("ri:filename") or attributes.get("filename"),
                alt_text=attributes.get("ri:description"),
                title=attributes.get("ri:version-at-save"),
            )
        elif tag in {"ac:plain-text-body", "ac:rich-text-body"}:
            self._macro_body_parts = []

    def handle_endtag(self, tag: str) -> None:
        """Finish the active supported HTML element."""
        if tag in {"script", "style"}:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return
        if self._ignored_depth:
            return
        if tag == "title":
            self._in_title = False
        elif self._heading_level is not None and tag == f"h{self._heading_level}":
            text = join_text_parts(self._heading_parts)
            if text:
                self.headings.append(ParsedHeading(level=self._heading_level, text=text))
            self._heading_level = None
            self._heading_parts = []
        elif tag == "p" and self._paragraph_parts is not None:
            text = join_text_parts(self._paragraph_parts)
            if text:
                self.paragraphs.append(ParsedParagraph(text=text))
            self._paragraph_parts = None
        elif tag == "li" and self._list_item_parts is not None:
            text = join_text_parts(self._list_item_parts)
            if text:
                prefix = "- "
                if self._list_tag == "ol":
                    self._ordered_list_index += 1
                    prefix = f"{self._ordered_list_index}. "
                self.paragraphs.append(ParsedParagraph(text=f"{prefix}{text}"))
            self._list_item_parts = None
        elif tag in {"ul", "ol"} and self._list_tag == tag:
            self._list_tag = None
            self._ordered_list_index = 0
        elif (
            tag in {"ac:plain-text-body", "ac:rich-text-body"}
            and self._macro_body_parts is not None
        ):
            self._append_macro_body(join_text_parts(self._macro_body_parts))
            self._macro_body_parts = None
        elif tag in {"th", "td"} and self._cell_parts is not None:
            if self._row is not None:
                self._row.append(join_text_parts(self._cell_parts))
            self._cell_parts = None
        elif tag == "tr" and self._row is not None:
            if self._table_rows is not None and any(self._row):
                self._table_rows.append((self._row, self._row_has_header))
            self._row = None
            self._row_has_header = False
        elif tag == "table" and self._table_rows is not None:
            headers: list[str] = []
            rows = [row for row, _ in self._table_rows]
            if self._table_rows and self._table_rows[0][1]:
                headers = self._table_rows[0][0]
                rows = rows[1:]
            self.tables.append(ParsedTable(headers=headers, rows=rows))
            self._table_rows = None

    def handle_data(self, data: str) -> None:
        """Collect visible text for active elements and raw text output."""
        if self._ignored_depth or not data.strip():
            return
        self.raw_parts.append(data)
        if self._in_title:
            self.title_parts.append(data)
        if self._heading_level is not None:
            self._heading_parts.append(data)
        if self._paragraph_parts is not None:
            self._paragraph_parts.append(data)
        if self._list_item_parts is not None:
            self._list_item_parts.append(data)
        if self._cell_parts is not None:
            self._cell_parts.append(data)
        if self._macro_body_parts is not None:
            self._macro_body_parts.append(data)

    def _append_macro_body(self, text: str) -> None:
        if not text:
            return
        labels = extract_diagram_labels(text)
        if labels:
            for label in labels:
                self.paragraphs.append(ParsedParagraph(text=f"Diagram: {label}"))
            return
        self.paragraphs.append(ParsedParagraph(text=text))

    def _add_image(
        self,
        source: str | None,
        alt_text: str | None,
        title: str | None,
    ) -> None:
        if not source:
            return
        descriptor = f"{source} {alt_text or ''} {title or ''}".lower()
        self.image_references.append(
            ImageReference(
                source=source,
                alt_text=alt_text or None,
                title=title or None,
                is_diagram=any(marker in descriptor for marker in ("diagram", "drawio", "gliffy")),
            )
        )
