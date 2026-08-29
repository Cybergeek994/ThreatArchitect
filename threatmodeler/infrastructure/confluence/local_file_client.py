"""Local Confluence export client adapter."""

import base64
import hashlib
import mimetypes
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse

from pydantic import AnyUrl

from threatmodeler.contracts.integration import (
    AttachmentContent,
    AttachmentKind,
    ConfluencePage,
)
from threatmodeler.contracts.source import SourceReference, SourceType
from threatmodeler.errors.application import ConfluenceClientError


class _LocalAttachmentReferenceParser(HTMLParser):
    """Collect local attachment paths referenced by an HTML export."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        reference: str | None = None
        if tag == "img":
            reference = attributes.get("src")
        elif tag == "object":
            reference = attributes.get("data")
        elif tag == "a":
            reference = attributes.get("href")
        elif tag == "ri:attachment":
            reference = attributes.get("ri:filename") or attributes.get("filename")
        if reference:
            self.references.append(reference)


class LocalFileConfluenceClient:
    """Adapt exported Confluence HTML or Markdown files to the client port."""

    def __init__(self, max_attachment_bytes: int = 10_000_000) -> None:
        if max_attachment_bytes < 1:
            raise ConfluenceClientError(
                "Local attachment size limit must be greater than zero",
                error_code="CONFLUENCE_ATTACHMENT_LIMIT_INVALID",
                retryable=False,
                context={"max_attachment_bytes": max_attachment_bytes},
            )
        self._max_attachment_bytes = max_attachment_bytes

    def get_page(self, page_id_or_url: str) -> ConfluencePage:
        """Read a supported local export into a Confluence page contract.

        Args:
            page_id_or_url: Path to an exported HTML or Markdown file.

        Returns:
            Validated page whose source points to the resolved local file.

        Raises:
            ConfluenceClientError: If the file is unavailable, unreadable, or unsupported.
        """
        path = Path(page_id_or_url).expanduser()
        try:
            resolved_path = path.resolve(strict=True)
            media_type = self._media_type(resolved_path)
            content = resolved_path.read_text(encoding="utf-8-sig")
            return ConfluencePage(
                page_id=resolved_path.stem,
                title=resolved_path.stem,
                url=AnyUrl(resolved_path.as_uri()),
                content=content,
                version=1,
                media_type=media_type,
                source_type=SourceType.CONFLUENCE_ATTACHMENT,
            )
        except ConfluenceClientError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise ConfluenceClientError(
                "Unable to read the local Confluence export",
                error_code="CONFLUENCE_LOCAL_READ_FAILED",
                retryable=False,
                context={"path": str(path)},
            ) from error

    def get_attachments(self, page_id_or_url: str) -> list[AttachmentContent]:
        """Load files referenced by a local HTML or Markdown export.

        References outside the export directory and remote URLs are ignored. This keeps
        local ingestion confined to the directory explicitly supplied by the user.

        Args:
            page_id_or_url: Path to an exported HTML or Markdown file.

        Returns:
            Deduplicated, integrity-checked attachment content.

        Raises:
            ConfluenceClientError: If a referenced file is unreadable or exceeds limits.
        """
        export_path = Path(page_id_or_url).expanduser()
        try:
            resolved_export = export_path.resolve(strict=True)
            media_type = self._media_type(resolved_export)
            content = resolved_export.read_text(encoding="utf-8-sig")
            references = self._attachment_references(content, media_type)
            return self._load_references(resolved_export, references)
        except ConfluenceClientError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise ConfluenceClientError(
                "Unable to load local Confluence attachments",
                error_code="CONFLUENCE_ATTACHMENT_READ_FAILED",
                retryable=False,
                context={"path": str(export_path)},
            ) from error

    def _media_type(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix in {".html", ".htm"}:
            return "text/html"
        if suffix in {".md", ".markdown"}:
            return "text/markdown"
        raise ConfluenceClientError(
            "Only HTML and Markdown Confluence exports are supported",
            error_code="CONFLUENCE_LOCAL_UNSUPPORTED_TYPE",
            retryable=False,
            context={"path": str(path), "suffix": suffix},
        )

    def _attachment_references(self, content: str, media_type: str) -> list[str]:
        if media_type == "text/html":
            parser = _LocalAttachmentReferenceParser()
            parser.feed(content)
            parser.close()
            return parser.references
        image_references = re.findall(r"!\[[^]]*]\(([^\s)]+)", content)
        link_references = re.findall(r"(?<!!)\[[^]]+]\(([^\s)]+)", content)
        return [*image_references, *link_references]

    def _load_references(
        self,
        export_path: Path,
        references: list[str],
    ) -> list[AttachmentContent]:
        attachments: list[AttachmentContent] = []
        loaded_paths: set[Path] = set()
        export_root = export_path.parent.resolve()
        for reference in references:
            parsed = urlparse(reference.strip("<>\"'"))
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            candidate = (export_root / unquote(parsed.path)).resolve()
            if (
                candidate == export_path
                or candidate in loaded_paths
                or not candidate.is_relative_to(export_root)
                or not candidate.is_file()
            ):
                continue
            loaded_paths.add(candidate)
            attachments.append(self._read_attachment(export_path, candidate))
        return attachments

    def _read_attachment(self, export_path: Path, attachment_path: Path) -> AttachmentContent:
        try:
            size_bytes = attachment_path.stat().st_size
            if size_bytes < 1 or size_bytes > self._max_attachment_bytes:
                raise ConfluenceClientError(
                    "A local Confluence attachment violates the configured size limit",
                    error_code="CONFLUENCE_ATTACHMENT_SIZE_INVALID",
                    retryable=False,
                    context={
                        "path": str(attachment_path),
                        "size_bytes": size_bytes,
                        "max_attachment_bytes": self._max_attachment_bytes,
                    },
                )
            content = attachment_path.read_bytes()
        except ConfluenceClientError:
            raise
        except OSError as error:
            raise ConfluenceClientError(
                "Unable to read a local Confluence attachment",
                error_code="CONFLUENCE_ATTACHMENT_READ_FAILED",
                retryable=False,
                context={"path": str(attachment_path)},
            ) from error

        relative_name = attachment_path.relative_to(export_path.parent.resolve()).as_posix()
        media_type = mimetypes.guess_type(attachment_path.name)[0] or "application/octet-stream"
        kind = self._attachment_kind(attachment_path.name, media_type)
        source_type = (
            SourceType.DIAGRAM
            if kind is AttachmentKind.DIAGRAM
            else SourceType.CONFLUENCE_ATTACHMENT
        )
        source_reference = SourceReference(
            source_type=source_type,
            source_id=f"{export_path.stem}:{relative_name}",
            location=attachment_path.as_uri(),
            excerpt=f"Attachment {relative_name} referenced by {export_path.name}",
        )
        return AttachmentContent(
            attachment_id=source_reference.source_id,
            filename=attachment_path.name,
            media_type=media_type,
            kind=kind,
            content_base64=base64.b64encode(content).decode("ascii"),
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            source_reference=source_reference,
        )

    def _attachment_kind(self, filename: str, media_type: str) -> AttachmentKind:
        descriptor = filename.lower()
        if any(marker in descriptor for marker in ("drawio", "gliffy", "diagram")):
            return AttachmentKind.DIAGRAM
        if media_type.startswith("image/"):
            return AttachmentKind.IMAGE
        if media_type.startswith("text/") or media_type in {
            "application/pdf",
            "application/json",
            "application/xml",
        }:
            return AttachmentKind.DOCUMENT
        return AttachmentKind.OTHER
