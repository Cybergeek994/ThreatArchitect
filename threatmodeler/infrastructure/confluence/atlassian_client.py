"""Atlassian Confluence Cloud REST API adapter."""

import base64
import hashlib
import re
from typing import NoReturn
from urllib.parse import parse_qs, quote, urljoin, urlparse

from pydantic import (
    AliasChoices,
    AliasPath,
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
)

from threatmodeler.contracts.integration import (
    AttachmentContent,
    AttachmentKind,
    ConfluencePage,
)
from threatmodeler.contracts.source import SourceReference, SourceType
from threatmodeler.errors.application import ConfigurationError, ConfluenceClientError
from threatmodeler.ports.http_transport import HttpTransport


class _AtlassianPageResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(strict=True, min_length=1)
    title: str = Field(strict=True, min_length=1)
    version_number: int = Field(  # type: ignore[pydantic-alias]
        strict=True,
        ge=1,
        validation_alias=AliasPath("version", "number"),
    )
    storage_value: str = Field(  # type: ignore[pydantic-alias]
        strict=True,
        min_length=1,
        validation_alias=AliasPath("body", "storage", "value"),
    )
    webui: str | None = Field(  # type: ignore[pydantic-alias]
        default=None,
        validation_alias=AliasPath("_links", "webui"),
    )


class _AtlassianAttachmentResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(strict=True, min_length=1)
    title: str = Field(strict=True, min_length=1)
    media_type: str = Field(
        strict=True,
        min_length=1,
        validation_alias="mediaType",
    )
    file_size: int = Field(
        strict=True,
        ge=1,
        validation_alias="fileSize",
    )
    download_link: str = Field(  # type: ignore[pydantic-alias]
        strict=True,
        min_length=1,
        validation_alias=AliasChoices("downloadLink", AliasPath("_links", "download")),
    )


class _AtlassianAttachmentPage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    results: list[_AtlassianAttachmentResponse]
    next_link: str | None = Field(  # type: ignore[pydantic-alias]
        default=None,
        validation_alias=AliasPath("_links", "next"),
    )


class AtlassianConfluenceClient:
    """Adapt Confluence Cloud REST API v2 pages to the Confluence client port.

    Authentication settings and an HTTP transport are injected, allowing request behavior
    to be tested without constructing a global network client.
    """

    def __init__(
        self,
        base_url: AnyHttpUrl,
        user_email: str,
        api_token: SecretStr,
        transport: HttpTransport,
        *,
        timeout_seconds: float = 30.0,
        max_attachment_bytes: int = 10_000_000,
        max_attachments: int = 50,
    ) -> None:
        if timeout_seconds <= 0:
            raise ConfigurationError(
                "Confluence request timeout must be greater than zero",
                error_code="CONFLUENCE_TIMEOUT_INVALID",
                retryable=False,
                context={"timeout_seconds": timeout_seconds},
            )
        if max_attachment_bytes < 1 or max_attachments < 1:
            raise ConfigurationError(
                "Confluence attachment limits must be greater than zero",
                error_code="CONFLUENCE_ATTACHMENT_LIMIT_INVALID",
                retryable=False,
                context={
                    "max_attachment_bytes": max_attachment_bytes,
                    "max_attachments": max_attachments,
                },
            )
        self._base_url = str(base_url).rstrip("/")
        self._user_email = user_email
        self._api_token = api_token
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._max_attachment_bytes = max_attachment_bytes
        self._max_attachments = max_attachments

    def get_page(self, page_id_or_url: str) -> ConfluencePage:
        """Retrieve and normalize a page identified by an ID or Confluence URL.

        Args:
            page_id_or_url: Numeric page identifier or URL containing one.

        Returns:
            Validated page containing the Confluence storage-format body.

        Raises:
            ConfluenceClientError: If the reference, request, or API response is invalid.
        """
        page_id = self._extract_page_id(page_id_or_url)
        endpoint = self._page_endpoint(page_id)
        try:
            response = self._transport.get(
                endpoint,
                self._request_headers(),
                self._timeout_seconds,
            )
        except (OSError, TimeoutError) as error:
            raise ConfluenceClientError(
                "Unable to connect to Atlassian Confluence",
                error_code="CONFLUENCE_CONNECTION_FAILED",
                retryable=True,
                context={"page_id": page_id},
            ) from error

        if not 200 <= response.status_code < 300:
            self._raise_for_status(response.status_code, page_id)

        try:
            page = _AtlassianPageResponse.model_validate_json(response.body)
            return ConfluencePage(
                page_id=page.id,
                title=page.title,
                url=self._page_url(page_id_or_url, page, endpoint),
                content=page.storage_value,
                version=page.version_number,
                media_type="text/html",
                source_type=SourceType.CONFLUENCE_PAGE,
            )
        except ValidationError as error:
            raise ConfluenceClientError(
                "Confluence returned an invalid page response",
                error_code="CONFLUENCE_RESPONSE_INVALID",
                retryable=False,
                context={"page_id": page_id},
            ) from error

    def get_attachments(self, page_id_or_url: str) -> list[AttachmentContent]:
        """Retrieve and authenticate-download all attachments for a page.

        Args:
            page_id_or_url: Numeric page identifier or URL containing one.

        Returns:
            Attachment content suitable for typed agent request inputs.

        Raises:
            ConfluenceClientError: If listing, validation, or download fails.
        """
        page_id = self._extract_page_id(page_id_or_url)
        endpoint: str | None = self._attachments_endpoint(page_id)
        attachments: list[AttachmentContent] = []
        while endpoint is not None:
            attachment_page = self._request_attachment_page(endpoint, page_id)
            for attachment in attachment_page.results:
                if len(attachments) >= self._max_attachments:
                    raise ConfluenceClientError(
                        "The Confluence page exceeds the configured attachment count limit",
                        error_code="CONFLUENCE_ATTACHMENT_COUNT_EXCEEDED",
                        retryable=False,
                        context={
                            "page_id": page_id,
                            "max_attachments": self._max_attachments,
                        },
                    )
                attachments.append(self._download_attachment(page_id, attachment))
            endpoint = (
                self._absolute_url(attachment_page.next_link) if attachment_page.next_link else None
            )
        return attachments

    def _extract_page_id(self, page_id_or_url: str) -> str:
        reference = page_id_or_url.strip()
        if re.fullmatch(r"[0-9]+", reference):
            return reference

        parsed = urlparse(reference)
        if parsed.scheme not in {"http", "https"}:
            self._raise_invalid_reference(page_id_or_url)
        query = parse_qs(parsed.query)
        for key in ("pageId", "pageid"):
            values = query.get(key, [])
            if values and re.fullmatch(r"[0-9]+", values[0]):
                return values[0]
        segments = [segment for segment in parsed.path.split("/") if segment]
        for index, segment in enumerate(segments[:-1]):
            if segment == "pages" and re.fullmatch(r"[0-9]+", segments[index + 1]):
                return segments[index + 1]
        self._raise_invalid_reference(page_id_or_url)

    def _raise_invalid_reference(self, page_id_or_url: str) -> NoReturn:
        raise ConfluenceClientError(
            "A numeric Confluence page ID could not be found in the input",
            error_code="CONFLUENCE_PAGE_ID_INVALID",
            retryable=False,
            context={"page_id_or_url": page_id_or_url},
        )

    def _page_endpoint(self, page_id: str) -> str:
        return f"{self._api_root()}/pages/{quote(page_id, safe='')}?body-format=storage"

    def _attachments_endpoint(self, page_id: str) -> str:
        return f"{self._api_root()}/pages/{quote(page_id, safe='')}/attachments?limit=50"

    def _api_root(self) -> str:
        return (
            f"{self._base_url}/api/v2"
            if self._base_url.endswith("/wiki")
            else f"{self._base_url}/wiki/api/v2"
        )

    def _request_headers(self) -> dict[str, str]:
        credentials = f"{self._user_email}:{self._api_token.get_secret_value()}".encode()
        encoded_credentials = base64.b64encode(credentials).decode("ascii")
        return {
            "Accept": "application/json",
            "Authorization": f"Basic {encoded_credentials}",
        }

    def _request_attachment_page(
        self,
        endpoint: str,
        page_id: str,
    ) -> _AtlassianAttachmentPage:
        try:
            response = self._transport.get(
                endpoint,
                self._request_headers(),
                self._timeout_seconds,
            )
        except (OSError, TimeoutError) as error:
            raise ConfluenceClientError(
                "Unable to list Confluence attachments",
                error_code="CONFLUENCE_ATTACHMENT_LIST_FAILED",
                retryable=True,
                context={"page_id": page_id},
            ) from error
        if not 200 <= response.status_code < 300:
            self._raise_for_status(response.status_code, page_id)
        try:
            return _AtlassianAttachmentPage.model_validate_json(response.body)
        except ValidationError as error:
            raise ConfluenceClientError(
                "Confluence returned invalid attachment metadata",
                error_code="CONFLUENCE_ATTACHMENT_RESPONSE_INVALID",
                retryable=False,
                context={"page_id": page_id},
            ) from error

    def _download_attachment(
        self,
        page_id: str,
        attachment: _AtlassianAttachmentResponse,
    ) -> AttachmentContent:
        if attachment.file_size > self._max_attachment_bytes:
            raise ConfluenceClientError(
                "A Confluence attachment exceeds the configured size limit",
                error_code="CONFLUENCE_ATTACHMENT_SIZE_EXCEEDED",
                retryable=False,
                context={
                    "page_id": page_id,
                    "attachment_id": attachment.id,
                    "size_bytes": attachment.file_size,
                    "max_attachment_bytes": self._max_attachment_bytes,
                },
            )
        download_url = self._absolute_url(attachment.download_link)
        try:
            response = self._transport.get_binary(
                download_url,
                self._request_headers(),
                self._timeout_seconds,
            )
        except (OSError, TimeoutError) as error:
            raise ConfluenceClientError(
                "Unable to download a Confluence attachment",
                error_code="CONFLUENCE_ATTACHMENT_DOWNLOAD_FAILED",
                retryable=True,
                context={"page_id": page_id, "attachment_id": attachment.id},
            ) from error
        if not 200 <= response.status_code < 300:
            raise ConfluenceClientError(
                "Confluence attachment download failed",
                error_code="CONFLUENCE_ATTACHMENT_DOWNLOAD_FAILED",
                retryable=response.status_code == 429 or response.status_code >= 500,
                context={
                    "page_id": page_id,
                    "attachment_id": attachment.id,
                    "status_code": response.status_code,
                },
            )
        content = response.body
        if len(content) != attachment.file_size:
            raise ConfluenceClientError(
                "Downloaded Confluence attachment size does not match its metadata",
                error_code="CONFLUENCE_ATTACHMENT_SIZE_MISMATCH",
                retryable=True,
                context={
                    "page_id": page_id,
                    "attachment_id": attachment.id,
                    "expected_size": attachment.file_size,
                    "actual_size": len(content),
                },
            )
        kind = self._attachment_kind(attachment.title, attachment.media_type)
        source_type = (
            SourceType.DIAGRAM
            if kind is AttachmentKind.DIAGRAM
            else SourceType.CONFLUENCE_ATTACHMENT
        )
        return AttachmentContent(
            attachment_id=attachment.id,
            filename=attachment.title,
            media_type=attachment.media_type,
            kind=kind,
            content_base64=base64.b64encode(content).decode("ascii"),
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            source_reference=SourceReference(
                source_type=source_type,
                source_id=attachment.id,
                location=download_url,
                excerpt=f"Attachment {attachment.title} on Confluence page {page_id}",
            ),
        )

    def _absolute_url(self, reference: str) -> str:
        return urljoin(f"{self._base_url}/", reference)

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

    def _page_url(
        self,
        original_reference: str,
        page: _AtlassianPageResponse,
        endpoint: str,
    ) -> AnyHttpUrl:
        parsed = urlparse(original_reference)
        if parsed.scheme in {"http", "https"}:
            return AnyHttpUrl(original_reference)
        if page.webui:
            return AnyHttpUrl(urljoin(f"{self._base_url}/", page.webui))
        return AnyHttpUrl(endpoint.split("?", maxsplit=1)[0])

    def _raise_for_status(self, status_code: int, page_id: str) -> None:
        if status_code == 404:
            message, error_code, retryable = (
                "The Confluence page was not found",
                "CONFLUENCE_PAGE_NOT_FOUND",
                False,
            )
        elif status_code in {401, 403}:
            message, error_code, retryable = (
                "Confluence rejected the configured credentials",
                "CONFLUENCE_AUTH_FAILED",
                False,
            )
        elif status_code == 429:
            message, error_code, retryable = (
                "Confluence rate-limited the request",
                "CONFLUENCE_RATE_LIMITED",
                True,
            )
        elif status_code >= 500:
            message, error_code, retryable = (
                "Confluence reported a server error",
                "CONFLUENCE_SERVER_ERROR",
                True,
            )
        else:
            message, error_code, retryable = (
                "Confluence page retrieval failed",
                "CONFLUENCE_REQUEST_FAILED",
                False,
            )
        raise ConfluenceClientError(
            message,
            error_code=error_code,
            retryable=retryable,
            context={"page_id": page_id, "status_code": status_code},
        )
