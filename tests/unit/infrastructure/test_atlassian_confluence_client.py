"""Tests for Atlassian Confluence Cloud ingestion adapters."""

import base64
import json
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import AnyHttpUrl, SecretStr
from threatmodeler.config.settings import Settings
from threatmodeler.contracts import (
    AttachmentKind,
    BinaryHttpResponse,
    HttpResponse,
    SourceType,
)
from threatmodeler.errors import ConfigurationError, ConfluenceClientError
from threatmodeler.infrastructure.confluence.atlassian_client import (
    AtlassianConfluenceClient,
)
from threatmodeler.infrastructure.confluence.client_factory import ConfluenceClientFactory
from threatmodeler.infrastructure.confluence.local_file_client import (
    LocalFileConfluenceClient,
)
from threatmodeler.ports.http_transport import HttpTransport


@pytest.fixture
def page_response_factory() -> Callable[..., HttpResponse]:
    """Return a fixture factory for Atlassian HTTP responses."""

    def create(*, status_code: int = 200, body: str | None = None) -> HttpResponse:
        payload = {
            "id": "12345",
            "title": "Payments Architecture",
            "version": {"number": 7},
            "body": {
                "storage": {
                    "value": "<h1>Overview</h1><p>Payments API</p>",
                    "representation": "storage",
                }
            },
            "_links": {"webui": "/wiki/spaces/ARB/pages/12345"},
        }
        return HttpResponse(
            status_code=status_code,
            body=json.dumps(payload) if body is None else body,
        )

    return create


@pytest.fixture
def mock_transport_factory() -> Callable[[HttpResponse], Mock]:
    """Return a fixture factory for standard HTTP transport mocks."""

    def create(response: HttpResponse) -> Mock:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = response
        return transport

    return create


@pytest.fixture
def confluence_client_factory() -> Callable[..., AtlassianConfluenceClient]:
    """Return a fixture factory for configured Atlassian clients."""

    def create(
        transport: HttpTransport,
        *,
        timeout_seconds: float = 30.0,
        max_attachment_bytes: int = 10_000_000,
        max_attachments: int = 50,
    ) -> AtlassianConfluenceClient:
        return AtlassianConfluenceClient(
            base_url=AnyHttpUrl("https://example.atlassian.net"),
            user_email="architect@example.test",
            api_token=SecretStr("test-api-token"),
            transport=transport,
            timeout_seconds=timeout_seconds,
            max_attachment_bytes=max_attachment_bytes,
            max_attachments=max_attachments,
        )

    return create


class TestAtlassianConfluenceClientPositive:
    """Verify supported inputs and successful behavior."""

    def test_get_page_by_id_uses_rest_v2_and_maps_validated_response(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = mock_transport_factory(page_response_factory())

        page = confluence_client_factory(transport).get_page("12345")

        assert page.page_id == "12345"
        assert page.title == "Payments Architecture"
        assert page.version == 7
        assert page.content == "<h1>Overview</h1><p>Payments API</p>"
        assert page.source_type is SourceType.CONFLUENCE_PAGE
        assert str(page.url) == "https://example.atlassian.net/wiki/spaces/ARB/pages/12345"
        url, headers, timeout = transport.get.call_args.args
        assert url == ("https://example.atlassian.net/wiki/api/v2/pages/12345?body-format=storage")
        encoded = headers["Authorization"].removeprefix("Basic ")
        assert base64.b64decode(encoded).decode() == "architect@example.test:test-api-token"
        assert headers["Accept"] == "application/json"
        assert timeout == 30.0

    @pytest.mark.parametrize(
        "reference",
        [
            "https://example.atlassian.net/wiki/spaces/ARB/pages/12345/Payments",
            "https://example.atlassian.net/pages/viewpage.action?pageId=12345",
            "https://example.atlassian.net/wiki/api/v2/pages/12345",
        ],
    )

    def test_get_page_extracts_id_from_supported_confluence_urls(
        self,
        reference: str,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = mock_transport_factory(page_response_factory())

        page = confluence_client_factory(transport).get_page(reference)

        assert page.page_id == "12345"
        assert str(page.url) == reference

    def test_get_attachments_downloads_authenticated_binary_content(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        content = b"drawio-content"
        metadata = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "runtime.drawio",
                            "mediaType": "application/vnd.jgraph.mxfile",
                            "fileSize": len(content),
                            "downloadLink": "/download/attachments/12345/runtime.drawio",
                        }
                    ],
                    "_links": {},
                }
            ),
        )
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = metadata
        transport.get_binary.return_value = BinaryHttpResponse(
            status_code=200,
            body=content,
        )

        attachments = confluence_client_factory(transport).get_attachments("12345")

        assert len(attachments) == 1
        assert attachments[0].kind is AttachmentKind.DIAGRAM
        assert attachments[0].decoded_content() == content
        assert attachments[0].source_reference.source_type is SourceType.DIAGRAM
        list_url = transport.get.call_args.args[0]
        assert list_url.endswith("/wiki/api/v2/pages/12345/attachments?limit=50")
        download_url, headers, timeout = transport.get_binary.call_args.args
        assert download_url == (
            "https://example.atlassian.net/download/attachments/12345/runtime.drawio"
        )
        assert headers["Authorization"].startswith("Basic ")
        assert timeout == 30.0

    def test_factory_selects_local_export_without_remote_configuration(
        self,
        tmp_path: Path,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
    ) -> None:
        local_path = tmp_path / "page.html"
        factory = ConfluenceClientFactory(
            Settings(),
            lambda: mock_transport_factory(page_response_factory()),
        )

        selected = factory.create(str(local_path))

        assert isinstance(selected, LocalFileConfluenceClient)

    def test_factory_builds_atlassian_client_from_settings(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
    ) -> None:
        factory = ConfluenceClientFactory(
            Settings(
                confluence_base_url=AnyHttpUrl("https://example.atlassian.net/wiki"),
                confluence_user_email="architect@example.test",
                confluence_api_key=SecretStr("test-token"),
            ),
            lambda: mock_transport_factory(page_response_factory()),
        )

        selected = factory.create("12345")
        page = selected.get_page("12345")

        assert isinstance(selected, AtlassianConfluenceClient)
        assert page.page_id == "12345"


class TestAtlassianConfluenceClientNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_invalid_reference_and_response_fail_cleanly(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = mock_transport_factory(page_response_factory(body="not-json"))

        with pytest.raises(ConfluenceClientError, match="numeric Confluence page ID") as invalid:
            confluence_client_factory(transport).get_page("not-a-page")
        with pytest.raises(ConfluenceClientError) as malformed:
            confluence_client_factory(transport).get_page("12345")

        assert invalid.value.error_code == "CONFLUENCE_PAGE_ID_INVALID"
        assert malformed.value.error_code == "CONFLUENCE_RESPONSE_INVALID"

    def test_factory_requires_remote_configuration(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
    ) -> None:
        factory = ConfluenceClientFactory(
            Settings(),
            lambda: mock_transport_factory(page_response_factory()),
        )

        with pytest.raises(ConfigurationError) as captured:
            factory.create("12345")

        assert captured.value.error_code == "CONFLUENCE_CONFIG_MISSING"
        assert captured.value.context == {
            "missing_fields": [
                "confluence_base_url",
                "confluence_user_email",
                "confluence_api_key",
            ]
        }

    def test_attachment_metadata_over_size_limit_is_rejected_before_download(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "large.pdf",
                            "mediaType": "application/pdf",
                            "fileSize": 100,
                            "downloadLink": "/download/large.pdf",
                        }
                    ]
                }
            ),
        )

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(
                transport,
                max_attachment_bytes=10,
            ).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_SIZE_EXCEEDED"
        transport.get_binary.assert_not_called()


class TestAtlassianConfluenceClientErrors:
    """Verify dependency and application failures remain controlled."""

    @pytest.mark.parametrize(
        ("status_code", "error_code", "retryable"),
        [
            (401, "CONFLUENCE_AUTH_FAILED", False),
            (404, "CONFLUENCE_PAGE_NOT_FOUND", False),
            (429, "CONFLUENCE_RATE_LIMITED", True),
            (503, "CONFLUENCE_SERVER_ERROR", True),
            (418, "CONFLUENCE_REQUEST_FAILED", False),
        ],
    )

    def test_http_failures_are_mapped_to_custom_errors(
        self,
        status_code: int,
        error_code: str,
        retryable: bool,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(
                mock_transport_factory(page_response_factory(status_code=status_code))
            ).get_page("12345")

        assert captured.value.error_code == error_code
        assert captured.value.retryable is retryable
        assert captured.value.context == {"page_id": "12345", "status_code": status_code}

    def test_connection_failure_is_retryable_and_timeout_is_validated(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        failing_transport = Mock(spec=HttpTransport)
        failing_transport.get.side_effect = OSError("Unable to reach Confluence")
        with pytest.raises(ConfluenceClientError) as connection:
            confluence_client_factory(failing_transport).get_page("12345")
        with pytest.raises(ConfigurationError) as invalid_timeout:
            confluence_client_factory(
                mock_transport_factory(page_response_factory()), timeout_seconds=0
            )

        assert connection.value.error_code == "CONFLUENCE_CONNECTION_FAILED"
        assert connection.value.retryable is True
        assert invalid_timeout.value.error_code == "CONFLUENCE_TIMEOUT_INVALID"

    def test_invalid_attachment_limits_are_rejected_at_construction(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        with pytest.raises(ConfigurationError) as captured:
            confluence_client_factory(
                mock_transport_factory(page_response_factory()),
                max_attachment_bytes=0,
            )

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_LIMIT_INVALID"

    def test_attachment_count_limit_is_enforced(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        content = b"x"
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": f"att-{index}",
                            "title": f"file-{index}.txt",
                            "mediaType": "text/plain",
                            "fileSize": len(content),
                            "downloadLink": f"/download/file-{index}.txt",
                        }
                        for index in range(3)
                    ],
                    "_links": {},
                }
            ),
        )
        transport.get_binary.return_value = BinaryHttpResponse(status_code=200, body=content)

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport, max_attachments=2).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_COUNT_EXCEEDED"

    def test_attachment_pagination_follows_next_links(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        content = b"page"
        first_page = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "first.txt",
                            "mediaType": "text/plain",
                            "fileSize": len(content),
                            "downloadLink": "/download/first.txt",
                        }
                    ],
                    "_links": {"next": "/wiki/api/v2/pages/12345/attachments?cursor=next"},
                }
            ),
        )
        second_page = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-2",
                            "title": "second.txt",
                            "mediaType": "text/plain",
                            "fileSize": len(content),
                            "downloadLink": "/download/second.txt",
                        }
                    ],
                    "_links": {},
                }
            ),
        )
        transport = Mock(spec=HttpTransport)
        transport.get.side_effect = [first_page, second_page]
        transport.get_binary.return_value = BinaryHttpResponse(status_code=200, body=content)

        attachments = confluence_client_factory(transport).get_attachments("12345")

        assert len(attachments) == 2
        assert transport.get.call_count == 2

    def test_page_url_uses_webui_link_for_numeric_page_ids(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = mock_transport_factory(page_response_factory())

        page = confluence_client_factory(transport).get_page("12345")

        assert str(page.url) == "https://example.atlassian.net/wiki/spaces/ARB/pages/12345"

    def test_other_attachment_kind_is_supported(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        content = b"binary"
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "payload.bin",
                            "mediaType": "application/octet-stream",
                            "fileSize": len(content),
                            "downloadLink": "/download/payload.bin",
                        }
                    ],
                    "_links": {},
                }
            ),
        )
        transport.get_binary.return_value = BinaryHttpResponse(status_code=200, body=content)

        attachments = confluence_client_factory(transport).get_attachments("12345")

        assert attachments[0].kind is AttachmentKind.OTHER


class TestAtlassianConfluenceClientAttachmentErrors:
    """Verify attachment listing and download failures are mapped."""

    def test_attachment_list_connection_failure(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.side_effect = OSError("network down")

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_LIST_FAILED"

    def test_invalid_attachment_metadata_response(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(status_code=200, body='{"results": [{}]}')

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_RESPONSE_INVALID"

    def test_attachment_list_http_failure(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(status_code=404, body="{}")

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_PAGE_NOT_FOUND"

    def test_attachment_download_connection_failure(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "file.txt",
                            "mediaType": "text/plain",
                            "fileSize": 4,
                            "downloadLink": "/download/file.txt",
                        }
                    ]
                }
            ),
        )
        transport.get_binary.side_effect = OSError("download failed")

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_DOWNLOAD_FAILED"

    def test_attachment_download_http_failure(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "file.txt",
                            "mediaType": "text/plain",
                            "fileSize": 4,
                            "downloadLink": "/download/file.txt",
                        }
                    ]
                }
            ),
        )
        transport.get_binary.return_value = BinaryHttpResponse(status_code=503, body=b"")

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_DOWNLOAD_FAILED"
        assert captured.value.retryable is True

    def test_attachment_size_mismatch_is_reported(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "file.txt",
                            "mediaType": "text/plain",
                            "fileSize": 10,
                            "downloadLink": "/download/file.txt",
                        }
                    ]
                }
            ),
        )
        transport.get_binary.return_value = BinaryHttpResponse(status_code=200, body=b"short")

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_attachments("12345")

        assert captured.value.error_code == "CONFLUENCE_ATTACHMENT_SIZE_MISMATCH"

    def test_invalid_page_reference_without_numeric_id(
        self,
        page_response_factory: Callable[..., HttpResponse],
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        transport = mock_transport_factory(page_response_factory())

        with pytest.raises(ConfluenceClientError) as captured:
            confluence_client_factory(transport).get_page("https://example.com/no-page-id")

        assert captured.value.error_code == "CONFLUENCE_PAGE_ID_INVALID"

    def test_image_attachment_kind_is_detected_from_media_type(
        self,
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        content = b"image"
        transport = Mock(spec=HttpTransport)
        transport.get.return_value = HttpResponse(
            status_code=200,
            body=json.dumps(
                {
                    "results": [
                        {
                            "id": "att-1",
                            "title": "photo.png",
                            "mediaType": "image/png",
                            "fileSize": len(content),
                            "downloadLink": "/download/photo.png",
                        }
                    ],
                    "_links": {},
                }
            ),
        )
        transport.get_binary.return_value = BinaryHttpResponse(status_code=200, body=content)

        attachments = confluence_client_factory(transport).get_attachments("12345")

        assert attachments[0].kind is AttachmentKind.IMAGE

    def test_page_url_falls_back_to_api_endpoint_without_webui(
        self,
        mock_transport_factory: Callable[[HttpResponse], Mock],
        confluence_client_factory: Callable[..., AtlassianConfluenceClient],
    ) -> None:
        payload = {
            "id": "12345",
            "title": "Payments Architecture",
            "version": {"number": 7},
            "body": {
                "storage": {
                    "value": "<h1>Overview</h1>",
                    "representation": "storage",
                }
            },
            "_links": {},
        }
        transport = mock_transport_factory(HttpResponse(status_code=200, body=json.dumps(payload)))

        page = confluence_client_factory(transport).get_page("12345")

        assert str(page.url).endswith("/wiki/api/v2/pages/12345")
