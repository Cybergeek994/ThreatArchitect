"""Tests for the standard-library HTTP transport adapter."""

import io
from email.message import Message
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from threatmodeler.infrastructure.http.urllib_transport import UrllibHttpTransport


class TestUrllibHttpTransportPositive:
    """Verify successful GET and binary GET responses."""

    def test_get_returns_decoded_response_body(self) -> None:
        response = MagicMock()
        response.status = 200
        response.read.return_value = b'{"ok": true}'
        response.headers.items.return_value = [("Content-Type", "application/json")]
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)

        with patch(
            "threatmodeler.infrastructure.http.urllib_transport.urlopen",
            return_value=response,
        ):
            result = UrllibHttpTransport().get("https://example.test/page", {}, 5.0)

        assert result.status_code == 200
        assert result.body == '{"ok": true}'
        assert result.headers["Content-Type"] == "application/json"

    def test_get_binary_returns_bytes(self) -> None:
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"\x89PNG"
        response.headers.items.return_value = []
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)

        with patch(
            "threatmodeler.infrastructure.http.urllib_transport.urlopen",
            return_value=response,
        ):
            result = UrllibHttpTransport().get_binary("https://example.test/file", {}, 5.0)

        assert result.status_code == 200
        assert result.body == b"\x89PNG"


class TestUrllibHttpTransportErrors:
    """Verify HTTP errors are returned instead of raised."""

    def test_get_maps_http_error_to_response(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/plain"
        error = HTTPError(
            url="https://example.test/missing",
            code=404,
            msg="Not Found",
            hdrs=headers,
            fp=io.BytesIO(b"missing"),
        )

        with patch(
            "threatmodeler.infrastructure.http.urllib_transport.urlopen",
            side_effect=error,
        ):
            result = UrllibHttpTransport().get("https://example.test/missing", {}, 5.0)

        assert result.status_code == 404
        assert result.body == "missing"

    def test_get_binary_maps_http_error_without_headers(self) -> None:
        error = HTTPError(
            url="https://example.test/missing",
            code=500,
            msg="Server Error",
            hdrs=Message(),
            fp=io.BytesIO(b"failure"),
        )

        with patch(
            "threatmodeler.infrastructure.http.urllib_transport.urlopen",
            side_effect=error,
        ):
            result = UrllibHttpTransport().get_binary("https://example.test/missing", {}, 5.0)

        assert result.status_code == 500
        assert result.body == b"failure"
        assert result.headers == {}
