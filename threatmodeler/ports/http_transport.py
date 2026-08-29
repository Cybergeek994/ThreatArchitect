"""HTTP transport port owned by the application boundary."""

from collections.abc import Mapping
from typing import Protocol

from threatmodeler.contracts.http import BinaryHttpResponse, HttpResponse


class HttpTransport(Protocol):
    """Define HTTP GET execution without exposing a concrete network client."""

    def get(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> HttpResponse:
        """Execute a GET and return the complete response, including error statuses.

        Args:
            url: Absolute URL to request.
            headers: Request headers to send without mutation.
            timeout_seconds: Maximum duration allowed for transport activity.

        Returns:
            Typed status, body, and response headers.

        Raises:
            OSError: If the transport cannot establish or complete the connection.
            TimeoutError: If the configured timeout expires.
        """
        ...

    def get_binary(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> BinaryHttpResponse:
        """Execute a GET without decoding the response body.

        Args:
            url: Absolute URL to request.
            headers: Request headers to send without mutation.
            timeout_seconds: Maximum duration allowed for transport activity.

        Returns:
            Typed status, binary body, and response headers.

        Raises:
            OSError: If the transport cannot establish or complete the connection.
            TimeoutError: If the configured timeout expires.
        """
        ...
