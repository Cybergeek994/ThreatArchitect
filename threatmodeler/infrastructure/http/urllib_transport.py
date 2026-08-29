"""Standard-library HTTP transport adapter."""

from collections.abc import Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from threatmodeler.contracts.http import BinaryHttpResponse, HttpResponse


class UrllibHttpTransport:
    """Execute HTTP requests with the Python standard library."""

    def get(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> HttpResponse:
        """Execute a GET and preserve non-success responses for adapter handling.

        Args:
            url: Absolute HTTP or HTTPS URL to request.
            headers: Request headers copied into the transport-specific request.
            timeout_seconds: Maximum duration allowed for the network operation.

        Returns:
            Typed response containing status, decoded body, and response headers.
        """
        request = Request(url=url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return HttpResponse(
                    status_code=response.status,
                    body=response.read().decode("utf-8"),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as error:
            return HttpResponse(
                status_code=error.code,
                body=error.read().decode("utf-8", errors="replace"),
                headers=dict(error.headers.items()) if error.headers is not None else {},
            )

    def get_binary(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> BinaryHttpResponse:
        """Execute a GET while preserving arbitrary binary response content.

        Args:
            url: Absolute HTTP or HTTPS URL to request.
            headers: Request headers copied into the transport-specific request.
            timeout_seconds: Maximum duration allowed for the network operation.

        Returns:
            Typed response containing status, bytes, and response headers.
        """
        request = Request(url=url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return BinaryHttpResponse(
                    status_code=response.status,
                    body=response.read(),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as error:
            return BinaryHttpResponse(
                status_code=error.code,
                body=error.read(),
                headers=dict(error.headers.items()) if error.headers is not None else {},
            )
