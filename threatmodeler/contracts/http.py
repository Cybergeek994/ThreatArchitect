"""Typed contracts used at the HTTP transport boundary."""

from typing import Annotated

from pydantic import Field

from threatmodeler.contracts.base import ContractModel


class HttpResponse(ContractModel):
    """Provider-neutral result of an HTTP request."""

    status_code: Annotated[int, Field(strict=True, ge=100, le=599)]
    body: str
    headers: dict[str, str] = Field(default_factory=dict)


class BinaryHttpResponse(ContractModel):
    """Provider-neutral result of an HTTP request for binary content."""

    status_code: Annotated[int, Field(strict=True, ge=100, le=599)]
    body: bytes
    headers: dict[str, str] = Field(default_factory=dict)
