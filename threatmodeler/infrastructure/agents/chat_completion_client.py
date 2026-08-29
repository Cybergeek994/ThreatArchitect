"""OpenAI-compatible chat completion client for schema-bound agent requests."""

import json
import re
from collections.abc import Callable
from typing import Any, cast

from openai import APIConnectionError, APIStatusError, AuthenticationError, RateLimitError

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.infrastructure.agents.vision_message_builder import build_messages

CreateCompletion = Callable[..., object]

_MARKDOWN_JSON_FENCE = re.compile(
    r"^```(?:json)?\s*(.*?)\s*```$",
    re.DOTALL | re.IGNORECASE,
)
_RAW_RESPONSE_PREVIEW_CHARS = 500


class ChatCompletionAgentClient:
    """Execute agent requests through an injected OpenAI-compatible SDK client."""

    def __init__(
        self,
        create_completion: CreateCompletion,
        *,
        provider_name: str,
        model_name: str,
    ) -> None:
        self._create_completion = create_completion
        self._provider_name = provider_name
        self._model_name = model_name

    @property
    def provider_name(self) -> str:
        """Return the configured provider name."""
        return self._provider_name

    @property
    def model_name(self) -> str:
        """Return the configured model name."""
        return self._model_name

    def complete(self, request: AgentRequest) -> AgentResponse:
        """Complete one schema-bound agent request and normalize the JSON payload.

        Args:
            request: Provider-neutral request containing prompt messages and attachments.

        Returns:
            Provider response with a parsed JSON object payload.

        Raises:
            AgentProviderError: If the provider rejects or fails the request.
        """
        try:
            completion = self._create_completion(
                model=self._model_name,
                messages=build_messages(request),
                response_format={"type": "json_object"},
                **_sampling_kwargs(self._model_name, request.temperature),
                **_output_token_limit_kwargs(self._model_name, request.max_output_tokens),
            )
        except RateLimitError as error:
            raise AgentProviderError(
                "Agent provider rate limit exceeded",
                error_code="AGENT_PROVIDER_RATE_LIMIT",
                retryable=True,
                context=_rate_limit_error_context(request.task_name, error),
            ) from error
        except AuthenticationError as error:
            raise AgentProviderError(
                "Agent provider authentication failed",
                error_code="AGENT_PROVIDER_AUTH_FAILED",
                retryable=False,
                context={"task_name": request.task_name},
            ) from error
        except APIConnectionError as error:
            raise AgentProviderError(
                "Agent provider connection failed",
                error_code="AGENT_PROVIDER_CONNECTION_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error
        except APIStatusError as error:
            raise AgentProviderError(
                "Agent provider returned an error response",
                error_code="AGENT_PROVIDER_HTTP_ERROR",
                retryable=500 <= error.status_code < 600,
                context={
                    "task_name": request.task_name,
                    "status_code": error.status_code,
                    "provider_message": _provider_error_message(error),
                    "response_headers": _response_headers(error),
                },
            ) from error
        except Exception as error:
            raise AgentProviderError(
                "Agent provider request failed",
                error_code="AGENT_PROVIDER_REQUEST_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error

        message_content = _completion_message_content(completion)
        finish_reason = _completion_finish_reason(completion)
        if finish_reason == "length":
            raise AgentProviderError(
                "Agent provider output was truncated before valid JSON completed",
                error_code="AGENT_PROVIDER_OUTPUT_TRUNCATED",
                retryable=True,
                context={
                    "task_name": request.task_name,
                    "finish_reason": finish_reason,
                    "max_output_tokens": request.max_output_tokens,
                    "raw_response_preview": _raw_preview(message_content or ""),
                },
            )
        if not message_content:
            raise AgentProviderError(
                "Agent provider returned an empty completion",
                error_code="AGENT_PROVIDER_EMPTY_RESPONSE",
                retryable=False,
                context={"task_name": request.task_name},
            )
        candidate = _strip_markdown_fence(message_content.strip())
        try:
            output_payload = json.loads(candidate)
        except json.JSONDecodeError as error:
            raise AgentProviderError(
                "Agent provider returned invalid JSON",
                error_code="AGENT_PROVIDER_INVALID_JSON",
                retryable=True,
                context={
                    "task_name": request.task_name,
                    "finish_reason": finish_reason,
                    "json_error": error.msg,
                    "raw_response_preview": _raw_preview(message_content),
                },
            ) from error
        if not isinstance(output_payload, dict):
            raise AgentProviderError(
                "Agent provider JSON output must be an object",
                error_code="AGENT_PROVIDER_JSON_OBJECT_REQUIRED",
                retryable=False,
                context={"task_name": request.task_name},
            )
        return AgentResponse(
            output_payload=output_payload,
            confidence=0.75,
            raw_response=message_content,
            provider_name=self._provider_name,
            model_name=self._model_name,
        )

    def complete_turn(
        self,
        request: AgentRequest,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> object:
        """Invoke one chat-completion turn, optionally with tools.

        Args:
            request: Original request used for temperature, token limits, and errors.
            messages: Chat messages including prior tool results.
            tools: OpenAI tool definitions, or ``None`` for a plain completion.

        Returns:
            Raw SDK completion object.

        Raises:
            AgentProviderError: If the provider rejects or fails the request.
        """
        kwargs: dict[str, Any] = {
            "model": self._model_name,
            "messages": messages,
            **_sampling_kwargs(self._model_name, request.temperature),
            **_output_token_limit_kwargs(self._model_name, request.max_output_tokens),
            **_tool_calling_kwargs(self._model_name, tools),
        }
        if tools:
            kwargs["tools"] = tools
        try:
            return self._create_completion(**kwargs)
        except RateLimitError as error:
            raise AgentProviderError(
                "Agent provider rate limit exceeded",
                error_code="AGENT_PROVIDER_RATE_LIMIT",
                retryable=True,
                context=_rate_limit_error_context(request.task_name, error),
            ) from error
        except AuthenticationError as error:
            raise AgentProviderError(
                "Agent provider authentication failed",
                error_code="AGENT_PROVIDER_AUTH_FAILED",
                retryable=False,
                context={"task_name": request.task_name},
            ) from error
        except APIConnectionError as error:
            raise AgentProviderError(
                "Agent provider connection failed",
                error_code="AGENT_PROVIDER_CONNECTION_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error
        except APIStatusError as error:
            raise AgentProviderError(
                "Agent provider returned an error response",
                error_code="AGENT_PROVIDER_HTTP_ERROR",
                retryable=500 <= error.status_code < 600,
                context={
                    "task_name": request.task_name,
                    "status_code": error.status_code,
                    "provider_message": _provider_error_message(error),
                    "response_headers": _response_headers(error),
                },
            ) from error
        except Exception as error:
            raise AgentProviderError(
                "Agent provider request failed",
                error_code="AGENT_PROVIDER_REQUEST_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error


def _completion_message_content(completion: object) -> str | None:
    response = cast(Any, completion)
    content = response.choices[0].message.content
    return content if isinstance(content, str) else None


def _completion_finish_reason(completion: object) -> str | None:
    response = cast(Any, completion)
    reason = getattr(response.choices[0], "finish_reason", None)
    return reason if isinstance(reason, str) else None


def _strip_markdown_fence(content: str) -> str:
    match = _MARKDOWN_JSON_FENCE.match(content)
    if match is None:
        return content
    return match.group(1).strip()


def _raw_preview(content: str) -> str:
    if len(content) <= _RAW_RESPONSE_PREVIEW_CHARS:
        return content
    return content[:_RAW_RESPONSE_PREVIEW_CHARS] + "..."


def _requires_max_completion_tokens(model_name: str) -> bool:
    """Return whether the model rejects deprecated ``max_tokens``."""
    normalized = model_name.lower()
    return normalized.startswith(("gpt-5", "o1", "o3", "o4"))


def _supports_custom_temperature(model_name: str) -> bool:
    """Return whether the model accepts a non-default temperature."""
    return not _requires_max_completion_tokens(model_name)


def _sampling_kwargs(model_name: str, temperature: float) -> dict[str, float]:
    """Include temperature only when the model supports overriding the default."""
    if _supports_custom_temperature(model_name):
        return {"temperature": temperature}
    return {}


def _output_token_limit_kwargs(model_name: str, max_output_tokens: int) -> dict[str, int]:
    """Select the provider token-limit field for the configured model."""
    if _requires_max_completion_tokens(model_name):
        return {"max_completion_tokens": max_output_tokens}
    return {"max_tokens": max_output_tokens}


def _tool_calling_kwargs(
    model_name: str,
    tools: list[dict[str, Any]] | None,
) -> dict[str, str]:
    """Return Chat Completions kwargs required when function tools are present.

    GPT-5.6 models default to a non-none ``reasoning_effort`` that Chat Completions
    rejects together with function tools. Force ``none`` so tool-calling extract/model
    loops work without migrating to the Responses API.
    """
    if not tools:
        return {}
    if _requires_reasoning_effort_none_for_tools(model_name):
        return {"reasoning_effort": "none"}
    return {}


def _requires_reasoning_effort_none_for_tools(model_name: str) -> bool:
    """Return whether Chat Completions function tools require reasoning_effort=none."""
    return model_name.lower().startswith("gpt-5.6")


def _provider_error_message(error: APIStatusError) -> str:
    body = error.body
    if isinstance(body, dict):
        nested = body.get("error")
        if isinstance(nested, dict):
            message = nested.get("message")
            if isinstance(message, str) and message.strip():
                return message
        message = body.get("message")
        if isinstance(message, str) and message.strip():
            return message
    message = str(error)
    return message


def _rate_limit_error_context(task_name: str, error: RateLimitError) -> dict[str, object]:
    headers = _response_headers(error)
    context: dict[str, object] = {
        "task_name": task_name,
        "status_code": getattr(error, "status_code", None),
        "provider_message": _provider_error_message(error),
        "response_headers": headers,
    }
    retry_after = _header_value(headers, "retry-after")
    if retry_after is not None:
        context["retry_after"] = retry_after
    reset_requests = _header_value(headers, "x-ratelimit-reset-requests")
    if reset_requests is not None:
        context["ratelimit_reset_requests"] = reset_requests
    reset_tokens = _header_value(headers, "x-ratelimit-reset-tokens")
    if reset_tokens is not None:
        context["ratelimit_reset_tokens"] = reset_tokens
    remaining_requests = _header_value(headers, "x-ratelimit-remaining-requests")
    if remaining_requests is not None:
        context["ratelimit_remaining_requests"] = remaining_requests
    remaining_tokens = _header_value(headers, "x-ratelimit-remaining-tokens")
    if remaining_tokens is not None:
        context["ratelimit_remaining_tokens"] = remaining_tokens
    request_id = _header_value(headers, "x-request-id")
    if request_id is not None:
        context["request_id"] = request_id
    return context


def _response_headers(error: APIStatusError | RateLimitError) -> dict[str, str]:
    response = getattr(error, "response", None)
    raw_headers = getattr(response, "headers", None)
    if raw_headers is None:
        return {}
    try:
        items = list(raw_headers.items())
    except (TypeError, AttributeError):
        return {}
    headers: dict[str, str] = {}
    for key, value in items:
        if not isinstance(key, str):
            continue
        headers[key.lower()] = value if isinstance(value, str) else str(value)
    return headers


def _header_value(headers: dict[str, str], name: str) -> str | None:
    value = headers.get(name.lower())
    if value is None or not value.strip():
        return None
    return value.strip()
