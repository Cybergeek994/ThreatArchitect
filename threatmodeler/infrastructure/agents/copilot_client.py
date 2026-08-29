"""GitHub Copilot SDK-backed agent client for schema-bound completions.

Lifecycle follows the official Copilot SDK pattern: start the client once on a
dedicated event loop, create a session per request, call ``send_and_wait``, then
close the session. See:

- https://docs.github.com/en/copilot/how-tos/copilot-sdk/getting-started
- https://docs.github.com/en/copilot/how-tos/copilot-sdk/features/image-input
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Protocol, cast

from threatmodeler.config.settings import Settings
from threatmodeler.contracts.integration import AgentRequest, AgentResponse, AttachmentContent
from threatmodeler.errors.application import AgentProviderError, ConfigurationError
from threatmodeler.infrastructure.agents.vision_message_builder import (
    is_text_attachment,
    is_vision_image,
)
from threatmodeler.shared.constants import AgentProviderName, CopilotModelName

try:
    from copilot import CopilotClient as _CopilotClientClass
except ImportError:  # pragma: no cover
    _CopilotClientClass = None

try:
    from copilot.generated.rpc import PermissionDecisionReject as _PermissionDecisionReject
except ImportError:  # pragma: no cover
    try:
        from copilot.rpc import PermissionDecisionReject as _PermissionDecisionReject
    except ImportError:  # pragma: no cover
        _PermissionDecisionReject = None


class _CopilotSessionPort(Protocol):
    """Minimal async session surface used by the Copilot agent client."""

    def send_and_wait(self, prompt: str, **kwargs: object) -> Awaitable[object]:
        """Send a prompt and wait for the assistant response."""
        ...


class _CopilotClientPort(Protocol):
    """Minimal async client surface used by the Copilot agent client."""

    def start(self) -> Awaitable[None]:
        """Start the Copilot runtime connection."""
        ...

    def create_session(self, **kwargs: object) -> Awaitable[_CopilotSessionPort]:
        """Create a conversation session."""
        ...


CreateCopilotClient = Callable[[], _CopilotClientPort]

_MARKDOWN_JSON_FENCE = re.compile(
    r"^```(?:json)?\s*(.*?)\s*```$",
    re.DOTALL | re.IGNORECASE,
)


class _AsyncEventLoopRunner:
    """Run awaitables on one long-lived event loop (official SDK is async-native)."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._lock = threading.Lock()

    def run[T](self, coroutine: Coroutine[Any, Any, T]) -> T:
        """Schedule ``coroutine`` on the shared loop and wait for its result."""
        self._ensure_started()
        assert self._loop is not None
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        return future.result()

    def _ensure_started(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return

            def run_loop() -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                self._ready.set()
                loop.run_forever()

            self._ready.clear()
            self._thread = threading.Thread(
                target=run_loop,
                name="copilot-sdk-event-loop",
                daemon=True,
            )
            self._thread.start()
        if not self._ready.wait(timeout=30):
            raise AgentProviderError(
                "Failed to start Copilot SDK event loop",
                error_code="AGENT_PROVIDER_REQUEST_FAILED",
                retryable=True,
            )


class CopilotSdkAgentClient:
    """Execute schema-bound agent requests through an injected async Copilot client."""

    def __init__(
        self,
        create_client: CreateCopilotClient,
        *,
        model_name: str,
        request_timeout_seconds: float,
        loop_runner: _AsyncEventLoopRunner | None = None,
    ) -> None:
        self._create_client = create_client
        self._model_name = model_name
        self._request_timeout_seconds = request_timeout_seconds
        self._loop_runner = loop_runner or _AsyncEventLoopRunner()
        self._client: _CopilotClientPort | None = None
        self._started = False

    @property
    def model_name(self) -> str:
        """Return the configured Copilot model name."""
        return self._model_name

    def complete(self, request: AgentRequest) -> AgentResponse:
        """Complete one schema-bound request through a fresh Copilot session.

        Args:
            request: Provider-neutral request containing prompt messages and attachments.

        Returns:
            Provider response with a parsed JSON object payload.

        Raises:
            AgentProviderError: If the Copilot runtime rejects or fails the request.
        """
        try:
            return self._loop_runner.run(self._complete_async(request))
        except AgentProviderError:
            raise
        except Exception as error:
            raise AgentProviderError(
                "Agent provider request failed",
                error_code="AGENT_PROVIDER_REQUEST_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error

    def complete_with_tools(
        self,
        request: AgentRequest,
        *,
        tools: list[object],
        available_tools: list[str],
    ) -> str:
        """Run a Copilot session with host-defined tools and return assistant text.

        Args:
            request: Provider-neutral request.
            tools: Copilot SDK tool objects.
            available_tools: Allowlist of host tool names that hides built-in tools.

        Returns:
            Assistant message text from the finished session.

        Raises:
            AgentProviderError: If the Copilot runtime rejects or fails the request.
        """
        try:
            return self._loop_runner.run(
                self._complete_with_tools_async(request, tools, available_tools)
            )
        except AgentProviderError:
            raise
        except Exception as error:
            raise AgentProviderError(
                "Agent provider request failed",
                error_code="AGENT_PROVIDER_REQUEST_FAILED",
                retryable=True,
                context={"task_name": request.task_name},
            ) from error

    async def _complete_with_tools_async(
        self,
        request: AgentRequest,
        tools: list[object],
        available_tools: list[str],
    ) -> str:
        client = self._ensure_client()
        if not self._started:
            await client.start()
            self._started = True
        session = await client.create_session(
            on_permission_request=self._deny_permission_request,
            model=self._model_name,
            system_message={"mode": "append", "content": request.instructions},
            tools=tools,
            available_tools=available_tools,
        )
        try:
            sections = self._attachment_sections(request.attachments)
            sections.append(
                "Construct the artifact by calling the provided tools. "
                "Do not emit the full JSON object as a single message."
            )
            prompt = "\n\n".join(section for section in sections if section)
            attachments = self._blob_attachments(request.attachments)
            response = await session.send_and_wait(
                prompt,
                attachments=attachments or None,
                timeout=self._request_timeout_seconds,
            )
            return self._response_content(response)
        finally:
            await self._close_session(session)

    async def _complete_async(self, request: AgentRequest) -> AgentResponse:
        client = self._ensure_client()
        if not self._started:
            await client.start()
            self._started = True

        session = await client.create_session(
            on_permission_request=self._deny_permission_request,
            model=self._model_name,
            system_message={"mode": "append", "content": request.instructions},
        )
        try:
            prompt = self._build_prompt(request)
            attachments = self._blob_attachments(request.attachments)
            response = await session.send_and_wait(
                prompt,
                attachments=attachments or None,
                timeout=self._request_timeout_seconds,
            )
            message_content = self._response_content(response)
            output_payload = self._parse_json_object(message_content, request.task_name)
            return AgentResponse(
                output_payload=output_payload,
                confidence=0.75,
                raw_response=message_content,
                provider_name=AgentProviderName.GITHUB_COPILOT,
                model_name=self._model_name,
            )
        finally:
            await self._close_session(session)

    def _ensure_client(self) -> _CopilotClientPort:
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _build_prompt(self, request: AgentRequest) -> str:
        """Build the user prompt without re-emitting ``request.instructions``.

        Authoritative system/developer/user text is supplied once via
        ``create_session(..., system_message=...)`` per the SDK session config.
        """
        sections = self._attachment_sections(request.attachments)
        sections.append(
            "Respond with a single JSON object that matches the "
            f"{request.expected_schema_name} schema. Do not wrap the object in markdown."
        )
        return "\n\n".join(section for section in sections if section)

    def _attachment_sections(self, attachments: list[AttachmentContent]) -> list[str]:
        sections: list[str] = []
        for attachment in attachments:
            if is_vision_image(attachment.media_type):
                sections.append(
                    f"ATTACHMENT {attachment.filename} ({attachment.media_type}) "
                    "is provided as an image blob attachment."
                )
                continue
            if is_text_attachment(attachment.media_type):
                decoded = attachment.decoded_content().decode("utf-8", errors="replace")
                sections.append(
                    f"ATTACHMENT {attachment.filename} ({attachment.media_type}):\n{decoded}"
                )
                continue
            sections.append(
                f"ATTACHMENT {attachment.filename} ({attachment.media_type}, "
                f"{attachment.size_bytes} bytes) is included in the request manifest."
            )
        return sections

    def _blob_attachments(self, attachments: list[AttachmentContent]) -> list[dict[str, str]]:
        """Map vision-supported raster images to Copilot SDK blob attachments."""
        blobs: list[dict[str, str]] = []
        for attachment in attachments:
            if not is_vision_image(attachment.media_type):
                continue
            blobs.append(
                {
                    "type": "blob",
                    "data": attachment.content_base64,
                    "mimeType": attachment.media_type,
                    "displayName": attachment.filename,
                }
            )
        return blobs

    def _parse_json_object(self, message_content: str, task_name: str) -> dict[str, Any]:
        if not message_content.strip():
            raise AgentProviderError(
                "Agent provider returned an empty completion",
                error_code="AGENT_PROVIDER_EMPTY_RESPONSE",
                retryable=False,
                context={"task_name": task_name},
            )
        candidate = _strip_markdown_fence(message_content.strip())
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError as error:
            raise AgentProviderError(
                "Agent provider returned invalid JSON",
                error_code="AGENT_PROVIDER_INVALID_JSON",
                retryable=False,
                context={"task_name": task_name},
            ) from error
        if not isinstance(parsed, dict):
            raise AgentProviderError(
                "Agent provider JSON output must be an object",
                error_code="AGENT_PROVIDER_JSON_OBJECT_REQUIRED",
                retryable=False,
                context={"task_name": task_name},
            )
        return cast(dict[str, Any], parsed)

    def _response_content(self, response: object) -> str:
        if response is None:
            return ""
        data = getattr(response, "data", None)
        content = getattr(data, "content", None) if data is not None else None
        if content is None:
            return ""
        if not isinstance(content, str):
            return ""
        return content

    def _deny_permission_request(self, request: object, invocation: dict[str, str]) -> object:
        del request, invocation
        return _build_permission_reject()

    async def _close_session(self, session: object) -> None:
        close = getattr(session, "close", None)
        if callable(close):
            result = close()
            if asyncio.iscoroutine(result):
                await cast(Awaitable[None], result)
            return
        aexit = getattr(session, "__aexit__", None)
        if callable(aexit):
            result = aexit(None, None, None)
            if asyncio.iscoroutine(result):
                await cast(Awaitable[None], result)


def create_copilot_sdk_client(settings: Settings) -> CopilotSdkAgentClient:
    """Create a Copilot SDK client from immutable settings.

    Args:
        settings: Application settings containing optional GitHub token and model name.

    Returns:
        Copilot agent client bound to the configured model.

    Raises:
        ConfigurationError: If the Copilot SDK package is not installed.
    """
    client_cls = _load_copilot_client_class()

    def create_client() -> _CopilotClientPort:
        if settings.github_token is not None:
            return cast(
                _CopilotClientPort,
                client_cls(
                    github_token=settings.github_token.get_secret_value(),
                    use_logged_in_user=False,
                ),
            )
        return cast(_CopilotClientPort, client_cls())

    return CopilotSdkAgentClient(
        create_client,
        model_name=_resolve_copilot_model_name(settings.agent_model_name),
        request_timeout_seconds=float(settings.agent_request_timeout_seconds),
    )


def _resolve_copilot_model_name(configured_model: str) -> str:
    if configured_model == CopilotModelName.PLACEHOLDER:
        return CopilotModelName.AUTO
    return configured_model


def _load_copilot_client_class() -> type[Any]:
    if _CopilotClientClass is None:
        raise ConfigurationError(
            "GitHub Copilot SDK is not installed; install github-copilot-sdk",
            error_code="GITHUB_COPILOT_SDK_MISSING",
            retryable=False,
            context={"agent_provider_name": AgentProviderName.GITHUB_COPILOT},
        )
    return _CopilotClientClass


def _build_permission_reject() -> object:
    if _PermissionDecisionReject is None:
        raise AgentProviderError(
            "Copilot SDK permission decision type is unavailable",
            error_code="AGENT_PROVIDER_REQUEST_FAILED",
            retryable=False,
        )
    return _PermissionDecisionReject(
        feedback="Tool execution is disabled for threat-model artifact generation."
    )


def _strip_markdown_fence(content: str) -> str:
    match = _MARKDOWN_JSON_FENCE.match(content)
    if match is None:
        return content
    return match.group(1).strip()
