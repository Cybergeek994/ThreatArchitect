"""Tests for the GitHub Copilot SDK agent client and provider strategy."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pydantic import SecretStr
from threatmodeler.config.settings import Settings
from threatmodeler.contracts import AgentRequest, AttachmentContent, SourceReference, SourceType
from threatmodeler.contracts.integration import AgentResponse, AttachmentKind
from threatmodeler.contracts.prompts import PromptMessage, PromptRole
from threatmodeler.errors import AgentProviderError, ConfigurationError
from threatmodeler.infrastructure.agents.copilot_client import (
    CopilotSdkAgentClient,
    _AsyncEventLoopRunner,
    _build_permission_reject,
    _resolve_copilot_model_name,
    create_copilot_sdk_client,
)
from threatmodeler.infrastructure.agents.copilot_provider import CopilotAgentProvider
from threatmodeler.infrastructure.agents.provider_factory import AgentProviderFactory
from threatmodeler.ports.agent_client import AgentClient
from threatmodeler.shared.constants import AgentProviderName, EnvironmentVariable


@pytest.fixture
def agent_request() -> AgentRequest:
    """Create a schema-bound request with prompt messages."""
    return AgentRequest(
        task_name="extract_canonical_system_model",
        instructions="SYSTEM MESSAGE:\nSystem rules.\n\nUSER MESSAGE:\nUser payload.",
        input_payload={"title": "Payments"},
        expected_schema_name="CanonicalSystemModel",
        messages=[
            PromptMessage(role=PromptRole.SYSTEM, content="System rules."),
            PromptMessage(role=PromptRole.USER, content="User payload."),
        ],
        temperature=0.0,
        max_output_tokens=500,
    )


@pytest.fixture
def text_attachment() -> AttachmentContent:
    """Create a validated text attachment."""
    content = b'{"diagram": "auth-flow"}'
    encoded = base64.b64encode(content).decode("ascii")
    return AttachmentContent(
        attachment_id="attachment:notes.json",
        filename="notes.json",
        media_type="application/json",
        kind=AttachmentKind.DOCUMENT,
        content_base64=encoded,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        source_reference=SourceReference(
            source_type=SourceType.CONFLUENCE_ATTACHMENT,
            source_id="notes.json",
            location="file:///notes.json",
            excerpt="JSON notes",
        ),
    )


@pytest.fixture
def image_attachment() -> AttachmentContent:
    """Create a validated image attachment."""
    content = b"fake-image-bytes"
    encoded = base64.b64encode(content).decode("ascii")
    return AttachmentContent(
        attachment_id="attachment:diagram.png",
        filename="diagram.png",
        media_type="image/png",
        kind=AttachmentKind.IMAGE,
        content_base64=encoded,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        source_reference=SourceReference(
            source_type=SourceType.CONFLUENCE_ATTACHMENT,
            source_id="diagram.png",
            location="file:///diagram.png",
            excerpt="Diagram attachment",
        ),
    )


@pytest.fixture
def binary_attachment() -> AttachmentContent:
    """Create a validated non-text binary attachment."""
    content = b"%PDF-binary"
    encoded = base64.b64encode(content).decode("ascii")
    return AttachmentContent(
        attachment_id="attachment:spec.pdf",
        filename="spec.pdf",
        media_type="application/pdf",
        kind=AttachmentKind.DOCUMENT,
        content_base64=encoded,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        source_reference=SourceReference(
            source_type=SourceType.CONFLUENCE_ATTACHMENT,
            source_id="spec.pdf",
            location="file:///spec.pdf",
            excerpt="PDF attachment",
        ),
    )


@pytest.fixture
def session_factory() -> Callable[..., AsyncMock]:
    """Return a factory for mocked async Copilot sessions."""

    def create(*, content: object = '{"ok": true}') -> AsyncMock:
        session = AsyncMock()
        session.send_and_wait = AsyncMock(
            return_value=SimpleNamespace(data=SimpleNamespace(content=content))
        )
        session.close = AsyncMock(return_value=None)
        return session

    return create


@pytest.fixture
def client_factory(
    session_factory: Callable[..., AsyncMock],
) -> Callable[..., tuple[AsyncMock, AsyncMock]]:
    """Return a factory for mocked async Copilot clients and sessions."""

    def create(*, content: object = '{"ok": true}') -> tuple[AsyncMock, AsyncMock]:
        session = session_factory(content=content)
        client = AsyncMock()
        client.start = AsyncMock(return_value=None)
        client.create_session = AsyncMock(return_value=session)
        return client, session

    return create


@pytest.fixture
def sync_loop_runner() -> _AsyncEventLoopRunner:
    """Use a real loop runner so async mocks execute under asyncio."""
    return _AsyncEventLoopRunner()


class TestCopilotSdkAgentClientPositive:
    """Verify supported Copilot client inputs and successful behavior."""

    def test_client_returns_parsed_json_payload(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        payload = {"application": {"id": "application", "name": "Payments"}}
        sdk_client, session = client_factory(content=json.dumps(payload))
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="gpt-5",
            request_timeout_seconds=120.0,
            loop_runner=sync_loop_runner,
        )

        response = client.complete(agent_request)

        assert response.output_payload == payload
        assert response.provider_name == AgentProviderName.GITHUB_COPILOT
        assert response.model_name == "gpt-5"
        assert response.raw_response == json.dumps(payload)
        sdk_client.start.assert_awaited_once()
        session.close.assert_awaited_once()

    def test_client_strips_markdown_fenced_json(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        payload = {"status": "ok"}
        sdk_client, _session = client_factory(content=f"```json\n{json.dumps(payload)}\n```")
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        response = client.complete(agent_request)

        assert response.output_payload == payload

    def test_existing_started_client_skips_start(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        sdk_client, _session = client_factory()
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )
        client.complete(agent_request)
        client.complete(agent_request)

        assert sdk_client.start.await_count == 1
        assert sdk_client.create_session.await_count == 2

    def test_prompt_uses_instructions_once_and_includes_text_attachment(
        self,
        agent_request: AgentRequest,
        text_attachment: AttachmentContent,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        sdk_client, session = client_factory()
        request = agent_request.model_copy(update={"attachments": [text_attachment]})
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=90.0,
            loop_runner=sync_loop_runner,
        )

        client.complete(request)

        kwargs = sdk_client.create_session.call_args.kwargs
        assert kwargs["system_message"] == {
            "mode": "append",
            "content": agent_request.instructions,
        }
        prompt = session.send_and_wait.call_args.args[0]
        assert "SYSTEM MESSAGE:" not in prompt
        assert "USER MESSAGE:" not in prompt
        assert "ATTACHMENT notes.json" in prompt
        assert '{"diagram": "auth-flow"}' in prompt
        assert "CanonicalSystemModel" in prompt
        assert session.send_and_wait.call_args.kwargs["timeout"] == 90.0

    def test_image_attachment_is_sent_as_blob_and_binary_is_manifested(
        self,
        agent_request: AgentRequest,
        image_attachment: AttachmentContent,
        binary_attachment: AttachmentContent,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        sdk_client, session = client_factory()
        request = agent_request.model_copy(
            update={"attachments": [image_attachment, binary_attachment]}
        )
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        client.complete(request)

        prompt = session.send_and_wait.call_args.args[0]
        assert "diagram.png" in prompt
        assert "image blob attachment" in prompt
        assert "ATTACHMENT spec.pdf" in prompt
        assert "request manifest" in prompt
        attachments = session.send_and_wait.call_args.kwargs["attachments"]
        assert attachments == [
            {
                "type": "blob",
                "data": image_attachment.content_base64,
                "mimeType": "image/png",
                "displayName": "diagram.png",
            }
        ]

    def test_create_session_uses_append_system_message_and_deny_handler(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        sdk_client, _session = client_factory()
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        client.complete(agent_request)

        kwargs = sdk_client.create_session.call_args.kwargs
        assert kwargs["model"] == "auto"
        assert kwargs["system_message"] == {
            "mode": "append",
            "content": agent_request.instructions,
        }
        deny_result = kwargs["on_permission_request"](Mock(), {})
        assert deny_result.kind == "reject"
        assert "disabled" in deny_result.feedback.lower()

    def test_create_copilot_sdk_client_passes_token_and_disables_logged_in_user(
        self,
    ) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="gpt-5",
            github_token=SecretStr("gho_test_token"),
            agent_request_timeout_seconds=180.0,
        )
        constructed: dict[str, object] = {}

        class FakeCopilotClient:
            def __init__(self, **kwargs: object) -> None:
                constructed.update(kwargs)

        with patch(
            "threatmodeler.infrastructure.agents.copilot_client._load_copilot_client_class",
            return_value=FakeCopilotClient,
        ):
            client = create_copilot_sdk_client(settings)
            created = client._create_client()

        assert isinstance(created, FakeCopilotClient)
        assert constructed["github_token"] == "gho_test_token"
        assert constructed["use_logged_in_user"] is False
        assert client._model_name == "gpt-5"
        assert client._request_timeout_seconds == 180.0

    def test_create_copilot_sdk_client_uses_default_client_without_token(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="auto",
        )
        call_kwargs: list[dict[str, object]] = []

        class FakeCopilotClient:
            def __init__(self, **kwargs: object) -> None:
                call_kwargs.append(kwargs)

        with patch(
            "threatmodeler.infrastructure.agents.copilot_client._load_copilot_client_class",
            return_value=FakeCopilotClient,
        ):
            client = create_copilot_sdk_client(settings)
            client._create_client()

        assert call_kwargs == [{}]

    def test_create_copilot_sdk_client_maps_placeholder_model_to_auto(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="agent-model",
        )

        with patch(
            "threatmodeler.infrastructure.agents.copilot_client._load_copilot_client_class",
            return_value=Mock,
        ):
            client = create_copilot_sdk_client(settings)

        assert client._model_name == "auto"

    def test_resolve_copilot_model_name_keeps_explicit_models(self) -> None:
        assert _resolve_copilot_model_name("gpt-5") == "gpt-5"
        assert _resolve_copilot_model_name("agent-model") == "auto"

    def test_session_close_falls_back_to_aexit(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = SimpleNamespace(
            send_and_wait=AsyncMock(
                return_value=SimpleNamespace(data=SimpleNamespace(content='{"ok": true}'))
            ),
            __aexit__=AsyncMock(return_value=None),
        )
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        client.complete(agent_request)

        session.__aexit__.assert_awaited_once_with(None, None, None)

    def test_session_sync_close_is_accepted(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = Mock()
        session.send_and_wait = AsyncMock(
            return_value=SimpleNamespace(data=SimpleNamespace(content='{"ok": true}'))
        )
        session.close = Mock(return_value=None)
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        client.complete(agent_request)

        session.close.assert_called_once()

    def test_session_sync_aexit_is_accepted(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        aexit = Mock(return_value=None)
        session = SimpleNamespace(
            send_and_wait=AsyncMock(
                return_value=SimpleNamespace(data=SimpleNamespace(content='{"ok": true}'))
            ),
            __aexit__=aexit,
        )
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        client.complete(agent_request)

        aexit.assert_called_once_with(None, None, None)

    def test_session_without_close_or_aexit_still_completes(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = SimpleNamespace(
            send_and_wait=AsyncMock(
                return_value=SimpleNamespace(data=SimpleNamespace(content='{"ok": true}'))
            )
        )
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        response = client.complete(agent_request)

        assert response.output_payload == {"ok": True}

    def test_event_loop_runner_raises_when_startup_times_out(self) -> None:
        runner = _AsyncEventLoopRunner()
        runner._ready = Mock()
        runner._ready.wait.return_value = False
        runner._thread = None

        with (
            patch("threading.Thread") as thread_cls,
            pytest.raises(AgentProviderError) as captured,
        ):
            thread_cls.return_value.start = Mock()
            runner._ensure_started()

        assert captured.value.error_code == "AGENT_PROVIDER_REQUEST_FAILED"

    def test_load_copilot_client_class_returns_installed_sdk_class(self) -> None:
        from threatmodeler.infrastructure.agents.copilot_client import (
            _load_copilot_client_class,
        )

        client_cls = _load_copilot_client_class()

        assert client_cls.__name__ == "CopilotClient"

    def test_async_event_loop_runner_executes_coroutine(self) -> None:
        runner = _AsyncEventLoopRunner()

        async def sample() -> str:
            await asyncio.sleep(0)
            return "done"

        assert runner.run(sample()) == "done"
        assert runner.run(sample()) == "done"


class TestCopilotSdkAgentClientNegative:
    """Verify Copilot client rejects invalid responses and runtime failures."""

    @pytest.mark.parametrize(
        ("content", "error_code"),
        [
            ("", "AGENT_PROVIDER_EMPTY_RESPONSE"),
            (None, "AGENT_PROVIDER_EMPTY_RESPONSE"),
            ("not-json", "AGENT_PROVIDER_INVALID_JSON"),
            ("[1, 2]", "AGENT_PROVIDER_JSON_OBJECT_REQUIRED"),
            ("42", "AGENT_PROVIDER_JSON_OBJECT_REQUIRED"),
        ],
    )

    def test_invalid_completion_content_raises_provider_error(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
        content: object,
        error_code: str,
    ) -> None:
        sdk_client, session = client_factory(content=content)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == error_code
        assert captured.value.retryable is False
        session.close.assert_awaited_once()

    def test_sdk_exception_is_mapped_to_retryable_provider_error(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        sdk_client, session = client_factory()
        session.send_and_wait.side_effect = RuntimeError("copilot down")
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_REQUEST_FAILED"
        assert captured.value.retryable is True
        session.close.assert_awaited_once()

    def test_non_string_response_content_is_treated_as_empty(
        self,
        agent_request: AgentRequest,
        client_factory: Callable[..., tuple[AsyncMock, AsyncMock]],
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        sdk_client, _session = client_factory(content={"not": "a-string"})
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_EMPTY_RESPONSE"

    def test_missing_response_data_is_treated_as_empty(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = AsyncMock()
        session.send_and_wait = AsyncMock(return_value=SimpleNamespace(data=None))
        session.close = AsyncMock(return_value=None)
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_EMPTY_RESPONSE"

    def test_none_send_and_wait_response_is_treated_as_empty(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = AsyncMock()
        session.send_and_wait = AsyncMock(return_value=None)
        session.close = AsyncMock(return_value=None)
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_EMPTY_RESPONSE"

    def test_deny_permission_handler_returns_reject_decision(self) -> None:
        decision = cast(Any, _build_permission_reject())

        assert decision.kind == "reject"
        assert "disabled" in decision.feedback.lower()

    def test_deny_permission_handler_raises_when_decision_type_missing(self) -> None:
        with patch(
            "threatmodeler.infrastructure.agents.copilot_client._build_permission_reject",
            side_effect=AgentProviderError(
                "missing",
                error_code="AGENT_PROVIDER_REQUEST_FAILED",
                retryable=False,
            ),
        ):
            client = CopilotSdkAgentClient(
                lambda: Mock(),
                model_name="auto",
                request_timeout_seconds=60.0,
            )
            with pytest.raises(AgentProviderError) as captured:
                client._deny_permission_request(Mock(), {})

        assert captured.value.error_code == "AGENT_PROVIDER_REQUEST_FAILED"


class TestCopilotAgentProviderPositive:
    """Verify the Copilot strategy stamps the provider name."""

    def test_provider_stamps_github_copilot_name(
        self,
        agent_request: AgentRequest,
    ) -> None:
        low_level = Mock(spec=AgentClient)
        low_level.complete.return_value = AgentResponse(
            output_payload={"ok": True},
            confidence=0.9,
            provider_name="low_level",
            model_name="auto",
        )
        provider = CopilotAgentProvider(low_level)

        response = provider.complete(agent_request)

        assert response.provider_name == AgentProviderName.GITHUB_COPILOT
        low_level.complete.assert_called_once_with(agent_request)


class TestCopilotAgentProviderNegative:
    """Verify Copilot strategy error mapping."""

    def test_provider_passthrough_agent_provider_error(
        self,
        agent_request: AgentRequest,
    ) -> None:
        low_level = Mock(spec=AgentClient)
        low_level.complete.side_effect = AgentProviderError(
            "boom",
            error_code="AGENT_PROVIDER_INVALID_JSON",
            retryable=False,
        )
        provider = CopilotAgentProvider(low_level)

        with pytest.raises(AgentProviderError) as captured:
            provider.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_INVALID_JSON"

    def test_provider_wraps_unexpected_exception(
        self,
        agent_request: AgentRequest,
    ) -> None:
        low_level = Mock(spec=AgentClient)
        low_level.complete.side_effect = RuntimeError("unexpected")
        provider = CopilotAgentProvider(low_level)

        with pytest.raises(AgentProviderError) as captured:
            provider.complete(agent_request)

        assert captured.value.error_code == "GITHUB_COPILOT_REQUEST_FAILED"
        assert captured.value.retryable is True


class TestAgentProviderFactoryCopilotPositive:
    """Verify factory selection of the Copilot strategy."""

    @pytest.mark.parametrize(
        "provider_name",
        [AgentProviderName.GITHUB_COPILOT, AgentProviderName.COPILOT],
    )

    def test_factory_selects_copilot_without_openai_key(
        self,
        provider_name: str,
    ) -> None:
        settings = Settings(agent_provider_name=provider_name, agent_model_name="auto")
        fake_client = Mock(spec=AgentClient)

        with patch(
            "threatmodeler.infrastructure.agents.provider_factory.create_copilot_sdk_client",
            return_value=fake_client,
        ) as create_client:
            provider = AgentProviderFactory(settings).create()

        assert isinstance(provider, CopilotAgentProvider)
        create_client.assert_called_once_with(settings)


class TestAgentProviderFactoryCopilotNegative:
    """Verify Copilot factory failure modes."""

    def test_factory_raises_when_copilot_sdk_missing(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="auto",
        )

        with (
            patch(
                "threatmodeler.infrastructure.agents.provider_factory.create_copilot_sdk_client",
                side_effect=ConfigurationError(
                    "missing",
                    error_code="GITHUB_COPILOT_SDK_MISSING",
                    retryable=False,
                ),
            ),
            pytest.raises(ConfigurationError) as captured,
        ):
            AgentProviderFactory(settings).create()

        assert captured.value.error_code == "GITHUB_COPILOT_SDK_MISSING"

    def test_create_copilot_sdk_client_raises_when_import_fails(self) -> None:
        settings = Settings(
            agent_provider_name=AgentProviderName.GITHUB_COPILOT,
            agent_model_name="auto",
        )

        with (
            patch(
                "threatmodeler.infrastructure.agents.copilot_client._load_copilot_client_class",
                side_effect=ConfigurationError(
                    "missing",
                    error_code="GITHUB_COPILOT_SDK_MISSING",
                    retryable=False,
                ),
            ),
            pytest.raises(ConfigurationError) as captured,
        ):
            create_copilot_sdk_client(settings)

        assert captured.value.error_code == "GITHUB_COPILOT_SDK_MISSING"

    def test_load_copilot_client_class_raises_when_package_missing(self) -> None:
        from threatmodeler.infrastructure.agents import copilot_client as module

        with (
            patch.object(module, "_CopilotClientClass", None),
            pytest.raises(ConfigurationError) as captured,
        ):
            module._load_copilot_client_class()

        assert captured.value.error_code == "GITHUB_COPILOT_SDK_MISSING"

    def test_build_permission_reject_falls_back_to_rpc_module(self) -> None:
        from threatmodeler.infrastructure.agents import copilot_client as module

        reject_cls = Mock(return_value=SimpleNamespace(kind="reject", feedback="denied"))

        with patch.object(module, "_PermissionDecisionReject", reject_cls):
            decision = cast(Any, module._build_permission_reject())

        assert decision.kind == "reject"
        reject_cls.assert_called_once()

    def test_build_permission_reject_raises_when_sdk_types_missing(self) -> None:
        from threatmodeler.infrastructure.agents import copilot_client as module

        with (
            patch.object(module, "_PermissionDecisionReject", None),
            pytest.raises(AgentProviderError) as captured,
        ):
            module._build_permission_reject()

        assert captured.value.error_code == "AGENT_PROVIDER_REQUEST_FAILED"


class TestCopilotSettingsAndConstantsPositive:
    """Verify Copilot settings and constant identifiers."""

    def test_github_token_loads_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THREATMODELER_GITHUB_TOKEN", "gho_from_env")
        monkeypatch.setenv("THREATMODELER_AGENT_PROVIDER_NAME", "github_copilot")
        monkeypatch.setenv("THREATMODELER_AGENT_REQUEST_TIMEOUT_SECONDS", "240")

        settings = Settings()

        assert settings.github_token is not None
        assert settings.github_token.get_secret_value() == "gho_from_env"
        assert settings.agent_provider_name == "github_copilot"
        assert settings.agent_request_timeout_seconds == 240.0
        assert EnvironmentVariable.GITHUB_TOKEN.value == "THREATMODELER_GITHUB_TOKEN"


class TestCopilotSdkAgentClientToolSession:
    """Verify Copilot SDK tool-session completion paths."""

    @pytest.fixture
    def agent_request(self) -> AgentRequest:
        return AgentRequest(
            task_name="extract_canonical_system_model",
            instructions="Build with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="CanonicalSystemModel",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )

    @pytest.fixture
    def sync_loop_runner(self) -> _AsyncEventLoopRunner:
        return _AsyncEventLoopRunner()

    def test_model_name_property_returns_configured_value(self) -> None:
        client = CopilotSdkAgentClient(lambda: Mock(), model_name="copilot-model", request_timeout_seconds=30.0)
        assert client.model_name == "copilot-model"

    def test_complete_with_tools_returns_assistant_text(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = AsyncMock()
        session.send_and_wait = AsyncMock(
            return_value=SimpleNamespace(data=SimpleNamespace(content="tool session finished"))
        )
        session.close = AsyncMock(return_value=None)
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        result = client.complete_with_tools(
            agent_request,
            tools=[Mock()],
            available_tools=["add_item"],
        )

        assert result == "tool session finished"
        assert sdk_client.create_session.call_args.kwargs["available_tools"] == ["add_item"]

    def test_complete_with_tools_reraises_agent_provider_error(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        client = CopilotSdkAgentClient(
            lambda: Mock(),
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with patch.object(
            client,
            "_complete_with_tools_async",
            side_effect=AgentProviderError("fail", error_code="AGENT_PROVIDER_FAILED", retryable=True),
        ):
            with pytest.raises(AgentProviderError) as captured:
                client.complete_with_tools(agent_request, tools=[], available_tools=[])

        assert captured.value.error_code == "AGENT_PROVIDER_FAILED"

    def test_complete_with_tools_wraps_unexpected_errors(
        self,
        agent_request: AgentRequest,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        client = CopilotSdkAgentClient(
            lambda: Mock(),
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )

        with patch.object(
            client,
            "_complete_with_tools_async",
            side_effect=RuntimeError("copilot crashed"),
        ):
            with pytest.raises(AgentProviderError) as captured:
                client.complete_with_tools(agent_request, tools=[], available_tools=[])

        assert captured.value.error_code == "AGENT_PROVIDER_REQUEST_FAILED"
        assert captured.value.retryable is True


class TestCopilotSdkAgentClientLifecycle:
    """Verify SDK client lifecycle edge cases."""

    def test_copilot_client_skips_restart_when_already_started(
        self,
        sync_loop_runner: _AsyncEventLoopRunner,
    ) -> None:
        session = AsyncMock()
        session.send_and_wait = AsyncMock(
            return_value=SimpleNamespace(data=SimpleNamespace(content="done"))
        )
        session.close = AsyncMock(return_value=None)
        sdk_client = AsyncMock()
        sdk_client.start = AsyncMock(return_value=None)
        sdk_client.create_session = AsyncMock(return_value=session)
        client = CopilotSdkAgentClient(
            lambda: sdk_client,
            model_name="auto",
            request_timeout_seconds=60.0,
            loop_runner=sync_loop_runner,
        )
        request = AgentRequest(
            task_name="demo",
            instructions="Use tools.",
            input_payload={},
            expected_schema_name="Demo",
            messages=[PromptMessage(role=PromptRole.USER, content="hi")],
            temperature=0.0,
            max_output_tokens=100,
        )
        client.complete_with_tools(request, tools=[], available_tools=[])
        client.complete_with_tools(request, tools=[], available_tools=[])
        assert sdk_client.start.await_count == 1
