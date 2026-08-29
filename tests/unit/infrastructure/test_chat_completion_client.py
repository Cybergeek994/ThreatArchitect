"""Tests for SDK-backed chat completion agent clients."""

import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from openai import APIConnectionError, APIStatusError, AuthenticationError, RateLimitError
from pydantic import AnyHttpUrl, SecretStr
from threatmodeler.config.settings import Settings
from threatmodeler.contracts import AgentRequest, AttachmentContent, SourceReference, SourceType
from threatmodeler.contracts.integration import AttachmentKind
from threatmodeler.contracts.prompts import PromptMessage, PromptRole
from threatmodeler.errors import AgentProviderError
from threatmodeler.infrastructure.agents.chat_completion_client import (
    ChatCompletionAgentClient,
    _provider_error_message,
    _raw_preview,
    _response_headers,
)
from threatmodeler.infrastructure.agents.client_factory import (
    create_azure_openai_sdk_client,
    create_openai_sdk_client,
)
from threatmodeler.infrastructure.agents.client_factory import SdkAgentClientFactory


@pytest.fixture
def agent_request() -> AgentRequest:
    """Create a schema-bound request with prompt messages."""
    return AgentRequest(
        task_name="extract_canonical_system_model",
        instructions="Extract architecture.",
        input_payload={"title": "Payments"},
        expected_schema_name="CanonicalSystemModel",
        messages=[
            PromptMessage(role=PromptRole.SYSTEM, content="System rules."),
            PromptMessage(role=PromptRole.DEVELOPER, content="Developer schema."),
            PromptMessage(role=PromptRole.USER, content="User payload."),
        ],
        temperature=0.0,
        max_output_tokens=500,
    )


@pytest.fixture
def image_attachment() -> AttachmentContent:
    """Create a validated image attachment."""
    content = b"fake-image-bytes"
    import base64
    import hashlib

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


class TestChatCompletionClientPositive:
    """Verify supported inputs and successful behavior."""

    def test_client_returns_parsed_json_payload(
        self,
        agent_request: AgentRequest,
    ) -> None:
        payload = {"application": {"id": "application", "name": "Payments"}}
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))]
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-4o",
        )

        response = client.complete(agent_request)

        assert response.output_payload == payload
        assert response.provider_name == "openai"
        assert response.model_name == "gpt-4o"
        create_completion.assert_called_once()
        call_kwargs = create_completion.call_args.kwargs
        assert call_kwargs["model"] == "gpt-4o"
        assert call_kwargs["response_format"] == {"type": "json_object"}
        assert call_kwargs["max_tokens"] == 500
        assert "max_completion_tokens" not in call_kwargs
        assert len(call_kwargs["messages"]) == 3

    def test_client_uses_max_completion_tokens_for_gpt_5_models(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-5.5",
        )

        client.complete(agent_request)
        call_kwargs = create_completion.call_args.kwargs
        assert call_kwargs["max_completion_tokens"] == 500
        assert "max_tokens" not in call_kwargs
        assert "temperature" not in call_kwargs

        client.complete_turn(agent_request, messages=[{"role": "user", "content": "hi"}])
        turn_kwargs = create_completion.call_args.kwargs
        assert turn_kwargs["max_completion_tokens"] == 500
        assert "max_tokens" not in turn_kwargs
        assert "temperature" not in turn_kwargs

    def test_client_sets_reasoning_effort_none_for_gpt_56_tool_calls(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-5.6-sol",
        )
        tools = [{"type": "function", "function": {"name": "add_actor", "parameters": {}}}]

        client.complete_turn(
            agent_request,
            messages=[{"role": "user", "content": "hi"}],
            tools=tools,
        )
        turn_kwargs = create_completion.call_args.kwargs
        assert turn_kwargs["reasoning_effort"] == "none"
        assert turn_kwargs["tools"] == tools

        client.complete_turn(agent_request, messages=[{"role": "user", "content": "hi"}])
        plain_kwargs = create_completion.call_args.kwargs
        assert "reasoning_effort" not in plain_kwargs
        assert "tools" not in plain_kwargs

    def test_client_sends_temperature_for_legacy_models(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-4o",
        )

        client.complete(agent_request)
        assert create_completion.call_args.kwargs["temperature"] == 0.0

    def test_client_adds_image_attachments_to_user_message(
        self,
        agent_request: AgentRequest,
        image_attachment: AttachmentContent,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        request = agent_request.model_copy(update={"attachments": [image_attachment]})
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-4o",
        )

        client.complete(request)

        user_message = create_completion.call_args.kwargs["messages"][-1]
        assert user_message["role"] == "user"
        assert isinstance(user_message["content"], list)
        assert user_message["content"][1]["type"] == "image_url"

    def test_client_inlines_svg_as_text_not_image_url(
        self,
        agent_request: AgentRequest,
    ) -> None:
        import base64
        import hashlib

        content = b'<svg xmlns="http://www.w3.org/2000/svg"><text>Payments API</text></svg>'
        encoded = base64.b64encode(content).decode("ascii")
        attachment = AttachmentContent(
            attachment_id="attachment:payments-runtime.svg",
            filename="payments-runtime.svg",
            media_type="image/svg+xml",
            kind=AttachmentKind.IMAGE,
            content_base64=encoded,
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            source_reference=SourceReference(
                source_type=SourceType.CONFLUENCE_ATTACHMENT,
                source_id="payments-runtime.svg",
                location="file:///payments-runtime.svg",
                excerpt="SVG diagram",
            ),
        )
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        request = agent_request.model_copy(update={"attachments": [attachment]})
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-4o",
        )

        client.complete(request)

        user_message = create_completion.call_args.kwargs["messages"][-1]
        assert user_message["content"][1]["type"] == "text"
        assert "Payments API" in user_message["content"][1]["text"]
        assert not any(
            block.get("type") == "image_url"
            for block in user_message["content"]
            if isinstance(block, dict)
        )

    def test_sdk_factory_creates_openai_and_azure_clients(self) -> None:
        settings = Settings(
            agent_provider_name="openai",
            openai_api_key=SecretStr("test-openai-key"),
            agent_model_name="deployment-name",
        )
        factory = SdkAgentClientFactory()

        with patch(
            "threatmodeler.infrastructure.agents.client_factory.OpenAI"
        ) as openai_cls:
            openai_cls.return_value.chat.completions.create = Mock()
            openai_client = factory.create_openai_client(settings)

        assert isinstance(openai_client, ChatCompletionAgentClient)

        azure_settings = Settings(
            agent_provider_name="azure_openai",
            azure_openai_api_key=SecretStr("test-azure-key"),
            azure_openai_endpoint=AnyHttpUrl("https://example.openai.azure.com"),
            agent_model_name="deployment-name",
        )
        with patch("openai.AzureOpenAI") as azure_cls:
            azure_cls.return_value.chat.completions.create = Mock()
            azure_client = factory.create_azure_openai_client(azure_settings)

        assert isinstance(azure_client, ChatCompletionAgentClient)

    def test_create_openai_sdk_client_uses_configured_api_key(self) -> None:
        settings = Settings(
            openai_api_key=SecretStr("direct-key"),
            agent_model_name="gpt-4o",
        )

        with patch(
            "threatmodeler.infrastructure.agents.client_factory.OpenAI"
        ) as openai_cls:
            openai_cls.return_value.chat.completions.create = Mock()
            client = create_openai_sdk_client(settings)

        openai_cls.assert_called_once_with(api_key="direct-key")
        assert isinstance(client, ChatCompletionAgentClient)


class TestChatCompletionClientNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_client_rejects_empty_completion(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=None))]
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-4o",
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_EMPTY_RESPONSE"

    def test_client_rejects_non_object_json(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='["not","object"]'))]
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-4o",
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_JSON_OBJECT_REQUIRED"

    def test_create_openai_sdk_client_requires_api_key(self) -> None:
        with pytest.raises(AgentProviderError) as captured:
            create_openai_sdk_client(Settings(agent_model_name="gpt-4o"))

        assert captured.value.error_code == "OPENAI_API_KEY_MISSING"

    def test_create_azure_openai_sdk_client_requires_configuration(self) -> None:
        with pytest.raises(AgentProviderError) as captured:
            create_azure_openai_sdk_client(Settings(agent_model_name="gpt-4o"))

        assert captured.value.error_code == "AZURE_OPENAI_CONFIG_MISSING"


class TestChatCompletionClientErrors:
    """Verify SDK and transport failures are mapped to provider errors."""

    @pytest.fixture
    def client(self, agent_request: AgentRequest) -> ChatCompletionAgentClient:
        """Create a client with a mock completion callable."""
        return ChatCompletionAgentClient(
            Mock(),
            provider_name="openai",
            model_name="gpt-4o",
        )

    @pytest.mark.parametrize(
        ("side_effect", "error_code", "retryable"),
        [
            (
                RateLimitError("rate limit", response=Mock(), body=None),
                "AGENT_PROVIDER_RATE_LIMIT",
                True,
            ),
            (
                AuthenticationError("auth failed", response=Mock(), body=None),
                "AGENT_PROVIDER_AUTH_FAILED",
                False,
            ),
            (APIConnectionError(request=Mock()), "AGENT_PROVIDER_CONNECTION_FAILED", True),
        ],
    )

    def test_sdk_errors_are_mapped(
        self,
        agent_request: AgentRequest,
        side_effect: Exception,
        error_code: str,
        retryable: bool,
    ) -> None:
        create_completion = Mock(side_effect=side_effect)
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == error_code
        assert captured.value.retryable is retryable

    def test_rate_limit_error_includes_response_headers(
        self,
        agent_request: AgentRequest,
    ) -> None:
        response = Mock()
        response.headers = {
            "Retry-After": "21",
            "x-ratelimit-remaining-tokens": "0",
            "x-ratelimit-reset-tokens": "12s",
            "x-ratelimit-remaining-requests": "0",
            "x-ratelimit-reset-requests": "1m",
            "x-request-id": "req_test_123",
        }
        create_completion = Mock(
            side_effect=RateLimitError(
                "Rate limit reached",
                response=response,
                body={
                    "error": {
                        "message": (
                            "Rate limit reached for gpt-4o in organization org on tokens per min"
                        ),
                        "type": "tokens",
                    }
                },
            )
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_RATE_LIMIT"
        context = captured.value.context
        assert context is not None
        assert context["task_name"] == agent_request.task_name
        assert context["retry_after"] == "21"
        assert context["ratelimit_reset_tokens"] == "12s"
        assert context["ratelimit_remaining_tokens"] == "0"
        assert context["request_id"] == "req_test_123"
        headers = context["response_headers"]
        assert isinstance(headers, dict)
        assert headers["retry-after"] == "21"
        assert "tokens per min" in str(context["provider_message"])

    def test_rate_limit_error_includes_response_headers_on_complete_turn(
        self,
        agent_request: AgentRequest,
    ) -> None:
        response = Mock()
        response.headers = {"retry-after": "5", "x-ratelimit-reset-requests": "5s"}
        create_completion = Mock(
            side_effect=RateLimitError("rate limit", response=response, body=None)
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete_turn(agent_request, messages=[{"role": "user", "content": "hi"}])

        assert captured.value.error_code == "AGENT_PROVIDER_RATE_LIMIT"
        context = captured.value.context
        assert context is not None
        assert context["retry_after"] == "5"
        assert context["ratelimit_reset_requests"] == "5s"

    def test_api_status_error_marks_5xx_as_retryable(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock(
            side_effect=APIStatusError("server error", response=Mock(status_code=503), body=None)
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_HTTP_ERROR"
        assert captured.value.retryable is True

    def test_api_status_error_includes_provider_message(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock(
            side_effect=APIStatusError(
                "bad request",
                response=Mock(status_code=400),
                body={
                    "error": {
                        "message": (
                            "You uploaded an unsupported image. Please make sure your "
                            "image is below 20 MB and is of one the following formats: "
                            "['png', 'jpeg', 'gif', 'webp']."
                        )
                    }
                },
            )
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_HTTP_ERROR"
        assert captured.value.retryable is False
        assert captured.value.context is not None
        assert "unsupported image" in str(captured.value.context["provider_message"]).lower()

    def test_api_status_error_uses_top_level_message_when_nested_missing(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock(
            side_effect=APIStatusError(
                "bad request",
                response=Mock(status_code=400),
                body={"message": "top-level provider failure"},
            )
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.context is not None
        assert captured.value.context["provider_message"] == "top-level provider failure"

    def test_unexpected_exception_is_wrapped(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock(side_effect=RuntimeError("boom"))
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_REQUEST_FAILED"

    def test_invalid_json_response_is_rejected(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="not-json"),
                    finish_reason="stop",
                )
            ]
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_INVALID_JSON"
        assert captured.value.retryable is True
        assert captured.value.context is not None
        assert "raw_response_preview" in captured.value.context

    def test_markdown_fenced_json_is_accepted(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content='```json\n{"ok": true}\n```'),
                    finish_reason="stop",
                )
            ]
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        response = client.complete(agent_request)

        assert response.output_payload == {"ok": True}

    def test_truncated_completion_raises_retryable_error(
        self,
        agent_request: AgentRequest,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content='{"application": {"name": "Pay'),
                    finish_reason="length",
                )
            ]
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        with pytest.raises(AgentProviderError) as captured:
            client.complete(agent_request)

        assert captured.value.error_code == "AGENT_PROVIDER_OUTPUT_TRUNCATED"
        assert captured.value.retryable is True

    def test_text_attachment_is_inlined_in_user_message(
        self,
        agent_request: AgentRequest,
    ) -> None:
        import base64
        import hashlib

        content = b'{"nodes": []}'
        encoded = base64.b64encode(content).decode("ascii")
        attachment = AttachmentContent(
            attachment_id="attachment:config.json",
            filename="config.json",
            media_type="application/json",
            kind=AttachmentKind.DOCUMENT,
            content_base64=encoded,
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            source_reference=SourceReference(
                source_type=SourceType.CONFLUENCE_ATTACHMENT,
                source_id="config.json",
                location="file:///config.json",
                excerpt="Config attachment",
            ),
        )
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        request = agent_request.model_copy(update={"attachments": [attachment]})
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        client.complete(request)

        user_message = create_completion.call_args.kwargs["messages"][-1]
        assert user_message["content"][1]["type"] == "text"
        assert "config.json" in user_message["content"][1]["text"]

    def test_binary_attachment_adds_manifest_text(
        self,
        agent_request: AgentRequest,
    ) -> None:
        import base64
        import hashlib

        content = b"\x00\x01\x02"
        encoded = base64.b64encode(content).decode("ascii")
        attachment = AttachmentContent(
            attachment_id="attachment:archive.bin",
            filename="archive.bin",
            media_type="application/octet-stream",
            kind=AttachmentKind.OTHER,
            content_base64=encoded,
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            source_reference=SourceReference(
                source_type=SourceType.CONFLUENCE_ATTACHMENT,
                source_id="archive.bin",
                location="file:///archive.bin",
                excerpt="Binary attachment",
            ),
        )
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        request = agent_request.model_copy(update={"attachments": [attachment]})
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        client.complete(request)

        user_message = create_completion.call_args.kwargs["messages"][-1]
        assert "included in the request manifest" in user_message["content"][1]["text"]

    def test_attachments_append_user_message_when_none_exists(
        self,
        agent_request: AgentRequest,
        image_attachment: AttachmentContent,
    ) -> None:
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        request = agent_request.model_copy(
            update={
                "messages": [agent_request.messages[0]],
                "attachments": [image_attachment],
            }
        )
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        client.complete(request)

        assert create_completion.call_args.kwargs["messages"][-1]["role"] == "user"

    def test_create_openai_sdk_client_uses_agent_api_key_fallback(self) -> None:
        settings = Settings(
            agent_api_key=SecretStr("fallback-key"),
            agent_model_name="gpt-4o",
        )

        with patch(
            "threatmodeler.infrastructure.agents.client_factory.OpenAI"
        ) as openai_cls:
            openai_cls.return_value.chat.completions.create = Mock()
            create_openai_sdk_client(settings)

        openai_cls.assert_called_once_with(api_key="fallback-key")

    def test_create_azure_openai_sdk_client_builds_client(self) -> None:
        settings = Settings(
            azure_openai_api_key=SecretStr("azure-key"),
            azure_openai_endpoint=AnyHttpUrl("https://example.openai.azure.com"),
            agent_model_name="deployment-name",
        )

        with patch("openai.AzureOpenAI") as azure_cls:
            azure_cls.return_value.chat.completions.create = Mock()
            client = create_azure_openai_sdk_client(settings)

        assert isinstance(client, ChatCompletionAgentClient)

    def test_user_message_with_list_content_merges_attachments(
        self,
        image_attachment: AttachmentContent,
    ) -> None:
        from threatmodeler.infrastructure.agents.vision_message_builder import (
            augment_user_message_with_attachments,
        )

        messages = [{"role": "user", "content": [{"type": "text", "text": "Existing block"}]}]

        merged = augment_user_message_with_attachments(messages, [image_attachment])

        assert len(merged[0]["content"]) == 2

    def test_augment_skips_non_user_messages_before_appending(
        self,
        image_attachment: AttachmentContent,
    ) -> None:
        from threatmodeler.infrastructure.agents.vision_message_builder import (
            augment_user_message_with_attachments,
        )

        messages = [
            {"role": "user", "content": "Primary user"},
            {"role": "assistant", "content": "Reply"},
        ]

        merged = augment_user_message_with_attachments(messages, [image_attachment])

        assert isinstance(merged[0]["content"], list)
        assert merged[1]["content"] == "Reply"

    def test_augment_returns_unchanged_when_user_content_is_unsupported(
        self,
        image_attachment: AttachmentContent,
    ) -> None:
        from threatmodeler.infrastructure.agents.vision_message_builder import (
            augment_user_message_with_attachments,
        )

        messages = [{"role": "user", "content": 123}]

        merged = augment_user_message_with_attachments(messages, [image_attachment])

        assert merged[0]["content"] == 123

    def test_empty_attachment_blocks_leave_messages_unchanged(
        self,
        agent_request: AgentRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from threatmodeler.infrastructure.agents import vision_message_builder

        monkeypatch.setattr(
            vision_message_builder,
            "attachment_content_blocks",
            lambda attachments: [],
        )
        create_completion = Mock()
        create_completion.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
        )
        request = agent_request.model_copy(update={"attachments": [Mock()]})
        client = ChatCompletionAgentClient(
            create_completion, provider_name="openai", model_name="gpt-4o"
        )

        client.complete(request)

        assert len(create_completion.call_args.kwargs["messages"]) == 3


class TestChatCompletionClientCompleteTurnErrors:
    """Cover chat-completion property accessors and complete_turn error paths."""

    @pytest.fixture
    def agent_request(self) -> AgentRequest:
        return AgentRequest(
            task_name="extract_canonical_system_model",
            instructions="Extract architecture.",
            input_payload={"title": "Payments"},
            expected_schema_name="CanonicalSystemModel",
            messages=[PromptMessage(role=PromptRole.USER, content="User payload.")],
            temperature=0.0,
            max_output_tokens=500,
        )

    def test_property_accessors_return_configured_values(self) -> None:
        client = ChatCompletionAgentClient(
            Mock(),
            provider_name="openai",
            model_name="gpt-4o",
        )
        assert client.provider_name == "openai"
        assert client.model_name == "gpt-4o"

    @pytest.mark.parametrize(
        ("side_effect", "error_code"),
        [
            (AuthenticationError("auth failed", response=Mock(), body=None), "AGENT_PROVIDER_AUTH_FAILED"),
            (APIConnectionError(request=Mock()), "AGENT_PROVIDER_CONNECTION_FAILED"),
            (
                APIStatusError("server error", response=Mock(status_code=503), body=None),
                "AGENT_PROVIDER_HTTP_ERROR",
            ),
            (RuntimeError("boom"), "AGENT_PROVIDER_REQUEST_FAILED"),
        ],
    )

    def test_complete_turn_maps_errors(
        self,
        agent_request: AgentRequest,
        side_effect: Exception,
        error_code: str,
    ) -> None:
        create_completion = Mock(side_effect=side_effect)
        client = ChatCompletionAgentClient(create_completion, provider_name="openai", model_name="gpt-4o")

        with pytest.raises(AgentProviderError) as captured:
            client.complete_turn(agent_request, messages=[{"role": "user", "content": "hi"}])

        assert captured.value.error_code == error_code

    def test_raw_preview_truncates_long_content(self) -> None:
        content = "x" * 600
        preview = _raw_preview(content)
        assert preview.endswith("...")
        assert len(preview) < len(content)

    def test_tool_calling_kwargs_omit_reasoning_effort_for_non_gpt_56(self, agent_request: AgentRequest) -> None:
        create_completion = Mock(
            return_value=SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))]
            )
        )
        client = ChatCompletionAgentClient(
            create_completion,
            provider_name="openai",
            model_name="gpt-5.5",
        )
        tools = [{"type": "function", "function": {"name": "add_actor", "parameters": {}}}]

        client.complete_turn(agent_request, messages=[{"role": "user", "content": "hi"}], tools=tools)

        assert "reasoning_effort" not in create_completion.call_args.kwargs

    def test_response_headers_and_provider_message_fallbacks(self) -> None:
        error = APIStatusError("fallback", response=Mock(status_code=400), body={"unexpected": True})
        assert _response_headers(error) == {}
        assert _provider_error_message(error) == "fallback"

        response = Mock()
        response.status_code = 429
        response.headers = {"X-Test": 456, 123: "ignored"}
        rate_error = RateLimitError("limited", response=response, body=None)
        headers = _response_headers(rate_error)
        assert headers["x-test"] == "456"
        assert 123 not in headers


class TestChatCompletionClientErrorHelpers:
    """Verify provider error message and header extraction edge cases."""

    def test_chat_completion_provider_message_and_headers_branches(self) -> None:
        nested_error = APIStatusError(
            "fallback",
            response=Mock(status_code=400),
            body={"error": {"message": "   "}, "message": "  "},
        )
        assert _provider_error_message(nested_error) == "fallback"

        class HeaderlessError(APIStatusError):
            pass

        error = HeaderlessError.__new__(HeaderlessError)
        error.response = None
        assert _response_headers(error) == {}
