"""Extended tests for OpenAI-compatible tool-calling driver branches."""

from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
from pydantic import BaseModel, Field, JsonValue
from threatmodeler.contracts.integration import AgentRequest
from threatmodeler.contracts.prompts import PromptMessage, PromptRole
from threatmodeler.contracts.tool_calling import JournalEvent
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import ArtifactBuilderSession
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.infrastructure.agents.openai_tool_calling_driver import OpenAIToolCallingDriver
from threatmodeler.infrastructure.journal.null_construction_journal import NullConstructionJournal
from threatmodeler.shared.constants import JournalEventType


class TestOpenAIToolCallingExtendedModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class Artifact(BaseModel):
        title: str
        items: list["TestOpenAIToolCallingExtendedModels.Item"] = Field(default_factory=list)


TestOpenAIToolCallingExtendedModels.Artifact.model_rebuild()


class TestOpenAIToolCallingDriverExtendedPositive:
    """Verify additional successful and recovery tool-calling paths."""

    def test_no_tool_calls_prompts_model_to_use_tools(self) -> None:
        def request() -> AgentRequest:
            return AgentRequest(
                task_name="generate_demo",
                instructions="Build the artifact with tools.",
                input_payload={"title": "demo"},
                expected_schema_name="_Artifact",
                messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
                temperature=0.0,
                max_output_tokens=200,
            )

        def tool_call(identifier: str, name: str, arguments: str) -> SimpleNamespace:
            return SimpleNamespace(
                id=identifier,
                function=SimpleNamespace(name=name, arguments=arguments),
            )

        def completion(
            tool_calls: list[SimpleNamespace] | None,
            *,
            content: str | None = None,
        ) -> SimpleNamespace:
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content=content, tool_calls=tool_calls)
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            )

        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.side_effect = [
            completion(None, content='{"title":"Demo"}'),
            completion([tool_call("call-1", "finish_artifact", '{"title": "Demo"}')]),
        ]
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingExtendedModels.Artifact)
        )
        journal = Mock()
        driver = OpenAIToolCallingDriver(client, max_turns=4)
        response = driver.complete_with_tools(request(), session, journal)

        payload = cast(dict[str, JsonValue], response.output_payload)
        assert payload["title"] == "Demo"
        turn_events = [
            call.args[0]
            for call in journal.record.call_args_list
            if call.args[0].event_type is JournalEventType.TURN_COMPLETED
        ]
        assert len(turn_events) == 2
        assert turn_events[0].details["prompt_tokens"] == 10


class TestOpenAIToolCallingDriverExtendedNegative:
    """Verify stall guard, turn budget, and invalid tool-call handling."""

    def test_turn_budget_exceeded_raises_when_finish_never_accepted(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=None))],
            usage=None,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingExtendedModels.Artifact)
        )
        journal = Mock()
        driver = OpenAIToolCallingDriver(client, max_turns=2)

        with pytest.raises(AgentProviderError) as captured:
            driver.complete_with_tools(request, session, journal)

        assert captured.value.error_code == "AGENT_PROVIDER_TOOL_LOOP_EXCEEDED"

    def test_repeated_finish_rejection_triggers_stall_guard(self) -> None:
        def tool_call(identifier: str, name: str, arguments: str) -> SimpleNamespace:
            return SimpleNamespace(
                id=identifier,
                function=SimpleNamespace(name=name, arguments=arguments),
            )

        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[
                            tool_call("call-1", "finish_artifact", "{}"),
                        ],
                    )
                )
            ],
            usage=None,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingExtendedModels.Artifact)
        )
        journal = Mock()
        driver = OpenAIToolCallingDriver(client, max_turns=4, stall_after_repeats=2)

        with pytest.raises(AgentProviderError) as captured:
            driver.complete_with_tools(request, session, journal)

        assert captured.value.error_code == "AGENT_PROVIDER_TOOL_LOOP_STALLED"

    def test_invalid_json_tool_arguments_are_rejected(self) -> None:
        def tool_call(identifier: str, name: str, arguments: str) -> SimpleNamespace:
            return SimpleNamespace(
                id=identifier,
                function=SimpleNamespace(name=name, arguments=arguments),
            )

        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.side_effect = [
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[tool_call("call-1", "add_item", "{not-json")],
                        )
                    )
                ],
                usage=None,
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[
                                tool_call(
                                    "call-2",
                                    "finish_artifact",
                                    '{"title": "Demo"}',
                                )
                            ],
                        )
                    )
                ],
                usage=None,
            ),
        ]
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingExtendedModels.Artifact)
        )
        journal = Mock()
        driver = OpenAIToolCallingDriver(client, max_turns=4)
        response = driver.complete_with_tools(request, session, journal)

        payload = cast(dict[str, JsonValue], response.output_payload)
        assert payload["title"] == "Demo"
        rejected_events = [
            call.args[0]
            for call in journal.record.call_args_list
            if call.args[0].event_type is JournalEventType.TOOL_CALL_REJECTED
        ]
        assert len(rejected_events) >= 1

    def test_non_object_tool_arguments_are_rejected(self) -> None:
        def tool_call(identifier: str, name: str, arguments: str) -> SimpleNamespace:
            return SimpleNamespace(
                id=identifier,
                function=SimpleNamespace(name=name, arguments=arguments),
            )

        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.side_effect = [
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[tool_call("call-1", "add_item", '["not-an-object"]')],
                        )
                    )
                ],
                usage=None,
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[
                                tool_call(
                                    "call-2",
                                    "finish_artifact",
                                    '{"title": "Demo"}',
                                )
                            ],
                        )
                    )
                ],
                usage=None,
            ),
        ]
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingExtendedModels.Artifact)
        )
        journal = Mock()
        driver = OpenAIToolCallingDriver(client, max_turns=4)
        response = driver.complete_with_tools(request, session, journal)

        payload = cast(dict[str, JsonValue], response.output_payload)
        assert payload["title"] == "Demo"

    def test_tool_calls_without_function_are_ignored(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.side_effect = [
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[SimpleNamespace(id="call-1", function=None)],
                        )
                    )
                ],
                usage=None,
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=None,
                            tool_calls=[
                                SimpleNamespace(
                                    id="call-2",
                                    function=SimpleNamespace(
                                        name="finish_artifact",
                                        arguments='{"title": "Demo"}',
                                    ),
                                )
                            ],
                        )
                    )
                ],
                usage=None,
            ),
        ]
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingExtendedModels.Artifact)
        )
        driver = OpenAIToolCallingDriver(client, max_turns=4)
        response = driver.complete_with_tools(request, session, NullConstructionJournal())

        payload = cast(dict[str, JsonValue], response.output_payload)
        assert payload["title"] == "Demo"
