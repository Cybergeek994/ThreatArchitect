"""Tests for repeated finish-rejection stall detection."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import BaseModel, Field
from threatmodeler.contracts.integration import AgentRequest
from threatmodeler.contracts.prompts import PromptMessage, PromptRole
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import ArtifactBuilderSession
from threatmodeler.domain.tool_calling.stall_guard import RepeatedFinishRejectionGuard
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.infrastructure.agents.openai_tool_calling_driver import OpenAIToolCallingDriver
from threatmodeler.infrastructure.journal.null_construction_journal import NullConstructionJournal


class TestStallGuardPositive:
    """Verify the guard only aborts after repeated identical messages."""

    def test_first_rejection_does_not_stall(self) -> None:
        guard = RepeatedFinishRejectionGuard(stall_after_repeats=2)
        assert guard.record("Duplicate entity id: 1") is False

    def test_identical_second_rejection_stalls(self) -> None:
        guard = RepeatedFinishRejectionGuard(stall_after_repeats=2)
        assert guard.record("Duplicate entity id: 1") is False
        assert guard.record("Duplicate entity id: 1") is True

    def test_different_message_resets_streak(self) -> None:
        guard = RepeatedFinishRejectionGuard(stall_after_repeats=2)
        assert guard.record("Duplicate entity id: 1") is False
        assert guard.record("Unknown source") is False
        assert guard.record("Duplicate entity id: 1") is False


class TestOpenAIToolCallingDriverStall:
    """Verify the driver aborts on repeated identical finish rejections."""

    def test_identical_finish_rejection_raises_stalled(self) -> None:
        class Item(BaseModel):
            id: str
            name: str

        class Artifact(BaseModel):
            title: str
            items: list[Item] = Field(default_factory=list)

        def request() -> AgentRequest:
            return AgentRequest(
                task_name="generate_demo",
                instructions="Build the artifact with tools.",
                input_payload={"title": "demo"},
                expected_schema_name="Artifact",
                messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
                temperature=0.0,
                max_output_tokens=200,
            )

        def tool_call(identifier: str, name: str, arguments: str) -> SimpleNamespace:
            return SimpleNamespace(
                id=identifier,
                function=SimpleNamespace(name=name, arguments=arguments),
            )

        def completion(tool_calls: list[SimpleNamespace] | None) -> SimpleNamespace:
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=tool_calls))
                ],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            )

        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.side_effect = [
            completion([tool_call("call-1", "finish_artifact", '{"title": "Demo"}')]),
            completion([tool_call("call-2", "finish_artifact", '{"title": "Demo"}')]),
        ]
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(Artifact),
            finish_validator=lambda _payload: ["Duplicate entity id: 1"],
        )
        driver = OpenAIToolCallingDriver(client, max_turns=8, stall_after_repeats=2)
        with pytest.raises(AgentProviderError) as captured:
            driver.complete_with_tools(request(), session, NullConstructionJournal())
        assert captured.value.error_code == "AGENT_PROVIDER_TOOL_LOOP_STALLED"
        assert client.complete_turn.call_count == 2


    def test_stall_guard_rejects_invalid_repeat_threshold(self) -> None:
        with pytest.raises(ValueError, match="stall_after_repeats"):
            RepeatedFinishRejectionGuard(stall_after_repeats=0)
