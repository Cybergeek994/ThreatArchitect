"""Tests for the OpenAI-compatible tool-calling driver."""

from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

from pydantic import BaseModel, Field, JsonValue
from threatmodeler.contracts.integration import AgentRequest
from threatmodeler.contracts.prompts import PromptMessage, PromptRole
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import ArtifactBuilderSession
from threatmodeler.infrastructure.agents.openai_tool_calling_driver import OpenAIToolCallingDriver
from threatmodeler.infrastructure.journal.null_construction_journal import NullConstructionJournal


class TestOpenAIToolCallingModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class Artifact(BaseModel):
        title: str
        items: list["TestOpenAIToolCallingModels.Item"] = Field(default_factory=list)


TestOpenAIToolCallingModels.Artifact.model_rebuild()


class TestOpenAIToolCallingDriverPositive:
    """Verify the driver assembles artifacts from accepted tool calls."""

    def test_driver_applies_add_and_finish_tools(self) -> None:
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

        def completion(tool_calls: list[SimpleNamespace] | None) -> SimpleNamespace:
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=tool_calls))
                ]
            )

        client = Mock()
        client.provider_name = "openai"
        client.model_name = "test-model"
        client.complete_turn.side_effect = [
            completion([tool_call("call-1", "add_item", '{"id": "item-1", "name": "Login"}')]),
            completion([tool_call("call-2", "finish_artifact", '{"title": "Demo"}')]),
        ]
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestOpenAIToolCallingModels.Artifact)
        )
        driver = OpenAIToolCallingDriver(client, max_turns=4)
        response = driver.complete_with_tools(request(), session, NullConstructionJournal())
        payload = cast(dict[str, JsonValue], response.output_payload)
        assert payload["title"] == "Demo"
        items = cast(list[dict[str, JsonValue]], payload["items"])
        assert items[0]["id"] == "item-1"
