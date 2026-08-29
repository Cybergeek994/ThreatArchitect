"""Tests for GitHub Copilot SDK tool-calling driver."""

from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, patch

import pytest
from pydantic import BaseModel, Field, JsonValue
from threatmodeler.contracts.integration import AgentRequest
from threatmodeler.contracts.prompts import PromptMessage, PromptRole
from threatmodeler.contracts.tool_calling import JournalEvent
from threatmodeler.domain.tool_calling.artifact_tool_set import ArtifactToolSet
from threatmodeler.domain.tool_calling.builder_session import ArtifactBuilderSession
from threatmodeler.errors.application import AgentProviderError, ConfigurationError
from threatmodeler.infrastructure.agents.copilot_tool_calling_driver import CopilotToolCallingDriver
from threatmodeler.infrastructure.journal.null_construction_journal import NullConstructionJournal
from threatmodeler.shared.constants import JournalEventType


class TestCopilotToolCallingModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class Artifact(BaseModel):
        title: str
        items: list["TestCopilotToolCallingModels.Item"] = Field(default_factory=list)


TestCopilotToolCallingModels.Artifact.model_rebuild()


class TestCopilotToolCallingDriverPositive:
    """Verify successful Copilot tool-calling sessions."""

    def test_complete_with_tools_assembles_accepted_artifact(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestCopilotToolCallingModels.Artifact)
        )
        journal = Mock()
        client = Mock()
        client.model_name = "copilot-test"

        def complete_side_effect(
            overlay: AgentRequest,
            *,
            tools: list[object],
            available_tools: list[str],
        ) -> None:
            del overlay, available_tools
            session.apply("add_item", {"id": "item-1", "name": "Login"})
            session.apply("finish_artifact", {"title": "Demo"})

        client.complete_with_tools.side_effect = complete_side_effect

        with patch(
            "threatmodeler.infrastructure.agents.copilot_tool_calling_driver._define_tool",
            side_effect=lambda name, **kwargs: SimpleNamespace(name=name, **kwargs),
        ):
            driver = CopilotToolCallingDriver(client, max_turns=4)
            response = driver.complete_with_tools(request, session, journal)

        payload = cast(dict[str, JsonValue], response.output_payload)
        assert payload["title"] == "Demo"
        assert journal.record.call_count >= 1
        assembled_events = [
            call.args[0]
            for call in journal.record.call_args_list
            if isinstance(call.args[0], JournalEvent)
            and call.args[0].event_type is JournalEventType.ASSEMBLED
        ]
        assert len(assembled_events) == 1

    def test_complete_with_tools_reraises_agent_provider_error(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestCopilotToolCallingModels.Artifact)
        )
        client = Mock()
        client.model_name = "copilot-test"
        client.complete_with_tools.side_effect = AgentProviderError(
            "provider failed",
            error_code="AGENT_PROVIDER_FAILED",
            retryable=True,
        )

        with (
            patch(
                "threatmodeler.infrastructure.agents.copilot_tool_calling_driver._define_tool",
                side_effect=lambda name, **kwargs: SimpleNamespace(name=name, **kwargs),
            ),
            pytest.raises(AgentProviderError) as captured,
        ):
            CopilotToolCallingDriver(client, max_turns=4).complete_with_tools(
                request,
                session,
                NullConstructionJournal(),
            )

        assert captured.value.error_code == "AGENT_PROVIDER_FAILED"


class TestCopilotToolCallingDriverNegative:
    """Verify Copilot tool-calling failure modes."""

    def test_complete_with_tools_raises_when_session_incomplete(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestCopilotToolCallingModels.Artifact)
        )
        journal = Mock()
        client = Mock()
        client.model_name = "copilot-test"
        client.complete_with_tools.return_value = None

        with (
            patch(
                "threatmodeler.infrastructure.agents.copilot_tool_calling_driver._define_tool",
                side_effect=lambda name, **kwargs: SimpleNamespace(name=name, **kwargs),
            ),
            pytest.raises(AgentProviderError) as captured,
        ):
            CopilotToolCallingDriver(client, max_turns=3).complete_with_tools(
                request,
                session,
                journal,
            )

        assert captured.value.error_code == "AGENT_PROVIDER_TOOL_LOOP_EXCEEDED"
        budget_events = [
            call.args[0]
            for call in journal.record.call_args_list
            if call.args[0].event_type is JournalEventType.TURN_BUDGET_EXCEEDED
        ]
        assert len(budget_events) == 1

    def test_copilot_tools_raises_when_define_tool_missing(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestCopilotToolCallingModels.Artifact)
        )
        client = Mock()
        client.model_name = "copilot-test"

        with (
            patch(
                "threatmodeler.infrastructure.agents.copilot_tool_calling_driver._define_tool",
                None,
            ),
            pytest.raises(ConfigurationError) as captured,
        ):
            CopilotToolCallingDriver(client, max_turns=4).complete_with_tools(
                request,
                session,
                NullConstructionJournal(),
            )

        assert captured.value.error_code == "GITHUB_COPILOT_SDK_MISSING"


from pydantic import BaseModel, Field
from threatmodeler.contracts.tool_calling import JournalEvent, ToolApplicationResult
from threatmodeler.infrastructure.agents.copilot_tool_calling_driver import _record_result
from threatmodeler.shared.constants import JournalEventType

class TestToolCallingFixtureModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class OnlyLists(BaseModel):
        items: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)

    class ScalarOnly(BaseModel):
        title: str

    class OptionalIdItem(BaseModel):
        id: str | None = None
        name: str

    class MultiFinish(BaseModel):
        title: str
        items: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)

    class ProcessesArtifact(BaseModel):
        title: str
        processes: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)
        entries: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)

    class BareListModel(BaseModel):
        rows: list = Field(default_factory=list)
        title: str

    class DataFieldModel(BaseModel):
        data: list["TestToolCallingFixtureModels.Item"] = Field(default_factory=list)
        title: str


TestToolCallingFixtureModels.Item.model_rebuild()
TestToolCallingFixtureModels.OnlyLists.model_rebuild()
TestToolCallingFixtureModels.MultiFinish.model_rebuild()
TestToolCallingFixtureModels.ProcessesArtifact.model_rebuild()

class TestCopilotToolCallingDriverJournalEvents:
    """Verify Copilot tool handler journal event classification."""

    def test_tool_handler_records_journal_events_and_returns_message(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish)
        )
        journal = Mock()
        client = Mock()
        client.model_name = "copilot-test"
        captured_handlers: dict[str, object] = {}

        def fake_define_tool(name: str, **kwargs: object) -> SimpleNamespace:
            captured_handlers[name] = kwargs["handler"]
            return SimpleNamespace(name=name, **kwargs)

        def complete_side_effect(
            overlay: AgentRequest,
            *,
            tools: list[object],
            available_tools: list[str],
        ) -> None:
            del overlay, tools, available_tools
            handler = captured_handlers["add_item"]
            handler(
                TestToolCallingFixtureModels.Item(id="item-1", name="Login"),
                Mock(),
            )
            finish_handler = captured_handlers["finish_multi_finish"]
            finish_handler(
                TestToolCallingFixtureModels.MultiFinish(title="Demo"),
                Mock(),
            )

        client.complete_with_tools.side_effect = complete_side_effect

        with patch(
            "threatmodeler.infrastructure.agents.copilot_tool_calling_driver._define_tool",
            side_effect=fake_define_tool,
        ):
            response = CopilotToolCallingDriver(client, max_turns=4).complete_with_tools(
                request,
                session,
                journal,
            )

        assert response.output_payload["title"] == "Demo"
        event_types = [
            call.args[0].event_type
            for call in journal.record.call_args_list
            if isinstance(call.args[0], JournalEvent)
        ]
        assert JournalEventType.TOOL_CALL_RECEIVED in event_types
        assert JournalEventType.TOOL_CALL_ACCEPTED in event_types
        assert JournalEventType.FINISH_ACCEPTED in event_types

    def test_tool_handler_stalls_on_repeated_finish_rejection(self) -> None:
        request = AgentRequest(
            task_name="generate_demo",
            instructions="Build the artifact with tools.",
            input_payload={"title": "demo"},
            expected_schema_name="_Artifact",
            messages=[PromptMessage(role=PromptRole.USER, content="Build it.")],
            temperature=0.0,
            max_output_tokens=200,
        )
        session = ArtifactBuilderSession(
            ArtifactToolSet.from_model(TestToolCallingFixtureModels.MultiFinish),
            finish_validator=lambda _payload: ["Duplicate entity id: 1"],
        )
        journal = Mock()
        client = Mock()
        client.model_name = "copilot-test"
        captured_handlers: dict[str, object] = {}

        def fake_define_tool(name: str, **kwargs: object) -> SimpleNamespace:
            captured_handlers[name] = kwargs["handler"]
            return SimpleNamespace(name=name, **kwargs)

        def complete_side_effect(
            overlay: AgentRequest,
            *,
            tools: list[object],
            available_tools: list[str],
        ) -> None:
            del overlay, tools, available_tools
            finish_handler = captured_handlers["finish_multi_finish"]
            finish_handler(
                TestToolCallingFixtureModels.MultiFinish(title="Demo"),
                Mock(),
            )
            finish_handler(
                TestToolCallingFixtureModels.MultiFinish(title="Demo"),
                Mock(),
            )

        client.complete_with_tools.side_effect = complete_side_effect

        with (
            patch(
                "threatmodeler.infrastructure.agents.copilot_tool_calling_driver._define_tool",
                side_effect=fake_define_tool,
            ),
            pytest.raises(AgentProviderError) as captured,
        ):
            CopilotToolCallingDriver(client, max_turns=4, stall_after_repeats=2).complete_with_tools(
                request,
                session,
                journal,
            )

        assert captured.value.error_code == "AGENT_PROVIDER_TOOL_LOOP_STALLED"

    def test_record_result_classifies_all_event_types(self) -> None:
        journal = Mock()
        task_name = "generate_demo"

        _record_result(
            journal,
            task_name,
            "finish_artifact",
            ToolApplicationResult(accepted=True, message="done", finished=True),
        )
        _record_result(
            journal,
            task_name,
            "finish_artifact",
            ToolApplicationResult(accepted=False, message="invalid", finished=False),
        )
        _record_result(
            journal,
            task_name,
            "add_item",
            ToolApplicationResult(accepted=True, message="accepted"),
        )
        _record_result(
            journal,
            task_name,
            "add_item",
            ToolApplicationResult(accepted=False, message="rejected"),
        )

        event_types = [call.args[0].event_type for call in journal.record.call_args_list]
        assert event_types == [
            JournalEventType.FINISH_ACCEPTED,
            JournalEventType.FINISH_REJECTED,
            JournalEventType.TOOL_CALL_ACCEPTED,
            JournalEventType.TOOL_CALL_REJECTED,
        ]
