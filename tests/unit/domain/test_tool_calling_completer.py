"""Tests for schema-bound tool-calling completer."""

from unittest.mock import Mock

import pytest
from pydantic import BaseModel, Field
from threatmodeler.contracts.integration import AgentRequest
from threatmodeler.domain.tool_calling.completer import SchemaBoundToolCallingCompleter
from threatmodeler.domain.tool_calling.discarding_journal import DiscardingConstructionJournal
from threatmodeler.errors import AgentProviderError


class TestToolCallingCompleterModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        id: str
        name: str

    class MultiFinish(BaseModel):
        title: str
        items: list["TestToolCallingCompleterModels.Item"] = Field(default_factory=list)


TestToolCallingCompleterModels.Item.model_rebuild()
TestToolCallingCompleterModels.MultiFinish.model_rebuild()


class TestSchemaBoundToolCallingCompleter:
    """Verify schema-bound tool-calling completer retry behavior."""

    def test_completer_rejects_invalid_max_attempts(self) -> None:
        with pytest.raises(ValueError, match="max_attempts"):
            SchemaBoundToolCallingCompleter(Mock(), max_attempts=0)

    def test_completer_reraises_last_retryable_error(self) -> None:
        provider = Mock()
        provider.complete_with_tools.side_effect = AgentProviderError(
            "still failing",
            error_code="AGENT_PROVIDER_FAILED",
            retryable=True,
        )
        completer = SchemaBoundToolCallingCompleter(provider, max_attempts=2)
        with pytest.raises(AgentProviderError) as captured:
            completer.complete(
                AgentRequest(
                    task_name="generate_demo",
                    instructions="Build",
                    input_payload={},
                    expected_schema_name="_Artifact",
                    messages=[],
                    temperature=0.0,
                    max_output_tokens=100,
                ),
                TestToolCallingCompleterModels.MultiFinish,
                DiscardingConstructionJournal(),
            )
        assert captured.value.error_code == "AGENT_PROVIDER_FAILED"
        assert provider.complete_with_tools.call_count == 2

    def test_completer_honors_session_factory_override(self) -> None:
        custom_factory = Mock()
        custom_session = Mock()
        custom_session.tool_definitions.return_value = []
        custom_factory.create.return_value = custom_session
        provider = Mock()
        provider.complete_with_tools.return_value = Mock(
            output_payload={"title": "Demo", "items": []},
            confidence=1.0,
            raw_response="{}",
            provider_name="mock",
            model_name="mock",
        )
        completer = SchemaBoundToolCallingCompleter(provider)
        completer.complete(
            AgentRequest(
                task_name="generate_demo",
                instructions="Build",
                input_payload={},
                expected_schema_name="_Artifact",
                messages=[],
                temperature=0.0,
                max_output_tokens=100,
            ),
            TestToolCallingCompleterModels.MultiFinish,
            DiscardingConstructionJournal(),
            session_factory=custom_factory,
        )

        custom_factory.create.assert_called_once()
