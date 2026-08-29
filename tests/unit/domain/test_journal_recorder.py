"""Tests for construction journal event recording."""

from unittest.mock import Mock

import pytest
from threatmodeler.contracts.tool_calling import JournalEvent, ToolApplicationResult
from threatmodeler.domain.tool_calling.journal_recorder import ConstructionJournalRecorder
from threatmodeler.shared.constants import JournalEventType


class TestConstructionJournalRecorderPositive:
    """Verify journal events are mapped correctly."""

    @pytest.fixture
    def recorder(self) -> ConstructionJournalRecorder:
        return ConstructionJournalRecorder()

    @pytest.fixture
    def journal(self) -> Mock:
        return Mock()

    def test_record_received_emits_tool_call_received(
        self,
        recorder: ConstructionJournalRecorder,
        journal: Mock,
    ) -> None:
        recorder.record_received(journal, "generate_demo", "add_item")

        journal.record.assert_called_once()
        event = journal.record.call_args[0][0]
        assert isinstance(event, JournalEvent)
        assert event.event_type is JournalEventType.TOOL_CALL_RECEIVED
        assert event.task_name == "generate_demo"
        assert event.tool_name == "add_item"

    @pytest.mark.parametrize(
        ("result", "tool_name", "expected_type"),
        [
            (
                ToolApplicationResult(
                    accepted=True,
                    message="done",
                    finished=True,
                    evidence_grounded=True,
                    item_id="item-1",
                    confidence=0.9,
                ),
                "finish_artifact",
                JournalEventType.FINISH_ACCEPTED,
            ),
            (
                ToolApplicationResult(accepted=False, message="invalid finish", finished=False),
                "finish_artifact",
                JournalEventType.FINISH_REJECTED,
            ),
            (
                ToolApplicationResult(
                    accepted=True,
                    message="accepted",
                    evidence_grounded=False,
                    item_id="item-1",
                    confidence=0.4,
                ),
                "add_item",
                JournalEventType.TOOL_CALL_ACCEPTED,
            ),
            (
                ToolApplicationResult(accepted=False, message="rejected"),
                "add_item",
                JournalEventType.TOOL_CALL_REJECTED,
            ),
        ],
    )

    def test_record_result_maps_event_types(
        self,
        recorder: ConstructionJournalRecorder,
        journal: Mock,
        result: ToolApplicationResult,
        tool_name: str,
        expected_type: JournalEventType,
    ) -> None:
        recorder.record_result(journal, "generate_demo", tool_name, result)

        journal.record.assert_called_once()
        event = journal.record.call_args[0][0]
        assert event.event_type is expected_type
        assert event.task_name == "generate_demo"
        assert event.tool_name == tool_name
        assert event.accepted is result.accepted
        assert event.message == result.message
        assert event.evidence_grounded is result.evidence_grounded
        assert event.item_id is result.item_id
        assert event.confidence is result.confidence
