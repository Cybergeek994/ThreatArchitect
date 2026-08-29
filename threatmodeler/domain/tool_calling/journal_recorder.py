"""Record construction-tool outcomes into a journal.

Drivers share this recorder so OpenAI and Copilot adapters do not duplicate event mapping.
"""

from threatmodeler.contracts.tool_calling import JournalEvent, ToolApplicationResult
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.shared.constants import JournalEventType


class ConstructionJournalRecorder:
    """Map tool-application results onto journal events."""

    def record_received(
        self,
        journal: ConstructionJournal,
        task_name: str,
        tool_name: str,
    ) -> None:
        """Record that a provider invoked a construction tool.

        Args:
            journal: Durable construction trace.
            task_name: Agent task that owns the invocation.
            tool_name: Tool name invoked by the provider.
        """
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_RECEIVED,
                task_name=task_name,
                tool_name=tool_name,
            )
        )

    def record_result(
        self,
        journal: ConstructionJournal,
        task_name: str,
        tool_name: str,
        result: ToolApplicationResult,
    ) -> None:
        """Record acceptance or rejection of one construction-tool invocation.

        Args:
            journal: Durable construction trace.
            task_name: Agent task that owns the invocation.
            tool_name: Tool name invoked by the provider.
            result: Host validation outcome.
        """
        if result.finished and result.accepted:
            event_type = JournalEventType.FINISH_ACCEPTED
        elif tool_name.startswith("finish_") and not result.accepted:
            event_type = JournalEventType.FINISH_REJECTED
        elif result.accepted:
            event_type = JournalEventType.TOOL_CALL_ACCEPTED
        else:
            event_type = JournalEventType.TOOL_CALL_REJECTED
        journal.record(
            JournalEvent(
                event_type=event_type,
                task_name=task_name,
                tool_name=tool_name,
                accepted=result.accepted,
                message=result.message,
                evidence_grounded=result.evidence_grounded,
                item_id=result.item_id,
                confidence=result.confidence,
            )
        )
