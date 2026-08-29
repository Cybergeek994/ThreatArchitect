"""GitHub Copilot SDK tool-calling driver using in-process construction tools."""

from __future__ import annotations

import json
from typing import cast

from pydantic import JsonValue

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.contracts.tool_calling import JournalEvent, ToolApplicationResult
from threatmodeler.orchestration.prompts.tool_calling_instructions import TOOL_CALLING_INSTRUCTIONS
from threatmodeler.domain.tool_calling.stall_guard import RepeatedFinishRejectionGuard
from threatmodeler.errors.application import AgentProviderError, ConfigurationError
from threatmodeler.infrastructure.agents.copilot_client import CopilotSdkAgentClient
from threatmodeler.ports.artifact_construction_session import ArtifactConstructionSession
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.shared.constants import AgentProviderName, JournalEventType

try:
    from copilot.tools import define_tool as _define_tool
except ImportError:  # pragma: no cover
    _define_tool = None


class CopilotToolCallingDriver:
    """Drive Copilot custom tools against a host construction session."""

    def __init__(
        self,
        client: CopilotSdkAgentClient,
        *,
        max_turns: int,
        stall_after_repeats: int = 2,
    ) -> None:
        self._client = client
        self._max_turns = max_turns
        self._stall_after_repeats = stall_after_repeats

    def complete_with_tools(
        self,
        request: AgentRequest,
        session: ArtifactConstructionSession,
        journal: ConstructionJournal,
    ) -> AgentResponse:
        """Run a Copilot session whose only tools are host construction tools.

        Args:
            request: Provider-neutral completion request.
            session: Host-owned construction state.
            journal: Durable construction trace.

        Returns:
            Response whose payload is the assembled artifact.

        Raises:
            AgentProviderError: If Copilot fails, stalls, or finish is never accepted.
        """
        stall_guard = RepeatedFinishRejectionGuard(stall_after_repeats=self._stall_after_repeats)
        tools = _copilot_tools(session, journal, request.task_name, stall_guard)
        available_tools = [definition.name for definition in session.tool_definitions()]
        overlay = request.model_copy(
            update={
                "instructions": f"{request.instructions}\n\n{TOOL_CALLING_INSTRUCTIONS}",
            }
        )
        try:
            self._client.complete_with_tools(
                overlay,
                tools=tools,
                available_tools=available_tools,
            )
        except AgentProviderError:
            raise
        if not session.is_complete():
            journal.record(
                JournalEvent(
                    event_type=JournalEventType.TURN_BUDGET_EXCEEDED,
                    task_name=request.task_name,
                    details={"max_turns": self._max_turns},
                )
            )
            raise AgentProviderError(
                "Copilot session ended before artifact construction finished",
                error_code="AGENT_PROVIDER_TOOL_LOOP_EXCEEDED",
                retryable=True,
                context={"task_name": request.task_name, "max_turns": self._max_turns},
            )
        payload = session.assemble()
        journal.record(
            JournalEvent(
                event_type=JournalEventType.ASSEMBLED,
                task_name=request.task_name,
                details={
                    "provider_name": AgentProviderName.GITHUB_COPILOT,
                    "model_name": self._client.model_name,
                },
            )
        )
        return AgentResponse(
            output_payload=payload,
            confidence=0.75,
            raw_response=json.dumps(payload, ensure_ascii=False),
            provider_name=AgentProviderName.GITHUB_COPILOT,
            model_name=self._client.model_name,
        )


def _copilot_tools(
    session: ArtifactConstructionSession,
    journal: ConstructionJournal,
    task_name: str,
    stall_guard: RepeatedFinishRejectionGuard,
) -> list[object]:
    if _define_tool is None:
        raise ConfigurationError(
            "GitHub Copilot SDK is not installed; install github-copilot-sdk",
            error_code="GITHUB_COPILOT_SDK_MISSING",
            retryable=False,
            context={"agent_provider_name": AgentProviderName.GITHUB_COPILOT},
        )

    tools: list[object] = []
    for definition in session.tool_definitions():
        parameter_model = session.tool_parameter_model(definition.name)
        bound_name = definition.name

        def handler(
            params: object,
            invocation: object,
            *,
            tool_name: str = bound_name,
        ) -> str:
            del invocation
            dump = params.model_dump(mode="json") if hasattr(params, "model_dump") else {}
            journal.record(
                JournalEvent(
                    event_type=JournalEventType.TOOL_CALL_RECEIVED,
                    task_name=task_name,
                    tool_name=tool_name,
                )
            )
            result = session.apply(tool_name, cast(dict[str, JsonValue], dump))
            _record_result(journal, task_name, tool_name, result)
            if (
                tool_name.startswith("finish_")
                and not result.accepted
                and stall_guard.record(result.message)
            ):
                journal.record(
                    JournalEvent(
                        event_type=JournalEventType.TURN_BUDGET_EXCEEDED,
                        task_name=task_name,
                        details={
                            "reason": "identical_finish_rejection",
                            "message": result.message,
                        },
                    )
                )
                raise AgentProviderError(
                    "Agent tool-calling loop stalled on repeated identical finish rejections",
                    error_code="AGENT_PROVIDER_TOOL_LOOP_STALLED",
                    retryable=False,
                    context={"task_name": task_name, "message": result.message},
                )
            return result.message

        tools.append(
            _define_tool(
                definition.name,
                description=definition.description,
                params_type=parameter_model,
                handler=handler,
                skip_permission=True,
                is_terminal=definition.is_terminal,
            )
        )
    return tools


def _record_result(
    journal: ConstructionJournal,
    task_name: str,
    tool_name: str,
    result: ToolApplicationResult,
) -> None:
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
