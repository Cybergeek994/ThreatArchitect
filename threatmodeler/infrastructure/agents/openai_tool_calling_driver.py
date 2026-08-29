"""OpenAI-compatible tool-calling driver shared by OpenAI and Azure OpenAI."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from pydantic import JsonValue

from threatmodeler.contracts.integration import AgentRequest, AgentResponse
from threatmodeler.contracts.tool_calling import JournalEvent, ToolApplicationResult
from threatmodeler.orchestration.prompts.tool_calling_instructions import TOOL_CALLING_INSTRUCTIONS
from threatmodeler.domain.tool_calling.stall_guard import RepeatedFinishRejectionGuard
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.infrastructure.agents.chat_completion_client import ChatCompletionAgentClient
from threatmodeler.infrastructure.agents.vision_message_builder import build_messages
from threatmodeler.ports.artifact_construction_session import ArtifactConstructionSession
from threatmodeler.ports.construction_journal import ConstructionJournal
from threatmodeler.shared.constants import JournalEventType


class OpenAIToolCallingDriver:
    """Drive OpenAI-compatible function calling against a host construction session."""

    def __init__(
        self,
        client: ChatCompletionAgentClient,
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
        """Run tool-calling turns until finish is accepted or the budget is exhausted.

        Args:
            request: Provider-neutral completion request.
            session: Host-owned construction state.
            journal: Durable construction trace.

        Returns:
            Response whose payload is the assembled artifact.

        Raises:
            AgentProviderError: If the provider fails, stalls, or the turn budget is exceeded.
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": TOOL_CALLING_INSTRUCTIONS},
            *build_messages(request),
        ]
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": definition.name,
                    "description": definition.description,
                    "parameters": definition.parameters_schema,
                },
            }
            for definition in session.tool_definitions()
        ]
        stall_guard = RepeatedFinishRejectionGuard(stall_after_repeats=self._stall_after_repeats)
        for turn in range(self._max_turns):
            started = time.perf_counter()
            completion = self._client.complete_turn(request, messages, tools=openai_tools)
            duration_ms = int((time.perf_counter() - started) * 1000)
            prompt_tokens, completion_tokens = _usage_tokens(completion)
            journal.record(
                JournalEvent(
                    event_type=JournalEventType.TURN_COMPLETED,
                    task_name=request.task_name,
                    details={
                        "turn": turn + 1,
                        "duration_ms": duration_ms,
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                    },
                )
            )
            tool_calls = _tool_calls(completion)
            messages.append(_assistant_message(completion))
            if not tool_calls:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Do not emit the artifact as a JSON message. "
                            "Call the provided add_*/replace_*/remove_* and finish_* tools instead."
                        ),
                    }
                )
                continue
            for call in tool_calls:
                result = _apply_call(session, journal, request.task_name, call)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": result.message,
                    }
                )
                if (
                    call["name"].startswith("finish_")
                    and not result.accepted
                    and stall_guard.record(result.message)
                ):
                    journal.record(
                        JournalEvent(
                            event_type=JournalEventType.TURN_BUDGET_EXCEEDED,
                            task_name=request.task_name,
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
                        context={
                            "task_name": request.task_name,
                            "message": result.message,
                        },
                    )
                if result.finished and result.accepted:
                    payload = session.assemble()
                    journal.record(
                        JournalEvent(
                            event_type=JournalEventType.ASSEMBLED,
                            task_name=request.task_name,
                            details={
                                "provider_name": self._client.provider_name,
                                "model_name": self._client.model_name,
                            },
                        )
                    )
                    return AgentResponse(
                        output_payload=payload,
                        confidence=(result.confidence if result.confidence is not None else 0.75),
                        raw_response=json.dumps(payload, ensure_ascii=False),
                        provider_name=self._client.provider_name,
                        model_name=self._client.model_name,
                    )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TURN_BUDGET_EXCEEDED,
                task_name=request.task_name,
                details={"max_turns": self._max_turns},
            )
        )
        raise AgentProviderError(
            "Agent tool-calling loop exceeded the configured turn budget",
            error_code="AGENT_PROVIDER_TOOL_LOOP_EXCEEDED",
            retryable=True,
            context={"task_name": request.task_name, "max_turns": self._max_turns},
        )


def _usage_tokens(completion: object) -> tuple[int | None, int | None]:
    usage = getattr(completion, "usage", None)
    if usage is None:
        return None, None
    prompt = getattr(usage, "prompt_tokens", None)
    completion_tokens = getattr(usage, "completion_tokens", None)
    return (
        prompt if isinstance(prompt, int) else None,
        completion_tokens if isinstance(completion_tokens, int) else None,
    )


def _apply_call(
    session: ArtifactConstructionSession,
    journal: ConstructionJournal,
    task_name: str,
    call: dict[str, str],
) -> ToolApplicationResult:
    name = call["name"]
    journal.record(
        JournalEvent(
            event_type=JournalEventType.TOOL_CALL_RECEIVED,
            task_name=task_name,
            tool_name=name,
        )
    )
    try:
        parsed = json.loads(call["arguments"] or "{}")
    except json.JSONDecodeError as error:
        result = ToolApplicationResult(
            accepted=False,
            message=f"Tool arguments are not valid JSON: {error.msg}",
        )
        _record_result(journal, task_name, name, result)
        return result
    if not isinstance(parsed, dict):
        result = ToolApplicationResult(
            accepted=False,
            message="Tool arguments must be a JSON object",
        )
        _record_result(journal, task_name, name, result)
        return result
    result = session.apply(name, cast(dict[str, JsonValue], parsed))
    _record_result(journal, task_name, name, result)
    return result


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


def _tool_calls(completion: object) -> list[dict[str, str]]:
    message = cast(Any, completion).choices[0].message
    raw_calls = getattr(message, "tool_calls", None) or []
    calls: list[dict[str, str]] = []
    for item in raw_calls:
        function = getattr(item, "function", None)
        if function is None:
            continue
        calls.append(
            {
                "id": str(getattr(item, "id", "")),
                "name": str(getattr(function, "name", "")),
                "arguments": str(getattr(function, "arguments", "") or "{}"),
            }
        )
    return calls


def _assistant_message(completion: object) -> dict[str, Any]:
    message = cast(Any, completion).choices[0].message
    payload: dict[str, Any] = {
        "role": "assistant",
        "content": getattr(message, "content", None),
    }
    tool_calls = getattr(message, "tool_calls", None)
    if not tool_calls:
        return payload
    serialized = []
    for item in tool_calls:
        function = getattr(item, "function", None)
        serialized.append(
            {
                "id": getattr(item, "id", ""),
                "type": "function",
                "function": {
                    "name": getattr(function, "name", ""),
                    "arguments": getattr(function, "arguments", "") or "{}",
                },
            }
        )
    payload["tool_calls"] = serialized
    return payload
