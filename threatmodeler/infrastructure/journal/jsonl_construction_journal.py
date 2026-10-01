"""JSONL construction journal with atomic manifest and trust-summary files."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from pydantic import JsonValue

from threatmodeler.contracts.tool_calling import JournalEvent
from threatmodeler.shared.constants import JournalEventType

_REPLACE_ATTEMPTS = 12
_REPLACE_INITIAL_DELAY_SECONDS = 0.05
_REPLACE_MAX_DELAY_SECONDS = 0.5


class JsonlConstructionJournal:
    """Append construction events to JSONL and rewrite aggregate files atomically."""

    def __init__(self, journal_directory: Path, *, low_confidence_threshold: float = 0.5) -> None:
        self._journal_directory = journal_directory
        self._low_confidence_threshold = low_confidence_threshold
        self._tasks: dict[str, _TaskStats] = {}
        self._journal_directory.mkdir(parents=True, exist_ok=True)

    def record(self, event: JournalEvent) -> None:
        """Append one event and refresh aggregate artifacts.

        Args:
            event: Validated construction event for the current task.
        """
        stats = self._tasks.setdefault(event.task_name, _TaskStats())
        stats.apply(event, self._low_confidence_threshold)
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            **event.model_dump(mode="json"),
        }
        jsonl_path = self._journal_directory / f"{event.task_name}.jsonl"
        with jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._write_aggregates()

    def close(self) -> None:
        """Rewrite manifest and trust-summary files from accumulated stats."""
        self._write_aggregates()

    def _write_aggregates(self) -> None:
        manifest = {
            "tasks": [
                {
                    "task_name": task_name,
                    "jsonl_file": f"{task_name}.jsonl",
                    **stats.manifest_row(),
                }
                for task_name, stats in self._tasks.items()
            ]
        }
        trust_summary = {
            "low_confidence_threshold": self._low_confidence_threshold,
            "tasks": {task_name: stats.trust_row() for task_name, stats in self._tasks.items()},
        }
        _atomic_json_write(self._journal_directory / "manifest.json", manifest)
        _atomic_json_write(self._journal_directory / "trust-summary.json", trust_summary)


class JsonlConstructionJournalFactory:
    """Create JSONL journals beneath a caller-supplied journal directory."""

    def __init__(self, *, low_confidence_threshold: float = 0.5) -> None:
        self._low_confidence_threshold = low_confidence_threshold

    def open(self, journal_directory: Path) -> JsonlConstructionJournal:
        """Open a journal that writes beneath ``journal_directory``.

        Args:
            journal_directory: Directory for JSONL traces and aggregate files.

        Returns:
            Journal bound to the supplied directory.
        """
        return JsonlConstructionJournal(
            journal_directory,
            low_confidence_threshold=self._low_confidence_threshold,
        )


class _TaskStats:
    def __init__(self) -> None:
        self.accepted_tool_calls = 0
        self.rejected_tool_calls = 0
        self.finish_rejections = 0
        self.turn_budget_exceeded = 0
        self.accepted_item_count = 0
        self.low_confidence_count = 0
        self.ungrounded_count = 0
        self.rejected_ids: set[str] = set()
        self.rejected_then_corrected = 0
        self.finish_then_corrected = 0
        self._pending_finish_correction = False
        self.provider_name: str | None = None
        self.model_name: str | None = None
        self.turn_count = 0
        self.total_duration_ms = 0
        self.last_duration_ms: int | None = None
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.last_prompt_tokens: int | None = None
        self.last_completion_tokens: int | None = None

    def apply(self, event: JournalEvent, low_confidence_threshold: float) -> None:
        details = event.details
        provider_name = details.get("provider_name")
        if isinstance(provider_name, str):
            self.provider_name = provider_name
        model_name = details.get("model_name")
        if isinstance(model_name, str):
            self.model_name = model_name
        if event.event_type is JournalEventType.TOOL_CALL_ACCEPTED:
            self.accepted_tool_calls += 1
            if event.item_id:
                self.accepted_item_count += 1
                if event.item_id in self.rejected_ids:
                    self.rejected_then_corrected += 1
            if event.confidence is not None and event.confidence < low_confidence_threshold:
                self.low_confidence_count += 1
            if event.evidence_grounded is False:
                self.ungrounded_count += 1
        elif event.event_type is JournalEventType.TOOL_CALL_REJECTED:
            self.rejected_tool_calls += 1
            if event.item_id:
                self.rejected_ids.add(event.item_id)
        elif event.event_type is JournalEventType.FINISH_REJECTED:
            self.finish_rejections += 1
            self.rejected_tool_calls += 1
            self._pending_finish_correction = True
        elif event.event_type is JournalEventType.FINISH_ACCEPTED:
            self.accepted_tool_calls += 1
            if self._pending_finish_correction:
                self.finish_then_corrected += 1
                self._pending_finish_correction = False
        elif event.event_type is JournalEventType.TURN_BUDGET_EXCEEDED:
            self.turn_budget_exceeded += 1
        elif event.event_type is JournalEventType.TURN_COMPLETED:
            self.turn_count += 1
            duration = details.get("duration_ms")
            if isinstance(duration, int):
                self.total_duration_ms += duration
                self.last_duration_ms = duration
            prompt_tokens = details.get("prompt_tokens")
            if isinstance(prompt_tokens, int):
                self.total_prompt_tokens += prompt_tokens
                self.last_prompt_tokens = prompt_tokens
            completion_tokens = details.get("completion_tokens")
            if isinstance(completion_tokens, int):
                self.total_completion_tokens += completion_tokens
                self.last_completion_tokens = completion_tokens

    def manifest_row(self) -> dict[str, JsonValue]:
        average_duration_ms = (
            round(self.total_duration_ms / self.turn_count) if self.turn_count else None
        )
        return {
            "provider_name": self.provider_name,
            "model_name": self.model_name,
            "accepted_tool_calls": self.accepted_tool_calls,
            "rejected_tool_calls": self.rejected_tool_calls,
            "finish_rejections": self.finish_rejections,
            "turn_budget_exceeded": self.turn_budget_exceeded,
            "rejected_then_corrected": self.rejected_then_corrected,
            "finish_then_corrected": self.finish_then_corrected,
            "turn_count": self.turn_count,
            "average_duration_ms": average_duration_ms,
            "last_duration_ms": self.last_duration_ms,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "last_prompt_tokens": self.last_prompt_tokens,
            "last_completion_tokens": self.last_completion_tokens,
        }

    def trust_row(self) -> dict[str, JsonValue]:
        item_count = self.accepted_item_count
        return {
            "accepted_item_count": item_count,
            "low_confidence_percent": _percent(self.low_confidence_count, item_count),
            "ungrounded_evidence_percent": _percent(self.ungrounded_count, item_count),
            "rejected_then_corrected_count": self.rejected_then_corrected,
            "finish_then_corrected_count": self.finish_then_corrected,
            "finish_rejection_count": self.finish_rejections,
        }


def _percent(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round((part / whole) * 100.0, 2)


def _atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            dir=directory,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _replace_with_retry(source: Path, destination: Path) -> None:
    """Replace ``destination`` with ``source``, retrying Windows lock races."""
    delay = _REPLACE_INITIAL_DELAY_SECONDS
    last_error: PermissionError | None = None
    for _ in range(_REPLACE_ATTEMPTS):
        try:
            source.replace(destination)
            return
        except PermissionError as error:
            last_error = error
            time.sleep(delay)
            delay = min(delay * 2, _REPLACE_MAX_DELAY_SECONDS)
    assert last_error is not None
    raise last_error
