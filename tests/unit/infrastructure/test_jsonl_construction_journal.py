"""Tests for JSONL construction journals."""

from pathlib import Path
from unittest.mock import patch

import pytest
from threatmodeler.contracts.tool_calling import JournalEvent
from threatmodeler.domain.tool_calling.discarding_journal import DiscardingConstructionJournal
from threatmodeler.infrastructure.journal.jsonl_construction_journal import (
    JsonlConstructionJournalFactory,
    _atomic_json_write,
)
from threatmodeler.infrastructure.journal.null_construction_journal_factory import (
    NullConstructionJournalFactory,
)
from threatmodeler.shared.constants import JournalEventType


class TestJsonlConstructionJournalPositive:
    """Verify supported journal persistence behavior."""

    def test_record_writes_jsonl_manifest_and_trust_summary(self, tmp_path: Path) -> None:
        journal = JsonlConstructionJournalFactory().open(tmp_path)
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_REJECTED,
                task_name="extract_canonical_system_model",
                tool_name="add_actor",
                accepted=False,
                message="invalid",
                item_id="actor-1",
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_ACCEPTED,
                task_name="extract_canonical_system_model",
                tool_name="add_actor",
                accepted=True,
                message="accepted",
                item_id="actor-1",
                confidence=0.4,
                evidence_grounded=False,
                details={"provider_name": "openai", "model_name": "test-model"},
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TURN_COMPLETED,
                task_name="extract_canonical_system_model",
                details={
                    "turn": 1,
                    "duration_ms": 1200,
                    "prompt_tokens": 100,
                    "completion_tokens": 40,
                },
            )
        )
        journal.close()
        jsonl = (tmp_path / "extract_canonical_system_model.jsonl").read_text(encoding="utf-8")
        assert "tool_call_accepted" in jsonl
        assert "turn_completed" in jsonl
        assert (tmp_path / "manifest.json").is_file()
        assert (tmp_path / "trust-summary.json").is_file()
        manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
        assert '"turn_count": 1' in manifest
        assert '"last_duration_ms": 1200' in manifest
        assert '"rejected_then_corrected": 1' in manifest

    def test_finish_then_corrected_increments_after_finish_repair(self, tmp_path: Path) -> None:
        journal = JsonlConstructionJournalFactory().open(tmp_path)
        journal.record(
            JournalEvent(
                event_type=JournalEventType.FINISH_REJECTED,
                task_name="extract_canonical_system_model",
                tool_name="finish_canonical_system_model",
                accepted=False,
                message="missing external boundary",
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_ACCEPTED,
                task_name="extract_canonical_system_model",
                tool_name="add_trust_boundary",
                accepted=True,
                message="accepted",
                item_id="tb-external",
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.FINISH_ACCEPTED,
                task_name="extract_canonical_system_model",
                tool_name="finish_canonical_system_model",
                accepted=True,
                message="finished",
            )
        )
        journal.close()
        manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
        trust = (tmp_path / "trust-summary.json").read_text(encoding="utf-8")
        assert '"finish_then_corrected": 1' in manifest
        assert '"finish_then_corrected_count": 1' in trust
        assert '"finish_rejections": 1' in manifest

    def test_atomic_json_write_retries_permission_error(self, tmp_path: Path) -> None:
        target = tmp_path / "manifest.json"
        target.write_text("{}", encoding="utf-8")
        attempts = {"count": 0}
        original_replace = Path.replace

        def flaky_replace(self: Path, target_path: Path) -> Path:
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise PermissionError(13, "Permission denied", str(target_path))
            return original_replace(self, target_path)

        with (
            patch.object(Path, "replace", flaky_replace),
            patch(
                "threatmodeler.infrastructure.journal.jsonl_construction_journal.time.sleep",
                return_value=None,
            ),
        ):
            _atomic_json_write(target, {"ok": True})

        assert attempts["count"] == 3
        assert '"ok": true' in target.read_text(encoding="utf-8")
        assert list(tmp_path.glob(".manifest.json.*.tmp")) == []

    def test_atomic_json_write_raises_after_exhausted_retries(self, tmp_path: Path) -> None:
        target = tmp_path / "manifest.json"
        target.write_text("{}", encoding="utf-8")

        def always_locked(self: Path, target_path: Path) -> Path:
            raise PermissionError(13, "Permission denied", str(target_path))

        with (
            patch.object(Path, "replace", always_locked),
            patch(
                "threatmodeler.infrastructure.journal.jsonl_construction_journal.time.sleep",
                return_value=None,
            ),
            pytest.raises(PermissionError),
        ):
            _atomic_json_write(target, {"ok": True})

        assert list(tmp_path.glob(".manifest.json.*.tmp")) == []


class TestDiscardingConstructionJournal:
    """Verify no-op discarding journal behavior."""

    def test_discarding_journal_close_is_noop(self) -> None:
        journal = DiscardingConstructionJournal()
        assert journal.close() is None


class TestNullConstructionJournalFactory:
    """Verify null journal factory produces usable journals."""

    def test_null_construction_journal_factory_open(self, tmp_path: Path) -> None:
        journal = NullConstructionJournalFactory().open(tmp_path / "ignored")
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_ACCEPTED,
                task_name="demo",
                tool_name="add_item",
            )
        )
        journal.close()


class TestJsonlConstructionJournalBranchCoverage:
    """Verify JSONL journal edge-case event handling."""

    def test_jsonl_journal_records_turn_budget_exceeded(self, tmp_path: Path) -> None:
        journal = JsonlConstructionJournalFactory().open(tmp_path)
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TURN_BUDGET_EXCEEDED,
                task_name="extract_canonical_system_model",
                details={"max_turns": 3},
            )
        )
        journal.close()
        manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
        assert '"turn_budget_exceeded": 1' in manifest

    def test_jsonl_journal_token_branches(self, tmp_path: Path) -> None:
        journal = JsonlConstructionJournalFactory().open(tmp_path)
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_ACCEPTED,
                task_name="extract_canonical_system_model",
                tool_name="add_actor",
                accepted=True,
                message="accepted without id",
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_REJECTED,
                task_name="extract_canonical_system_model",
                tool_name="add_actor",
                accepted=False,
                message="rejected without id",
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.FINISH_ACCEPTED,
                task_name="extract_canonical_system_model",
                tool_name="finish_canonical_system_model",
                accepted=True,
                message="finished without prior rejection",
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_ACCEPTED,
                task_name="extract_canonical_system_model",
                tool_name="add_actor",
                accepted=True,
                message="accepted",
                item_id="actor-1",
                confidence=0.1,
                evidence_grounded=False,
                details={"provider_name": "openai", "model_name": "gpt-test"},
            )
        )
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TURN_COMPLETED,
                task_name="extract_canonical_system_model",
                details={
                    "duration_ms": "not-int",
                    "prompt_tokens": "bad",
                    "completion_tokens": None,
                },
            )
        )
        journal.close()
        trust = (tmp_path / "trust-summary.json").read_text(encoding="utf-8")
        manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
        assert '"ungrounded_evidence_percent": 100.0' in trust
        assert '"low_confidence_percent": 100.0' in trust
        assert '"finish_then_corrected": 0' in manifest

    def test_jsonl_journal_ignores_unhandled_event_types(self, tmp_path: Path) -> None:
        journal = JsonlConstructionJournalFactory().open(tmp_path)
        journal.record(
            JournalEvent(
                event_type=JournalEventType.TOOL_CALL_RECEIVED,
                task_name="extract_canonical_system_model",
                tool_name="add_actor",
            )
        )
        journal.close()
        manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
        assert '"accepted_tool_calls": 0' in manifest
