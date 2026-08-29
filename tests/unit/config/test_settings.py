"""Settings validation and environment-loading tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from pytest import MonkeyPatch
from threatmodeler.config.settings import Settings
from threatmodeler.shared.constants import ControlFramework, LogLevel


class TestSettingsPositive:
    """Verify supported inputs and successful behavior."""

    def test_valid_settings_load_from_prefixed_environment(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        output_dir = tmp_path / "artifacts"
        monkeypatch.setenv("THREATMODELER_AGENT_PROVIDER_NAME", "mock")
        monkeypatch.setenv("THREATMODELER_AGENT_MODEL_NAME", "fixture-model")
        monkeypatch.setenv("THREATMODELER_AGENT_PROVIDER_MAX_ATTEMPTS", "4")
        monkeypatch.setenv("THREATMODELER_AGENT_SCHEMA_REPAIR_ATTEMPTS", "2")
        monkeypatch.setenv("THREATMODELER_OUTPUT_DIR", str(output_dir))
        monkeypatch.setenv("THREATMODELER_LOG_LEVEL", "DEBUG")

        settings = Settings()

        assert settings.agent_provider_name == "mock"
        assert settings.agent_model_name == "fixture-model"
        assert settings.agent_provider_max_attempts == 4
        assert settings.agent_schema_repair_attempts == 2
        assert settings.output_dir == output_dir
        assert settings.log_level is LogLevel.DEBUG
        assert settings.control_framework is ControlFramework.OWASP_ASVS
        assert settings.fail_on_missing_information is False


class TestSettingsNegative:
    """Verify invalid or adversarial inputs are rejected."""

    def test_existing_file_is_rejected_as_output_directory(self, tmp_path: Path) -> None:
        output_file = tmp_path / "not-a-directory"
        output_file.write_text("occupied", encoding="utf-8")

        with pytest.raises(ValidationError, match="output_dir must identify a directory"):
            Settings(output_dir=output_file)

    def test_settings_reject_unsupported_control_framework(self) -> None:
        with pytest.raises(ValidationError, match="control_framework"):
            Settings.model_validate({"control_framework": "nist_800_53"})

    def test_settings_reject_blank_provider_name(self) -> None:
        with pytest.raises(ValidationError, match="agent_provider_name"):
            Settings(agent_provider_name="   ")

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [
            ("agent_provider_max_attempts", 0),
            ("agent_schema_repair_attempts", -1),
            ("agent_tool_calling_max_turns", 0),
        ],
    )

    def test_settings_reject_invalid_retry_limits(self, field_name: str, value: int) -> None:
        with pytest.raises(ValidationError, match=field_name):
            Settings.model_validate({field_name: value})


    def test_settings_accepts_control_framework_enum_value(self) -> None:
        settings = Settings(control_framework=ControlFramework.OWASP_ASVS)
        assert settings.control_framework is ControlFramework.OWASP_ASVS
