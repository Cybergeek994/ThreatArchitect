"""Tests for CLI main entry-point composition."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr
from threatmodeler.cli.main import build_app
from threatmodeler.config.settings import Settings
from threatmodeler.contracts.integration import AgentResponse
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.tool_calling.completer import SchemaBoundToolCallingCompleter
from threatmodeler.infrastructure.agents.provider_factory import AgentProviderFactory
from typer.testing import CliRunner


class TestBuildAppComposition:
    """Cover CLI composition branches without injected provider overrides."""

    def test_build_app_uses_null_journal_when_disabled(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        parsed_path = tmp_path / "parsed-document.json"
        parsed_path.write_text(
            json.dumps(
                {
                    "document_id": "doc-1",
                    "title": "Demo",
                    "headings": [],
                    "paragraphs": [],
                    "raw_text": "Demo",
                    "source_reference": {
                        "source_type": "confluence_page",
                        "source_id": "doc-1",
                        "location": "file:///doc-1",
                        "excerpt": "Demo",
                    },
                    "media_type": "text/plain",
                    "attachments": [],
                    "diagram_topology": [],
                }
            ),
            encoding="utf-8",
        )
        app = build_app(
            Settings(agent_journal_enabled=False, output_dir=tmp_path / "out"),
            agent_provider_factory=lambda: agent_provider,
        )
        with patch.object(
            SchemaBoundToolCallingCompleter,
            "complete",
            return_value=AgentResponse(
                output_payload=canonical_system_model.model_dump(mode="json"),
                confidence=0.9,
                raw_response="{}",
                provider_name="openai",
                model_name="gpt-test",
            ),
        ):
            result = CliRunner().invoke(
                app,
                ["extract", "--input", str(parsed_path), "--output", str(tmp_path / "out")],
            )
        assert result.exit_code == 0

    def test_build_app_without_provider_override(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        agent_provider: Mock,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        parsed_path = tmp_path / "parsed-document.json"
        parsed_path.write_text(
            json.dumps(
                {
                    "document_id": "doc-1",
                    "title": "Demo",
                    "headings": [],
                    "paragraphs": [],
                    "raw_text": "Demo",
                    "source_reference": {
                        "source_type": "confluence_page",
                        "source_id": "doc-1",
                        "location": "file:///doc-1",
                        "excerpt": "Demo",
                    },
                    "media_type": "text/plain",
                    "attachments": [],
                    "diagram_topology": [],
                }
            ),
            encoding="utf-8",
        )
        container = Mock(agent_provider=agent_provider, document_parser=Mock())
        tool_calls: list[bool] = []

        def track_tool_calling_provider(self: AgentProviderFactory) -> Mock:
            tool_calls.append(True)
            return agent_provider

        with (
            patch("threatmodeler.cli.main.AppContainerFactory") as container_factory,
            patch.object(
                AgentProviderFactory,
                "create_tool_calling_provider",
                track_tool_calling_provider,
            ),
            patch.object(
                SchemaBoundToolCallingCompleter,
                "complete",
                return_value=AgentResponse(
                    output_payload=canonical_system_model.model_dump(mode="json"),
                    confidence=0.9,
                    raw_response="{}",
                    provider_name="openai",
                    model_name="gpt-test",
                ),
            ),
        ):
            container_factory.return_value.create.return_value = container
            app = build_app(
                Settings(
                    openai_api_key=SecretStr("sk-test"),
                    agent_journal_enabled=False,
                    output_dir=tmp_path / "out",
                )
            )
            result = CliRunner().invoke(
                app,
                ["extract", "--input", str(parsed_path), "--output", str(tmp_path / "out")],
            )
        assert result.exit_code == 0
        assert tool_calls == [True]