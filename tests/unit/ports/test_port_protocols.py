"""Tests for port protocol module definitions."""

from threatmodeler.ports.chat_completion_turn_client import ChatCompletionTurnClient
from threatmodeler.ports.copilot_tool_session_client import CopilotToolSessionClient


class TestPortProtocolImports:
    """Verify protocol-only port modules are importable."""

    def test_chat_completion_turn_client_protocol_is_importable(self) -> None:
        assert ChatCompletionTurnClient.__name__ == "ChatCompletionTurnClient"

    def test_copilot_tool_session_client_protocol_is_importable(self) -> None:
        assert CopilotToolSessionClient.__name__ == "CopilotToolSessionClient"
