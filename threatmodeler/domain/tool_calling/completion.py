"""Serialize agent input payloads for deterministic evidence grounding."""

import json

from pydantic import JsonValue


def source_text_from_payload(payload: dict[str, JsonValue]) -> str:
    """Serialize an input payload into grounding corpus text.

    Args:
        payload: Agent input payload.

    Returns:
        JSON text suitable for substring evidence checks.
    """
    return json.dumps(payload, ensure_ascii=False)
