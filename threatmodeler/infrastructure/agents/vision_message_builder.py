"""Build chat-completion message content blocks from agent attachments."""

from typing import Any

from threatmodeler.contracts.integration import AgentRequest, AttachmentContent
from threatmodeler.shared.constants import VisionMediaType

_VISION_IMAGE_MEDIA_TYPES = frozenset(member.value for member in VisionMediaType)


def build_messages(request: AgentRequest) -> list[dict[str, Any]]:
    """Convert prompt messages and optional attachments into provider chat messages."""
    messages = [
        {"role": message.role.value, "content": message.content} for message in request.messages
    ]
    if not request.attachments:
        return messages
    return augment_user_message_with_attachments(messages, request.attachments)


def augment_user_message_with_attachments(
    messages: list[dict[str, Any]],
    attachments: list[AttachmentContent],
) -> list[dict[str, Any]]:
    """Append attachment blocks to the last user message, or create one."""
    content_blocks = attachment_content_blocks(attachments)
    if not content_blocks:
        return messages
    for index in range(len(messages) - 1, -1, -1):
        if messages[index]["role"] != "user":
            continue
        existing_content = messages[index]["content"]
        if isinstance(existing_content, str):
            messages[index]["content"] = [
                {"type": "text", "text": existing_content},
                *content_blocks,
            ]
        elif isinstance(existing_content, list):
            messages[index]["content"] = [*existing_content, *content_blocks]
        return messages
    messages.append({"role": "user", "content": content_blocks})
    return messages


def attachment_content_blocks(
    attachments: list[AttachmentContent],
) -> list[dict[str, str | dict[str, str]]]:
    """Convert validated attachments into OpenAI-compatible content blocks."""
    blocks: list[dict[str, str | dict[str, str]]] = []
    for attachment in attachments:
        if is_vision_image(attachment.media_type):
            blocks.append(
                {
                    "type": "image_url",
                    "image_url": {
                        "url": (f"data:{attachment.media_type};base64,{attachment.content_base64}"),
                    },
                }
            )
            continue
        if is_text_attachment(attachment.media_type):
            decoded = attachment.decoded_content().decode("utf-8", errors="replace")
            blocks.append(
                {
                    "type": "text",
                    "text": (
                        f"ATTACHMENT {attachment.filename} ({attachment.media_type}):\n{decoded}"
                    ),
                }
            )
            continue
        blocks.append(
            {
                "type": "text",
                "text": (
                    f"ATTACHMENT {attachment.filename} ({attachment.media_type}, "
                    f"{attachment.size_bytes} bytes) is included in the request manifest."
                ),
            }
        )
    return blocks


def is_vision_image(media_type: str) -> bool:
    """Return whether ``media_type`` is supported by vision image_url inputs."""
    return media_type.lower() in _VISION_IMAGE_MEDIA_TYPES


def is_text_attachment(media_type: str) -> bool:
    """Return whether ``media_type`` should be inlined as decoded text."""
    normalized = media_type.lower()
    return normalized.startswith("text/") or normalized in {
        "application/json",
        "application/xml",
        "image/svg+xml",
    }
