"""Validation tests for typed agent attachment contracts."""

import base64
import hashlib

import pytest
from pydantic import ValidationError
from threatmodeler.contracts import (
    AttachmentContent,
    AttachmentKind,
    SourceReference,
    SourceType,
)


@pytest.fixture
def attachment_content() -> AttachmentContent:
    """Create a valid diagram attachment with verified content."""
    content = b"diagram-content"
    return AttachmentContent(
        attachment_id="attachment-1",
        filename="architecture.drawio",
        media_type="application/vnd.jgraph.mxfile",
        kind=AttachmentKind.DIAGRAM,
        content_base64=base64.b64encode(content).decode("ascii"),
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        source_reference=SourceReference(
            source_type=SourceType.DIAGRAM,
            source_id="attachment-1",
            location="https://example.test/architecture.drawio",
            excerpt="Architecture diagram attachment",
        ),
    )


class TestAttachmentContentPositive:
    """Verify valid attachment content remains portable and usable."""

    def test_attachment_serializes_and_decodes_without_data_loss(
        self,
        attachment_content: AttachmentContent,
    ) -> None:
        serialized = attachment_content.model_dump_json()
        restored = AttachmentContent.model_validate_json(serialized)

        assert restored == attachment_content
        assert restored.decoded_content() == b"diagram-content"


class TestAttachmentContentNegative:
    """Verify corrupt or inconsistent attachment content is rejected."""

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("content_base64", "not-base64!", "valid base64"),
            ("size_bytes", 1, "size does not match"),
            ("sha256", "0" * 64, "digest does not match"),
        ],
    )

    def test_attachment_rejects_invalid_integrity_metadata(
        self,
        field: str,
        value: object,
        message: str,
        attachment_content: AttachmentContent,
    ) -> None:
        payload = attachment_content.model_dump(mode="json")
        payload[field] = value

        with pytest.raises(ValidationError, match=message):
            AttachmentContent.model_validate(payload)
