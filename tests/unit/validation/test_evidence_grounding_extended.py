"""Extended tests for deterministic evidence grounding."""

import pytest
from pydantic import BaseModel
from threatmodeler.contracts.source import Evidence, SourceReference, SourceType
from threatmodeler.validation.evidence_grounding import EvidenceGroundingChecker


class TestEvidenceGroundingExtendedModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        evidence: list[Evidence | str]


class TestEvidenceGroundingCheckerExtendedNegative:
    """Verify additional ungrounded and invalid-input paths."""

    def test_invalid_overlap_ratio_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="overlap_ratio"):
            EvidenceGroundingChecker(overlap_ratio=0.0)

        with pytest.raises(ValueError, match="overlap_ratio"):
            EvidenceGroundingChecker(overlap_ratio=1.5)

    def test_empty_corpus_is_not_grounded(self) -> None:
        item = TestEvidenceGroundingExtendedModels.Item(
            evidence=[
                Evidence(
                    summary="Payments API HTTPS",
                    source_references=[
                        SourceReference(
                            source_type=SourceType.CONFLUENCE_PAGE,
                            source_id="page-1",
                            location="https://example.invalid/page",
                            excerpt="Payments API handles HTTPS traffic",
                        )
                    ],
                )
            ]
        )
        checker = EvidenceGroundingChecker()
        assert checker.is_grounded(item, "   ") is False

    def test_string_evidence_entry_can_be_grounded(self) -> None:
        item = TestEvidenceGroundingExtendedModels.Item(
            evidence=["Payments API accepts HTTPS requests"]
        )
        checker = EvidenceGroundingChecker()
        assert checker.is_grounded(item, "The Payments API accepts HTTPS requests.") is True

    def test_snippet_with_no_tokens_is_not_grounded(self) -> None:
        item = TestEvidenceGroundingExtendedModels.Item(
            evidence=[
                Evidence(
                    summary="!!!",
                    source_references=[
                        SourceReference(
                            source_type=SourceType.CONFLUENCE_PAGE,
                            source_id="page-1",
                            location="https://example.invalid/page",
                            excerpt="!!!",
                        )
                    ],
                )
            ]
        )
        checker = EvidenceGroundingChecker()
        assert checker.is_grounded(item, "The Payments API accepts HTTPS requests.") is False
