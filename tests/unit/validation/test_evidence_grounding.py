"""Tests for deterministic evidence grounding."""

from pydantic import BaseModel
from threatmodeler.contracts.source import Evidence, SourceReference, SourceType
from threatmodeler.validation.evidence_grounding import EvidenceGroundingChecker, _snippets


class TestEvidenceGroundingModels:
    """Nested models kept off the test-module body."""

    class Item(BaseModel):
        evidence: list[Evidence]


class TestEvidenceGroundingCheckerPositive:
    """Verify grounded evidence is recognized."""

    def test_excerpt_present_in_source_is_grounded(self) -> None:
        item = TestEvidenceGroundingModels.Item(
            evidence=[
                Evidence(
                    summary="API accepts HTTPS",
                    source_references=[
                        SourceReference(
                            source_type=SourceType.CONFLUENCE_PAGE,
                            source_id="page-1",
                            location="https://example.invalid/page",
                            excerpt="The Payments API accepts HTTPS requests.",
                        )
                    ],
                )
            ]
        )
        checker = EvidenceGroundingChecker()
        assert checker.is_grounded(item, "The Payments API accepts HTTPS requests.") is True

    def test_paraphrased_excerpt_with_token_overlap_is_grounded(self) -> None:
        item = TestEvidenceGroundingModels.Item(
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
        assert checker.is_grounded(item, "The Payments API accepts HTTPS requests.") is True


class TestEvidenceGroundingCheckerNegative:
    """Verify missing evidence snippets are reported as ungrounded."""

    def test_unrelated_excerpt_is_not_grounded(self) -> None:
        item = TestEvidenceGroundingModels.Item(
            evidence=[
                Evidence(
                    summary="secret vault",
                    source_references=[
                        SourceReference(
                            source_type=SourceType.CONFLUENCE_PAGE,
                            source_id="page-1",
                            location="https://example.invalid/page",
                            excerpt="totally-absent-token",
                        )
                    ],
                )
            ]
        )
        checker = EvidenceGroundingChecker()
        assert checker.is_grounded(item, "The Payments API accepts HTTPS requests.") is False

    def test_unrelated_paraphrase_is_not_grounded(self) -> None:
        item = TestEvidenceGroundingModels.Item(
            evidence=[
                Evidence(
                    summary="database vault",
                    source_references=[
                        SourceReference(
                            source_type=SourceType.CONFLUENCE_PAGE,
                            source_id="page-1",
                            location="https://example.invalid/page",
                            excerpt="encrypted vault stores credentials offline",
                        )
                    ],
                )
            ]
        )
        checker = EvidenceGroundingChecker()
        assert checker.is_grounded(item, "The Payments API accepts HTTPS requests.") is False


    def test_evidence_snippets_ignore_non_string_entries(self) -> None:
        assert _snippets(123) == []
