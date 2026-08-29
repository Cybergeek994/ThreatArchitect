"""Unit tests for OWASP-aligned STRIDE knowledge base."""

import pytest
from threatmodeler.contracts.artifacts.enums import StrideCategory
from threatmodeler.domain.stride_knowledge import (
    SecurityProperty,
    StrideKnowledgeBase,
    StrideSecurityMapping,
)


class TestStrideKnowledgeBasePositive:
    """Verify STRIDE-to-security-property mappings follow OWASP guidelines."""

    @pytest.mark.parametrize(
        ("category", "expected_property"),
        [
            (StrideCategory.SPOOFING, SecurityProperty.AUTHENTICATION),
            (StrideCategory.TAMPERING, SecurityProperty.INTEGRITY),
            (StrideCategory.REPUDIATION, SecurityProperty.NON_REPUDIATION),
            (StrideCategory.INFORMATION_DISCLOSURE, SecurityProperty.CONFIDENTIALITY),
            (StrideCategory.DENIAL_OF_SERVICE, SecurityProperty.AVAILABILITY),
            (StrideCategory.ELEVATION_OF_PRIVILEGE, SecurityProperty.AUTHORIZATION),
        ],
    )
    def test_stride_category_maps_to_correct_security_property(
        self,
        category: StrideCategory,
        expected_property: SecurityProperty,
    ) -> None:
        knowledge = StrideKnowledgeBase()

        mapping = knowledge.get_mapping(category)

        assert mapping.violated_property is expected_property

    def test_all_stride_categories_have_mappings(self) -> None:
        knowledge = StrideKnowledgeBase()

        mappings = knowledge.get_all_mappings()

        assert len(mappings) == len(StrideCategory)
        mapped_categories = {m.category for m in mappings}
        assert mapped_categories == set(StrideCategory)

    def test_every_mapping_has_mitigation_techniques(self) -> None:
        knowledge = StrideKnowledgeBase()

        for mapping in knowledge.get_all_mappings():
            assert len(mapping.mitigation_techniques) >= 3
            assert all(len(technique) > 0 for technique in mapping.mitigation_techniques)

    def test_format_threat_guidance_includes_all_categories(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_threat_guidance()

        assert "STRIDE-to-Security-Property Mapping" in guidance
        for category in StrideCategory:
            assert category.value.upper() in guidance

    def test_format_mitigation_guidance_includes_techniques(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_mitigation_guidance()

        assert "STRIDE Mitigation Techniques" in guidance
        assert "authentication" in guidance.lower()
        assert "encryption" in guidance.lower()
        assert "audit" in guidance.lower()

    def test_format_risk_assessment_guidance_includes_owasp_questions(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_risk_assessment_guidance()

        assert "OWASP Qualitative Risk Assessment" in guidance
        assert "exploitable_remotely" in guidance
        assert "requires_authentication" in guidance
        assert "exploit_automatable" in guidance
        assert "full_system_compromise" in guidance
        assert "admin_access_possible" in guidance
        assert "system_crash_possible" in guidance
        assert "sensitive_data_exposure" in guidance

    def test_format_risk_scoring_guidance_mirrors_owasp_rules(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_risk_scoring_guidance()

        assert "OWASP Risk Scoring" in guidance
        assert "full_system_compromise" in guidance
        assert "almost_certain" in guidance
        assert "external entry-point" in guidance

    def test_format_response_type_guidance_covers_all_categories(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_response_type_guidance()

        assert "OWASP Risk Response Types" in guidance
        for response in ("mitigate", "eliminate", "transfer", "accept"):
            assert response in guidance

    def test_format_threat_status_guidance_includes_partially_mitigated(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_threat_status_guidance()

        assert "partially_mitigated" in guidance
        assert "OWASP Threat Profiles" in guidance

    def test_format_control_type_guidance_covers_layered_defenses(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_control_type_guidance()

        assert "preventive" in guidance
        assert "detective" in guidance
        assert "corrective" in guidance
        assert "compensating" in guidance

    def test_format_asset_trust_guidance_references_trust_level_ids(self) -> None:
        knowledge = StrideKnowledgeBase()

        guidance = knowledge.format_asset_trust_guidance()

        assert "trust_level_ids" in guidance
        assert "trust_levels" in guidance


class TestStrideSecurityMappingImmutability:
    """Verify security mappings are immutable."""

    def test_mapping_is_frozen(self) -> None:
        mapping = StrideSecurityMapping(
            category=StrideCategory.SPOOFING,
            violated_property=SecurityProperty.AUTHENTICATION,
            description="Test",
            control_focus="Test focus",
            mitigation_techniques=("technique1",),
        )

        with pytest.raises(Exception):
            mapping.category = StrideCategory.TAMPERING  # type: ignore[misc]
