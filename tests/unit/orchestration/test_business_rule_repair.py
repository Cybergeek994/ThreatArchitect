"""Tests for canonical business-rule repair prompts."""

import pytest
from threatmodeler.contracts.prompts import PromptBuildRequest
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors import ConfigurationError
from threatmodeler.orchestration.prompts import (
    BusinessRuleRepairPromptBuilder,
    SecurePromptTemplate,
)
from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider


class TestBusinessRuleRepairPromptBuilderPositive:
    """Verify business-rule repair prompts encode violations and schema."""

    def test_builder_includes_violations_and_schema(self) -> None:
        schema_provider = PydanticSchemaProvider()
        schema = schema_provider.get_schema(CanonicalSystemModel)
        builder = BusinessRuleRepairPromptBuilder(SecurePromptTemplate())

        result = builder.build(
            PromptBuildRequest(
                task_name="repair_canonical_system_model_business_rules",
                input_payload={"document_id": "payments"},
                output_schema_name=CanonicalSystemModel.__name__,
                output_schema=schema,
                additional_context={
                    "original_task_name": "extract_canonical_system_model",
                    "invalid_output": {"application": {"id": "application"}},
                    "business_violations": [
                        "Component comp8 is not a member of any trust boundary"
                    ],
                    "source_context": {"document_id": "payments"},
                },
            )
        )

        assert result.expected_schema_name == "CanonicalSystemModel"
        assert "BUSINESS RULE REPAIR MODE" in result.messages[0].content
        assert "comp8" in result.messages[2].content
        assert "source_context" in result.messages[2].content


class TestBusinessRuleRepairPromptBuilderNegative:
    """Verify malformed repair context is rejected."""

    def test_builder_rejects_missing_context(self) -> None:
        schema_provider = PydanticSchemaProvider()
        builder = BusinessRuleRepairPromptBuilder(SecurePromptTemplate())

        with pytest.raises(ConfigurationError) as captured:
            builder.build(
                PromptBuildRequest(
                    task_name="repair_canonical_system_model_business_rules",
                    input_payload={},
                    output_schema_name=CanonicalSystemModel.__name__,
                    output_schema=schema_provider.get_schema(CanonicalSystemModel),
                    additional_context={"original_task_name": "extract"},
                )
            )

        assert captured.value.error_code == "BUSINESS_RULE_REPAIR_CONTEXT_INVALID"


    def test_business_rule_repair_omits_source_context_when_absent(self) -> None:
        from threatmodeler.contracts.prompts import PromptBuildRequest
        from threatmodeler.contracts.system_model import CanonicalSystemModel
        from threatmodeler.orchestration.prompts import (
            BusinessRuleRepairPromptBuilder,
            SecurePromptTemplate,
        )
        from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

        schema_provider = PydanticSchemaProvider()
        builder = BusinessRuleRepairPromptBuilder(SecurePromptTemplate())
        result = builder.build(
            PromptBuildRequest(
                task_name="repair_canonical_system_model_business_rules",
                input_payload={},
                output_schema_name=CanonicalSystemModel.__name__,
                output_schema=schema_provider.get_schema(CanonicalSystemModel),
                additional_context={
                    "original_task_name": "extract_canonical_system_model",
                    "invalid_output": {"application": {"id": "application"}},
                    "business_violations": ["missing boundary"],
                },
            )
        )
        assert "source_context" not in result.messages[2].content
