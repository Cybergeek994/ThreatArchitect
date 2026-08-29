"""Registry of schema-bound prompt builders for downstream artifact tasks."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, SkipValidation

from threatmodeler.ports.prompt_builder import PromptBuilder


class ArtifactPromptBuilderRegistry(BaseModel):
    """Immutable registry of schema-bound prompt builders for artifact tasks."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    missing_information: Annotated[PromptBuilder, SkipValidation()]
    dfd: Annotated[PromptBuilder, SkipValidation()]
    attack_tree: Annotated[PromptBuilder, SkipValidation()]
    abuse_cases: Annotated[PromptBuilder, SkipValidation()]
    risk_register: Annotated[PromptBuilder, SkipValidation()]
    mitigation_plan: Annotated[PromptBuilder, SkipValidation()]
    security_requirements: Annotated[PromptBuilder, SkipValidation()]
    control_mapping: Annotated[PromptBuilder, SkipValidation()]
    executive_summary: Annotated[PromptBuilder, SkipValidation()]
    technical_report: Annotated[PromptBuilder, SkipValidation()]
