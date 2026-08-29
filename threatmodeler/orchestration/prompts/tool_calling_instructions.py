"""Tool-calling instruction overlay derived from schema constraints."""

from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.orchestration.prompts.schema_guidance import SchemaDrivenConstraintCatalog

TOOL_CALLING_INSTRUCTIONS = " ".join(
    SchemaDrivenConstraintCatalog.for_tool_calling(CanonicalSystemModel).as_texts()
)
