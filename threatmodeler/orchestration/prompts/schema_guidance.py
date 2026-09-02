"""Schema-driven prompt constraints and reference-field discovery.

Derives generic extraction/generation guidance from Pydantic models so prompts
and validators stay aligned without naming document sections or entity types.
"""

from __future__ import annotations

from typing import get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field
from pydantic.fields import FieldInfo

from threatmodeler.contracts.artifacts.enums import ProvenanceConstraintKey
from threatmodeler.contracts.reference_graph import (
    ReferenceGraphEdgeSpec,
    ReferenceGraphNodeSpec,
    ReferenceGraphPolicy,
    default_reference_graph_policy,
)
from threatmodeler.contracts.schema_introspection import (
    discover_reference_fields,
    reference_fields_for_models,
)


class PromptConstraint(BaseModel):
    """One schema-neutral instruction bullet for prompt builders."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(strict=True, min_length=1)
    text: str = Field(strict=True, min_length=1)


class ValidationAlignedConstraint(BaseModel):
    """Maps a business-rule key to a schema-neutral prompt constraint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_key: str = Field(strict=True, min_length=1)
    constraint: PromptConstraint


class SchemaDrivenConstraintCatalog(BaseModel):
    """Generic constraints derived from an output model and shared policies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    constraints: tuple[PromptConstraint, ...] = Field(default_factory=tuple)

    def as_texts(self) -> tuple[str, ...]:
        """Return constraint texts in catalog order."""
        return tuple(item.text for item in self.constraints)

    def render_bullet_block(self) -> str:
        """Render constraints as a newline-joined bullet list."""
        return "\n".join(f"- {text}" for text in self.as_texts())

    @classmethod
    def for_extraction(cls, output_model: type[BaseModel]) -> SchemaDrivenConstraintCatalog:
        """Build extraction constraints from model structure and shared policies."""
        constraints = (
            *build_source_complete_constraints(output_model),
            *build_reference_integrity_constraints(output_model),
            *build_enum_constraints(output_model),
            *build_finish_order_constraints(output_model),
            *extraction_validation_aligned_constraints(),
        )
        return cls(constraints=_dedupe_by_key(constraints))

    @classmethod
    def for_generation(cls, output_model: type[BaseModel]) -> SchemaDrivenConstraintCatalog:
        """Build generation constraints from model structure and shared policies."""
        constraints = (
            *build_reference_integrity_constraints(output_model),
            *build_enum_constraints(output_model),
            *generation_traceability_constraints(),
        )
        return cls(constraints=_dedupe_by_key(constraints))

    @classmethod
    def for_tool_calling(cls, output_model: type[BaseModel]) -> SchemaDrivenConstraintCatalog:
        """Build tool-calling overlay constraints for incremental construction."""
        constraints = (
            PromptConstraint(
                key="tool_calling_incremental",
                text=(
                    "Construct the artifact incrementally by calling the provided tools. "
                    "Call one add_* tool for each list item. Prefer calling as many add_* "
                    "tools as possible in a single turn across every category you already "
                    "understand, rather than emitting only one category per turn."
                ),
            ),
            PromptConstraint(
                key="tool_calling_batch",
                text=(
                    "You have limited turns; batch aggressively to complete construction "
                    "in 3-5 turns."
                ),
            ),
            PromptConstraint(
                key="tool_calling_mutations",
                text=(
                    "Use replace_* to correct an existing item by id, and remove_* to "
                    "discard a mistaken item. Call the finish_* tool with the remaining "
                    "scalar and nested object fields when the artifact is complete."
                ),
            ),
            PromptConstraint(
                key="tool_calling_no_oneshot",
                text="Do not emit the full JSON object as a single assistant message.",
            ),
            *build_source_complete_constraints(output_model),
            *build_finish_order_constraints(output_model),
            *build_reference_integrity_constraints(output_model),
            *extraction_validation_aligned_constraints(),
        )
        return cls(constraints=_dedupe_by_key(constraints))

    @classmethod
    def for_business_repair(cls, output_model: type[BaseModel]) -> SchemaDrivenConstraintCatalog:
        """Build repair constraints aligned with business validation rules."""
        constraints = (
            PromptConstraint(
                key="repair_scope",
                text=(
                    "Repair only reference integrity and coverage. Do not invent entities "
                    "absent from the invalid output. Prefer reconnecting existing ids over "
                    "creating new ones. Preserve evidence and confidence where possible."
                ),
            ),
            *build_reference_integrity_constraints(output_model),
            *extraction_validation_aligned_constraints(),
        )
        return cls(constraints=_dedupe_by_key(constraints))


def discover_list_fields(model: type[BaseModel]) -> tuple[str, ...]:
    """Return top-level list field names on ``model`` (excluding host-owned fields)."""
    names: list[str] = []
    for name, field_info in model.model_fields.items():
        if _is_host_owned(field_info):
            continue
        annotation = field_info.annotation
        if get_origin(annotation) is list:
            names.append(name)
    return tuple(names)


def build_source_complete_constraints(model: type[BaseModel]) -> tuple[PromptConstraint, ...]:
    """Build constraints requiring every source row to populate schema list fields."""
    list_fields = discover_list_fields(model)
    list_label = ", ".join(f"`{name}`" for name in list_fields) if list_fields else "list fields"
    return (
        PromptConstraint(
            key="source_complete",
            text=(
                "Source-complete extraction: for every top-level list field in the "
                f"output schema ({list_label}), materialize one item per corresponding "
                "source table row or section. Do not skip a source row because the same "
                "label appears elsewhere in the document. When the same label maps to "
                "multiple list fields, extract into each list with distinct ids."
            ),
        ),
    )


def build_reference_integrity_constraints(
    model: type[BaseModel],
) -> tuple[PromptConstraint, ...]:
    """Build constraints requiring ``*_id`` / ``*_ids`` values to resolve."""
    refs = discover_reference_fields(model)
    if not refs:
        return (
            PromptConstraint(
                key="id_uniqueness",
                text=(
                    "Ids must be unique across all list fields and scalar id fields "
                    "in the output schema."
                ),
            ),
        )
    field_names = sorted({descriptor.field_name for descriptor in refs})
    fields_label = ", ".join(f"`{name}`" for name in field_names)
    return (
        PromptConstraint(
            key="id_uniqueness",
            text=(
                "Ids must be unique across all list fields and scalar id fields "
                "in the output schema."
            ),
        ),
        PromptConstraint(
            key="reference_integrity",
            text=(
                "Every field whose name ends with `_id` or `_ids` "
                f"({fields_label}) must resolve to an id declared in a list field "
                "or scalar id field within the same output model or supplied input payload."
            ),
        ),
    )


def build_enum_constraints(model: type[BaseModel]) -> tuple[PromptConstraint, ...]:
    """Build a constraint requiring enum-typed fields to use schema enum values."""
    del model
    return (
        PromptConstraint(
            key="enum_values",
            text=(
                "Typed enum fields must use only the enum values defined by the "
                "exact output schema."
            ),
        ),
    )


def build_finish_order_constraints(model: type[BaseModel]) -> tuple[PromptConstraint, ...]:
    """Build constraints requiring referenced entities to exist before references."""
    list_fields = discover_list_fields(model)
    if not list_fields:
        return ()
    return (
        PromptConstraint(
            key="reference_order",
            text=(
                "Before setting any field whose name ends with `_id` or `_ids`, "
                "ensure the referenced id already exists via the appropriate add_* tool. "
                "Prefer emitting independent list-field items first, then items that "
                "reference those ids."
            ),
        ),
    )


def extraction_validation_aligned_constraints() -> tuple[PromptConstraint, ...]:
    """Return schema-neutral constraints mirroring production business rules."""
    return tuple(item.constraint for item in VALIDATION_ALIGNED_CONSTRAINTS)


def build_coverage_constraints() -> tuple[PromptConstraint, ...]:
    """Build domain-agnostic coverage constraints for threat identification."""
    return (
        PromptConstraint(
            key="coverage_entry_points",
            text=(
                "Before finishing, review each item in the input "
                "`system_model.entry_points` list for applicable STRIDE threats."
            ),
        ),
        PromptConstraint(
            key="coverage_data_flows",
            text=(
                "Before finishing, review each item in the input "
                "`system_model.data_flows` list, especially flows with "
                "`trust_boundary_crossed=true`, for applicable STRIDE threats."
            ),
        ),
        PromptConstraint(
            key="coverage_external_dependencies",
            text=(
                "Before finishing, review each item in the input "
                "`system_model.external_dependencies` list for applicable "
                "STRIDE threats."
            ),
        ),
        PromptConstraint(
            key="coverage_exit_points",
            text=(
                "Before finishing, review each item in the input "
                "`system_model.exit_points` list for applicable STRIDE threats."
            ),
        ),
        PromptConstraint(
            key="coverage_affected_components",
            text=(
                "Populate `affected_component_ids` on each threat with component "
                "ids that could be impacted (blast radius) when those ids are "
                "present in the input."
            ),
        ),
        PromptConstraint(
            key="coverage_partial_mitigation",
            text=(
                "Use `partially_mitigated` in `status` when some but not all "
                "countermeasures are evidenced for a threat."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.RATIONALE.value,
            text=(
                "Every threat must populate `provenance.rationale` with a non-empty "
                "explanation of why the threat was identified from the input."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.ATTACK_PATH.value,
            text=(
                "Every threat must populate `provenance.attack_path` with ordered "
                "graph node names from the cited attack path."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.ATTACK_PATH_ID.value,
            text=(
                "Every threat must populate `provenance.attack_path_id` with an id "
                "from `architecture_graph.attack_paths` in the input payload."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.ENTRY_POINTS.value,
            text=(
                "Every threat that targets a component of an external or partner "
                "entry point must set `provenance.entry_point_id` to that entry "
                "point's id."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.TRUST_BOUNDARY.value,
            text=(
                "Every threat linked to a data flow with `trust_boundary_crossed=true` "
                "must set `provenance.trust_boundary_id` to a known trust-boundary id "
                "from the input."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.ACTOR.value,
            text=(
                "When the linked entry point has a non-null `actor_id`, the threat "
                "must set `provenance.actor_id` to that same id."
            ),
        ),
        PromptConstraint(
            key=ProvenanceConstraintKey.EVIDENCE.value,
            text=(
                "Every threat must include non-empty `evidence` citing source "
                "excerpts already present in the input payload."
            ),
        ),
    )


def generation_traceability_constraints() -> tuple[PromptConstraint, ...]:
    """Return generic generation constraints for threat-linked artifacts."""
    return (
        PromptConstraint(
            key="generation_traceability",
            text=(
                "Every generated item must satisfy schema traceability: populate at "
                "least one `*_id` / `*_ids` reference field or non-empty evidence."
            ),
        ),
        PromptConstraint(
            key="generation_required_refs",
            text=(
                "Every `*_ids` list with min_length=1 in the schema must be populated "
                "from ids present in the input payload."
            ),
        ),
        PromptConstraint(
            key="generation_category_skip",
            text=(
                "Skip an optional enum category only when the input payload lacks "
                "applicable elements that support that category."
            ),
        ),
        PromptConstraint(
            key="generation_id_format",
            text=(
                "Use semantic lowercase kebab-case ids as described by the schema "
                "`id` field. Never use generic sequential ids."
            ),
        ),
    )


VALIDATION_ALIGNED_CONSTRAINTS: tuple[ValidationAlignedConstraint, ...] = (
    ValidationAlignedConstraint(
        rule_key="UniqueEntityIdsRule",
        constraint=PromptConstraint(
            key="unique_entity_ids",
            text=(
                "All `id` fields across the output model must be unique "
                "(list items and scalar id fields alike)."
            ),
        ),
    ),
    ValidationAlignedConstraint(
        rule_key="ExternalEntryPointAuthRule",
        constraint=PromptConstraint(
            key="external_entry_auth",
            text=(
                "Items with `exposure=external` must not use placeholder "
                "`authentication_method` values (unknown, n/a, none, placeholder, tbd)."
            ),
        ),
    ),
    ValidationAlignedConstraint(
        rule_key="BoundaryCrossingFlowRule",
        constraint=PromptConstraint(
            key="boundary_crossing_encryption",
            text=(
                "Items with `trust_boundary_crossed=true` must have "
                "`encrypted_in_transit=true`."
            ),
        ),
    ),
    ValidationAlignedConstraint(
        rule_key="ExternalExposureCoverageRule",
        constraint=PromptConstraint(
            key="external_exposure_coverage",
            text=(
                "When any item has `exposure=external`, at least one "
                "`trust_boundaries` item must have `boundary_type` in "
                "{network, external}."
            ),
        ),
    ),
    ValidationAlignedConstraint(
        rule_key="ExternalEntryPointBoundaryRule",
        constraint=PromptConstraint(
            key="external_entry_boundary_membership",
            text=(
                "Ids referenced by items with `exposure=external` must appear in a "
                "`trust_boundaries` item whose `boundary_type` is external. A component "
                "may belong to multiple trust boundaries; extract every "
                "source-documented membership, including overlapping ones."
            ),
        ),
    ),
    ValidationAlignedConstraint(
        rule_key="TrustBoundaryMembershipRule",
        constraint=PromptConstraint(
            key="external_membership",
            text=(
                "Prefer source-documented trust boundaries. Ids referenced by "
                "`exposure=external` items must appear in at least one "
                "`trust_boundaries.component_ids` list; for other items without a "
                "documented boundary, record the gap in `missing_information`."
            ),
        ),
    ),
    ValidationAlignedConstraint(
        rule_key="UnreferencedExtractedItemRule",
        constraint=PromptConstraint(
            key="unreferenced_items",
            text=(
                "Every item in a reference-graph list field (`components`, "
                "`data_stores`, `actors`) must either appear in at least one "
                "configured reference edge, or be cited by its `id` in "
                "`missing_information` as an unresolved linkage gap. Prefer "
                "linking when the source documents the relationship; otherwise "
                "record an explicit gap that includes the item id."
            ),
        ),
    ),
)


def _dedupe_by_key(constraints: tuple[PromptConstraint, ...]) -> tuple[PromptConstraint, ...]:
    seen: set[str] = set()
    ordered: list[PromptConstraint] = []
    for constraint in constraints:
        if constraint.key in seen:
            continue
        seen.add(constraint.key)
        ordered.append(constraint)
    return tuple(ordered)


def _is_host_owned(field_info: FieldInfo) -> bool:
    extra = field_info.json_schema_extra
    return isinstance(extra, dict) and extra.get("x_host_owned") is True
