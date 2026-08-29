"""Canonical system model business validation rules."""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import JsonValue

from threatmodeler.contracts.system_model import (
    CanonicalSystemModel,
    ExposureType,
    TrustBoundaryType,
)
from threatmodeler.errors.application import AgentSchemaValidationError
from threatmodeler.contracts.reference_graph import (
    ReferenceGraphPolicy,
    default_reference_graph_policy,
)
from threatmodeler.ports.schema_validator import SystemModelValidationRule
from threatmodeler.shared.constants import PlaceholderAuthentication


class UniqueEntityIdsRule:
    """Require identifiers to be unique across canonical extracted entities.

    List-item collisions are also rejected at add_* time. application.id and
    deployment.id remain finish-only because those fields have no add_* tools.
    """

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find identifiers duplicated across canonical entities.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violation for every duplicated identifier.
        """
        ids = [
            model.application.id,
            model.deployment.id,
            *(item.id for item in model.actors),
            *(item.id for item in model.components),
            *(item.id for item in model.data_stores),
            *(item.id for item in model.data_flows),
            *(item.id for item in model.trust_boundaries),
            *(item.id for item in model.entry_points),
        ]
        duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
        return [f"Duplicate entity id: {item_id}" for item_id in duplicates]


class ReferenceIntegrityRule:
    """Require component and actor references to point to extracted entities."""

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find dangling flow, boundary, entry-point, and actor references.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for unresolved architecture references.
        """
        violations: list[str] = []
        component_ids = {component.id for component in model.components}
        store_ids = {store.id for store in model.data_stores}
        actor_ids = {actor.id for actor in model.actors}
        boundary_member_ids = component_ids | store_ids
        flow_target_ids = boundary_member_ids
        for flow in model.data_flows:
            if flow.source_component_id not in flow_target_ids:
                violations.append(
                    f"Data flow {flow.id} has unknown source {flow.source_component_id}"
                )
            if flow.destination_component_id not in flow_target_ids:
                violations.append(
                    f"Data flow {flow.id} has unknown destination {flow.destination_component_id}"
                )
            for actor_id in flow.actor_ids:
                if actor_id not in actor_ids:
                    violations.append(f"Data flow {flow.id} references unknown actor {actor_id}")
        for boundary in model.trust_boundaries:
            for member_id in boundary.component_ids:
                if member_id not in boundary_member_ids:
                    violations.append(
                        f"Trust boundary {boundary.id} contains unknown member {member_id}"
                    )
        for entry_point in model.entry_points:
            if entry_point.component_id not in component_ids:
                violations.append(
                    f"Entry point {entry_point.id} targets unknown component "
                    f"{entry_point.component_id}"
                )
            if entry_point.actor_id is not None and entry_point.actor_id not in actor_ids:
                violations.append(
                    f"Entry point {entry_point.id} references unknown actor {entry_point.actor_id}"
                )
        return violations


class UnreferencedExtractedItemRule:
    """Require every configured list item to be linked or cited as a gap.

    Finish-only: unreferenced items are only knowable after all linkages exist.
    An item may remain unlinked when ``missing_information`` cites its ``id`` as
    an unresolved linkage gap. Driven by ``ReferenceGraphPolicy`` (Pydantic).
    """

    def __init__(self, policy: ReferenceGraphPolicy | None = None) -> None:
        self._policy = policy or default_reference_graph_policy()

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find list items that are neither referenced nor cited as gaps.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for unreferenced, ungapped items.
        """
        gap_text = "\n".join(model.missing_information)
        violations: list[str] = []
        for node in self._policy.nodes:
            items = getattr(model, node.list_field, [])
            referenced = _collect_referenced_ids(model, node.edges)
            for item in items:
                item_id = getattr(item, "id", None)
                if not isinstance(item_id, str) or not item_id:
                    continue
                if item_id in referenced:
                    continue
                if _id_cited_in_gap_text(item_id, gap_text):
                    continue
                violations.append(
                    f"Item {item_id} in `{node.list_field}` is not referenced by any "
                    "configured reference-graph edge and is not cited by id in "
                    "`missing_information`. Link it via a reference edge or add a gap "
                    f"statement that cites id `{item_id}`."
                )
        return violations


class TrustBoundaryCrossingConsistencyRule:
    """Verify ``trust_boundary_crossed`` matches trust-boundary membership.

    Finish-only: depends on assembled flows and trust-boundary membership.
    """

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find flows whose crossing flag disagrees with membership sets.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for inconsistent crossing flags.
        """
        membership: dict[str, set[str]] = defaultdict(set)
        for boundary in model.trust_boundaries:
            for member_id in boundary.component_ids:
                membership[member_id].add(boundary.id)

        violations: list[str] = []
        for flow in model.data_flows:
            source_boundaries = membership.get(flow.source_component_id, set())
            dest_boundaries = membership.get(flow.destination_component_id, set())
            actually_crosses = bool(source_boundaries or dest_boundaries) and not (
                source_boundaries & dest_boundaries
            )
            # Unplaced endpoints: if either side has no membership, treat as crossing
            # only when the other side has membership (different containment).
            if not source_boundaries and not dest_boundaries:
                actually_crosses = False
            elif not source_boundaries or not dest_boundaries:
                actually_crosses = True

            if flow.trust_boundary_crossed and not actually_crosses:
                violations.append(
                    f"Data flow {flow.id} has trust_boundary_crossed=true but source and "
                    "destination share trust-boundary membership (or both are unplaced)."
                )
            elif not flow.trust_boundary_crossed and actually_crosses:
                violations.append(
                    f"Data flow {flow.id} has trust_boundary_crossed=false but source and "
                    "destination do not share trust-boundary membership."
                )
        return violations


class CanonicalSystemModelReferenceChecker:
    """Validate reference integrity incrementally during add_* tool calls."""

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        existing_lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        """Return violations for unresolved references in one candidate item.

        Args:
            list_field: Target list field for the add_* tool (e.g. ``data_flows``).
            payload: Parsed item payload about to be appended.
            existing_lists: Accumulated list payloads accepted so far.

        Returns:
            Human-readable violations. An empty list means the item may be accepted.
        """
        component_ids = _entity_ids(existing_lists.get("components", []))
        store_ids = _entity_ids(existing_lists.get("data_stores", []))
        actor_ids = _entity_ids(existing_lists.get("actors", []))
        flow_target_ids = component_ids | store_ids
        known_targets = _format_known_ids(flow_target_ids)
        known_actors = _format_known_ids(actor_ids)
        item_id = payload.get("id")
        item_label = item_id if isinstance(item_id, str) else list_field
        violations: list[str] = []
        if list_field == "data_flows":
            violations.extend(
                _check_flow_endpoint(
                    payload.get("source_component_id"),
                    role="source",
                    flow_label=item_label,
                    valid_ids=flow_target_ids,
                    known_targets=known_targets,
                )
            )
            violations.extend(
                _check_flow_endpoint(
                    payload.get("destination_component_id"),
                    role="destination",
                    flow_label=item_label,
                    valid_ids=flow_target_ids,
                    known_targets=known_targets,
                )
            )
            violations.extend(
                _check_actor_ids(
                    payload.get("actor_ids"),
                    item_label=f"Data flow {item_label}",
                    actor_ids=actor_ids,
                    known_actors=known_actors,
                )
            )
        elif list_field == "trust_boundaries":
            raw_members = payload.get("component_ids")
            if isinstance(raw_members, list):
                for member_id in raw_members:
                    if isinstance(member_id, str) and member_id not in flow_target_ids:
                        violations.append(
                            f"Trust boundary {item_label} contains unknown member {member_id}. "
                            f"Known component/data_store ids: {known_targets} "
                            "(add missing ones with add_component/add_data_store first)."
                        )
        elif list_field == "entry_points":
            component_id = payload.get("component_id")
            if isinstance(component_id, str) and component_id not in component_ids:
                known_components = _format_known_ids(component_ids)
                violations.append(
                    f"Entry point {item_label} targets unknown component {component_id}. "
                    f"Known component ids: {known_components} "
                    "(add missing ones with add_component first)."
                )
            actor_id = payload.get("actor_id")
            if isinstance(actor_id, str) and actor_id and actor_id not in actor_ids:
                violations.append(
                    f"Entry point {item_label} references unknown actor {actor_id}. "
                    f"Known actor ids: {known_actors} "
                    "(add missing ones with add_actor first)."
                )
            violations.extend(_external_entry_point_auth_violations(payload, item_label))
        return violations


class ExternalEntryPointAuthRule:
    """Require external entry points to declare a concrete authentication method."""

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find external entry points that still use placeholder authentication.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for placeholder external authentication.
        """
        violations: list[str] = []
        for entry_point in model.entry_points:
            violations.extend(
                _external_entry_point_auth_violations(
                    {
                        "id": entry_point.id,
                        "exposure": entry_point.exposure.value,
                        "authentication_method": entry_point.authentication_method,
                    },
                    entry_point.id,
                )
            )
        return violations


class TrustBoundaryMembershipRule:
    """Require externally exposed components to belong to at least one trust boundary.

    Hybrid policy: internal components may remain unplaced when the source document
    does not define a boundary for them (record that gap in missing_information).
    Finish-only: membership cannot be checked until entry points and boundaries exist.
    """

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find externally exposed components omitted from every trust boundary.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for uncovered external components.
        """
        external_component_ids = {
            entry_point.component_id
            for entry_point in model.entry_points
            if entry_point.exposure is ExposureType.EXTERNAL
        }
        if not external_component_ids:
            return []
        bounded = {
            component_id
            for boundary in model.trust_boundaries
            for component_id in boundary.component_ids
        }
        uncovered = sorted(external_component_ids - bounded)
        return [
            f"Externally exposed component {component_id} is not a member of any trust boundary"
            for component_id in uncovered
        ]


class BoundaryCrossingFlowRule:
    """Require boundary-crossing data flows to be encrypted in transit.

    Finish-only: encryption flags are validated together with the assembled model.
    Repair after rejection uses replace_data_flow.
    """

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find unencrypted flows that cross a trust boundary.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for unencrypted boundary-crossing flows.
        """
        return [
            f"Data flow {flow.id} crosses a trust boundary without encryption in transit"
            for flow in model.data_flows
            if flow.trust_boundary_crossed and not flow.encrypted_in_transit
        ]


class ExternalEntryPointBoundaryRule:
    """Require externally exposed components to sit in an external trust boundary.

    Membership check: ids referenced by ``exposure=external`` items must appear
    in a ``trust_boundaries`` item with ``boundary_type=external``. Stricter than
    ``ExternalExposureCoverageRule``, which only requires that a network or
    external boundary exists somewhere in the model.

    Finish-only: depends on the full set of entry points and trust boundaries.
    """

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find external entry points whose components lack an external boundary.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations for uncovered external entry points.
        """
        external_component_ids = {
            entry_point.component_id
            for entry_point in model.entry_points
            if entry_point.exposure is ExposureType.EXTERNAL
        }
        if not external_component_ids:
            return []
        members_of_external_boundary = {
            component_id
            for boundary in model.trust_boundaries
            if boundary.boundary_type is TrustBoundaryType.EXTERNAL
            for component_id in boundary.component_ids
        }
        uncovered = sorted(external_component_ids - members_of_external_boundary)
        return [
            f"Component {component_id} has external exposure but is not in an external "
            "trust boundary (add one with add_trust_boundary and boundary_type external)."
            for component_id in uncovered
        ]


class ExternalExposureCoverageRule:
    """Require a network or external boundary when external entry points exist.

    Existence check: when any item has ``exposure=external``, at least one
    ``trust_boundaries`` item must have ``boundary_type`` in ``{network, external}``.
    See ``ExternalEntryPointBoundaryRule`` for the stricter membership requirement.

    Finish-only: depends on the full set of entry points and trust boundaries.
    """

    def validate(self, model: CanonicalSystemModel) -> list[str]:
        """Find external exposure without a matching trust-boundary type.

        Args:
            model: Schema-valid canonical model to inspect.

        Returns:
            Human-readable violations when external exposure is uncontained.
        """
        has_external_entry = any(
            entry.exposure is ExposureType.EXTERNAL for entry in model.entry_points
        )
        if not has_external_entry:
            return []
        covering_types = {TrustBoundaryType.EXTERNAL, TrustBoundaryType.NETWORK}
        if any(boundary.boundary_type in covering_types for boundary in model.trust_boundaries):
            return []
        return ["External entry points require a trust boundary of type network or external"]


def production_system_model_rules() -> tuple[SystemModelValidationRule, ...]:
    """Return the production canonical-model business-rule chain.

    Returns:
        Ordered tuple of identifier, reference, and coverage rules.
    """
    return (
        UniqueEntityIdsRule(),
        ReferenceIntegrityRule(),
        UnreferencedExtractedItemRule(),
        ExternalEntryPointAuthRule(),
        TrustBoundaryMembershipRule(),
        BoundaryCrossingFlowRule(),
        TrustBoundaryCrossingConsistencyRule(),
        ExternalExposureCoverageRule(),
        ExternalEntryPointBoundaryRule(),
    )


class CanonicalSystemModelValidator:
    """Run an injected chain of canonical-system-model business rules."""

    def __init__(self, rules: Sequence[SystemModelValidationRule]) -> None:
        self._rules = tuple(rules)

    def validate(self, model: CanonicalSystemModel) -> CanonicalSystemModel:
        """Validate reference integrity while preserving non-fatal information gaps.

        Args:
            model: Schema-valid canonical model to evaluate with injected rules.

        Returns:
            Original canonical model when every rule succeeds.

        Raises:
            AgentSchemaValidationError: If one or more business rules report violations.
        """
        violations = [violation for rule in self._rules for violation in rule.validate(model)]
        if violations:
            raise AgentSchemaValidationError(
                "Extracted architecture failed business validation",
                error_code="CANONICAL_SYSTEM_MODEL_BUSINESS_INVALID",
                retryable=False,
                context={"violations": violations},
            )
        return model


def _entity_ids(items: list[dict[str, JsonValue]]) -> set[str]:
    ids: set[str] = set()
    for item in items:
        item_id = item.get("id")
        if isinstance(item_id, str) and item_id:
            ids.add(item_id)
    return ids


def _format_known_ids(ids: set[str], *, limit: int = 12) -> str:
    if not ids:
        return "(none yet)"
    ordered = sorted(ids)
    if len(ordered) <= limit:
        return ", ".join(ordered)
    visible = ", ".join(ordered[:limit])
    return f"{visible}, ... ({len(ordered)} total)"


def _check_flow_endpoint(
    endpoint_id: object,
    *,
    role: str,
    flow_label: str,
    valid_ids: set[str],
    known_targets: str,
) -> list[str]:
    if not isinstance(endpoint_id, str) or not endpoint_id:
        return []
    if endpoint_id in valid_ids:
        return []
    return [
        f"Data flow {flow_label} has unknown {role} {endpoint_id}. "
        f"Known component/data_store ids: {known_targets} "
        "(add missing ones with add_component/add_data_store first)."
    ]


def _check_actor_ids(
    raw_actor_ids: object,
    *,
    item_label: str,
    actor_ids: set[str],
    known_actors: str,
) -> list[str]:
    if not isinstance(raw_actor_ids, list):
        return []
    violations: list[str] = []
    for actor_id in raw_actor_ids:
        if isinstance(actor_id, str) and actor_id and actor_id not in actor_ids:
            violations.append(
                f"{item_label} references unknown actor {actor_id}. "
                f"Known actor ids: {known_actors} "
                "(add missing ones with add_actor first)."
            )
    return violations


def _external_entry_point_auth_violations(
    payload: Mapping[str, JsonValue] | dict[str, JsonValue],
    item_label: str,
) -> list[str]:
    exposure = payload.get("exposure")
    method_raw = payload.get("authentication_method")
    if exposure != ExposureType.EXTERNAL.value:
        return []
    if not isinstance(method_raw, str):
        return []
    method = method_raw.strip().lower()
    if method not in PlaceholderAuthentication:
        return []
    return [f"External entry point {item_label} uses placeholder authentication {method_raw}"]


def _collect_referenced_ids(
    model: CanonicalSystemModel,
    edges: Sequence[Any],
) -> set[str]:
    referenced: set[str] = set()
    for edge in edges:
        items = getattr(model, edge.list_field, [])
        for item in items:
            for field_name in edge.id_fields:
                raw = getattr(item, field_name, None)
                if isinstance(raw, str) and raw:
                    referenced.add(raw)
                elif isinstance(raw, list):
                    for value in raw:
                        if isinstance(value, str) and value:
                            referenced.add(value)
    return referenced


def _id_cited_in_gap_text(item_id: str, gap_text: str) -> bool:
    """Return True when ``item_id`` appears as a discrete token in gap text."""
    if not gap_text or item_id not in gap_text:
        return False
    # Require a word-boundary style match so short ids do not false-positive.
    start = 0
    while True:
        index = gap_text.find(item_id, start)
        if index < 0:
            return False
        before_ok = index == 0 or not gap_text[index - 1].isalnum()
        end = index + len(item_id)
        after_ok = end >= len(gap_text) or not gap_text[end].isalnum()
        if before_ok and after_ok:
            return True
        start = index + 1
