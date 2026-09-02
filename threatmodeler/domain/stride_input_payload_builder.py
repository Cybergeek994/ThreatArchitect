"""Assemble validated upstream artifacts into STRIDE agent input payloads."""

from pydantic import JsonValue, TypeAdapter

from threatmodeler.contracts.artifacts.enums import StrideInputPayloadField
from threatmodeler.contracts.artifacts.stride_context import PreStrideArtifacts, StrideUpstreamContext


class StrideInputPayloadBuilder:
    """Build STRIDE agent payloads from validated upstream context."""

    def build_graph_input(self, context: PreStrideArtifacts) -> dict[str, JsonValue]:
        """Serialize pre-STRIDE artifacts for architecture graph generation."""
        validated = PreStrideArtifacts.model_validate(context.model_dump(mode="json"))
        return self._serialize_pre_stride(validated)

    def build(self, context: StrideUpstreamContext) -> dict[str, JsonValue]:
        """Serialize upstream artifacts into the STRIDE input payload.

        Args:
            context: Validated upstream artifacts including architecture graph.

        Returns:
            JSON-compatible payload for STRIDE agent generation.

        Raises:
            ValueError: If context fails validation when built.
        """
        validated = StrideUpstreamContext.model_validate(context.model_dump(mode="json"))
        payload = self._serialize_pre_stride(validated)
        payload[StrideInputPayloadField.ARCHITECTURE_GRAPH] = (
            validated.architecture_graph.model_dump(mode="json")
        )
        return payload

    def _serialize_pre_stride(self, validated: PreStrideArtifacts) -> dict[str, JsonValue]:
        system_model = TypeAdapter(dict[str, JsonValue]).validate_json(
            validated.system_model.model_dump_json()
        )
        return {
            StrideInputPayloadField.SYSTEM_MODEL: system_model,
            StrideInputPayloadField.DIAGRAM_EVIDENCE: list(
                validated.system_model.diagram_evidence
            ),
            StrideInputPayloadField.DIAGRAM_TOPOLOGY: [
                snapshot.model_dump(mode="json")
                for snapshot in validated.system_model.diagram_topology
            ],
            StrideInputPayloadField.COMPONENT_INVENTORY: validated.component_inventory.model_dump(
                mode="json"
            ),
            StrideInputPayloadField.ASSET_INVENTORY: validated.asset_inventory.model_dump(
                mode="json"
            ),
            StrideInputPayloadField.ACTOR_MODEL: validated.actor_model.model_dump(mode="json"),
            StrideInputPayloadField.DATA_FLOW_DIAGRAM: validated.data_flow_diagram.model_dump(
                mode="json"
            ),
            StrideInputPayloadField.TRUST_BOUNDARY_MAP: validated.trust_boundary_map.model_dump(
                mode="json"
            ),
            StrideInputPayloadField.ENTRY_POINT_INVENTORY: validated.entry_point_inventory.model_dump(
                mode="json"
            ),
            StrideInputPayloadField.AUTHENTICATION_AUTHORIZATION_MODEL: (
                validated.authentication_authorization_model.model_dump(mode="json")
            ),
            StrideInputPayloadField.DEPLOYMENT_MODEL: validated.deployment_model.model_dump(
                mode="json"
            ),
        }
