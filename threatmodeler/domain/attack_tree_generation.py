"""Deterministic attack-tree generation."""

from threatmodeler.contracts.artifacts import (
    AttackTree,
    AttackTreeNode,
    StrideThreat,
    StrideThreatRegister,
)
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class AttackTreeGenerationService:
    """Derive traceable attack-tree nodes from validated STRIDE threats."""

    def __init__(self, metadata: ArtifactMetadataService) -> None:
        self._metadata = metadata

    def generate(
        self,
        model: CanonicalSystemModel,
        threat_register: StrideThreatRegister,
    ) -> AttackTree:
        """Generate one traceable attack goal per validated threat.

        Args:
            model: Canonical model supplying shared assumptions.
            threat_register: Validated STRIDE threats used as attack goals.

        Returns:
            Deterministic attack tree linked to source threats and architecture elements.
        """
        roots = [self._build_root(model, threat) for threat in threat_register.threats]
        return AttackTree(
            **self._metadata.artifact_fields(
                "attack-tree",
                "Attack Tree",
                "Attack goals derived from validated STRIDE threats.",
                model.assumptions,
                confidence=self._metadata.compute_confidence(
                    roots, when_empty=threat_register.confidence
                ),
            ).model_dump(),
            root_nodes=roots,
        )

    def _build_root(self, model: CanonicalSystemModel, threat: StrideThreat) -> AttackTreeNode:
        children = [
            AttackTreeNode(
                **self._metadata.item_fields(
                    f"attack-step-{threat.id}-{index}",
                    precondition,
                    f"Precondition for {threat.name}.",
                    threat.evidence,
                    threat.confidence,
                    [*model.assumptions, *threat.assumptions],
                ).model_dump(),
                component_id=threat.component_id,
                data_flow_id=threat.data_flow_id,
                asset_id=threat.asset_id,
                component_ids=threat.component_ids,
                data_flow_ids=threat.data_flow_ids,
                asset_ids=threat.asset_ids,
                operator="leaf",
            )
            for index, precondition in enumerate(threat.attack_preconditions, start=1)
        ]
        return AttackTreeNode(
            **self._metadata.item_fields(
                f"attack-{threat.id}",
                f"Realize {threat.name}",
                threat.description,
                threat.evidence,
                threat.confidence,
                [*model.assumptions, *threat.assumptions],
            ).model_dump(),
            component_id=threat.component_id,
            data_flow_id=threat.data_flow_id,
            asset_id=threat.asset_id,
            component_ids=threat.component_ids,
            data_flow_ids=threat.data_flow_ids,
            asset_ids=threat.asset_ids,
            operator="and" if children else "leaf",
            children=children,
        )
