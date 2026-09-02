"""Tests for deterministic architecture graph compilation."""

from threatmodeler.contracts.artifacts.enums import GraphNodeKind
from threatmodeler.contracts.system_model import (
    CanonicalSystemModel,
    ComponentType,
    DataStoreType,
    ExposureType,
)
from threatmodeler.domain.architecture_graph_generation import (
    ArchitectureGraphGenerationService,
    _component_node_kind,
    _store_node_kind,
)
from threatmodeler.domain.artifact_metadata import ArtifactMetadataService


class TestArchitectureGraphGenerationService:
    """Verify graph node kinds and edge/path compilation."""

    def test_maps_component_and_store_kinds(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        identity = canonical_system_model.components[0].model_copy(
            update={
                "id": "component-identity",
                "name": "Identity Provider",
                "component_type": ComponentType.IDENTITY_PROVIDER,
            }
        )
        external = canonical_system_model.components[0].model_copy(
            update={
                "id": "component-external",
                "name": "External Gateway",
                "component_type": ComponentType.EXTERNAL_SERVICE,
            }
        )
        queue_store = canonical_system_model.data_stores[0].model_copy(
            update={
                "id": "store-queue",
                "name": "Payment Queue",
                "data_store_type": DataStoreType.OBJECT_STORAGE,
            }
        )
        model = canonical_system_model.model_copy(
            update={
                "components": [*canonical_system_model.components, identity, external],
                "data_stores": [*canonical_system_model.data_stores, queue_store],
                "data_flows": [
                    *canonical_system_model.data_flows,
                    canonical_system_model.data_flows[0].model_copy(
                        update={
                            "id": "flow-unmapped",
                            "source_component_id": "missing-source",
                            "destination_component_id": "missing-target",
                        }
                    ),
                ],
                "entry_points": [
                    canonical_system_model.entry_points[0].model_copy(
                        update={
                            "id": "entry-orphan",
                            "component_id": "missing-component",
                            "exposure": ExposureType.EXTERNAL,
                        }
                    )
                ],
            }
        )

        graph = ArchitectureGraphGenerationService(ArtifactMetadataService()).generate(model)

        kinds = {node.kind for node in graph.nodes}
        assert GraphNodeKind.IDENTITY in kinds
        assert GraphNodeKind.EXTERNAL_SERVICE in kinds
        assert GraphNodeKind.STORAGE in kinds
        assert all(edge.data_flow_id != "flow-unmapped" for edge in graph.edges)

    def test_adds_flow_edges_between_components(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "components": [
                    *canonical_system_model.components,
                    canonical_system_model.components[0].model_copy(
                        update={
                            "id": "component-worker",
                            "name": "Worker",
                            "component_type": ComponentType.WEB_APP,
                        }
                    ),
                ],
                "data_flows": [
                    canonical_system_model.data_flows[0].model_copy(
                        update={
                            "id": "flow-internal",
                            "source_component_id": "component-api",
                            "destination_component_id": "component-worker",
                        }
                    )
                ],
                "entry_points": [],
            }
        )

        graph = ArchitectureGraphGenerationService(ArtifactMetadataService()).generate(model)

        assert any(edge.data_flow_id == "flow-internal" for edge in graph.edges)

    def test_builds_fallback_attack_path_when_no_external_entries(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "entry_points": [
                    entry.model_copy(update={"exposure": ExposureType.INTERNAL})
                    for entry in canonical_system_model.entry_points
                ]
            }
        )

        graph = ArchitectureGraphGenerationService(ArtifactMetadataService()).generate(model)

        assert len(graph.attack_paths) == 1
        assert graph.attack_paths[0].entry_node_id == graph.nodes[0].id
        assert graph.attack_paths[0].target_node_id == graph.nodes[0].id

    def test_skips_entry_expose_edge_when_component_missing(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        model = canonical_system_model.model_copy(
            update={
                "entry_points": [
                    canonical_system_model.entry_points[0].model_copy(
                        update={
                            "id": "entry-orphan",
                            "component_id": "missing-component",
                            "exposure": ExposureType.EXTERNAL,
                        }
                    )
                ]
            }
        )

        graph = ArchitectureGraphGenerationService(ArtifactMetadataService()).generate(model)

        assert graph.nodes
        assert not any(edge.kind.value == "exposes" for edge in graph.edges)
        assert graph.attack_paths


class TestArchitectureGraphKindHelpers:
    """Verify private node-kind mapping helpers."""

    def test_component_node_kind_mapping(self) -> None:
        assert _component_node_kind(ComponentType.API) is GraphNodeKind.API
        assert _component_node_kind(ComponentType.IDENTITY_PROVIDER) is GraphNodeKind.IDENTITY
        assert _component_node_kind(ComponentType.EXTERNAL_SERVICE) is GraphNodeKind.EXTERNAL_SERVICE
        assert _component_node_kind(ComponentType.WEB_APP) is GraphNodeKind.SERVICE

    def test_store_node_kind_mapping(self) -> None:
        assert _store_node_kind("queue") is GraphNodeKind.QUEUE
        assert _store_node_kind("object_storage") is GraphNodeKind.STORAGE
        assert _store_node_kind("database") is GraphNodeKind.DATABASE
