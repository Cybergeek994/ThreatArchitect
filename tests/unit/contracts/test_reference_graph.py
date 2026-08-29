"""Tests for default reference-graph policy."""

from threatmodeler.contracts.reference_graph import default_reference_graph_policy


class TestDefaultReferenceGraphPolicyPositive:
    """Verify production reference-graph node coverage."""

    def test_default_reference_graph_policy_returns_expected_nodes(self) -> None:
        policy = default_reference_graph_policy()

        list_fields = {node.list_field for node in policy.nodes}
        assert list_fields == {"components", "data_stores", "actors"}

        components = next(node for node in policy.nodes if node.list_field == "components")
        component_edges = {edge.list_field for edge in components.edges}
        assert component_edges == {"data_flows", "entry_points"}

        data_stores = next(node for node in policy.nodes if node.list_field == "data_stores")
        data_store_edges = {edge.list_field for edge in data_stores.edges}
        assert data_store_edges == {"data_flows", "trust_boundaries"}

        actors = next(node for node in policy.nodes if node.list_field == "actors")
        actor_edges = {edge.list_field for edge in actors.edges}
        assert actor_edges == {"entry_points", "data_flows"}

        flow_edge = next(
            edge for edge in components.edges if edge.list_field == "data_flows"
        )
        assert flow_edge.id_fields == ("source_component_id", "destination_component_id")
