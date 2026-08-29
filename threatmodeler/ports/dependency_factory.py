"""Abstract factory for infrastructure dependencies."""

from typing import Protocol

from threatmodeler.ports.agent_dependency_factory import AgentDependencyFactory
from threatmodeler.ports.artifact_output_dependency_factory import ArtifactOutputDependencyFactory
from threatmodeler.ports.ingestion_dependency_factory import IngestionDependencyFactory


class DependencyFactory(
    IngestionDependencyFactory,
    AgentDependencyFactory,
    ArtifactOutputDependencyFactory,
    Protocol,
):
    """Compose ingestion, agent, and artifact-output factory ports for the container."""
