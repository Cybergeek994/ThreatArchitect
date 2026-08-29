"""Interfaces owned by the application core."""

from threatmodeler.ports.agent_client import AgentClient as AgentClient
from threatmodeler.ports.agent_client import AgentClientFactory as AgentClientFactory
from threatmodeler.ports.agent_provider import AgentProvider as AgentProvider
from threatmodeler.ports.artifact_bundle_loader import ArtifactBundleLoader as ArtifactBundleLoader
from threatmodeler.ports.artifact_construction_session import (
    ArtifactConstructionSession as ArtifactConstructionSession,
)
from threatmodeler.ports.artifact_renderer import ArtifactRenderer as ArtifactRenderer
from threatmodeler.ports.artifact_renderer_factory import (
    ArtifactRendererFactory as ArtifactRendererFactory,
)
from threatmodeler.ports.artifact_repository import ArtifactRepository as ArtifactRepository
from threatmodeler.ports.artifact_validator import ArtifactValidator as ArtifactValidator
from threatmodeler.ports.confluence_client import ConfluenceClient as ConfluenceClient
from threatmodeler.ports.construction_journal import ConstructionJournal as ConstructionJournal
from threatmodeler.ports.construction_journal_factory import (
    ConstructionJournalFactory as ConstructionJournalFactory,
)
from threatmodeler.ports.dependency_factory import DependencyFactory as DependencyFactory
from threatmodeler.ports.document_parser import DocumentParser as DocumentParser
from threatmodeler.ports.http_transport import HttpTransport as HttpTransport
from threatmodeler.ports.logger import LoggerFactory as LoggerFactory
from threatmodeler.ports.logger import StructuredLogger as StructuredLogger
from threatmodeler.ports.output_renderer_factory import (
    OutputRendererFactory as OutputRendererFactory,
)
from threatmodeler.ports.parsed_document_loader import ParsedDocumentLoader as ParsedDocumentLoader
from threatmodeler.ports.prompt_builder import PromptBuilder as PromptBuilder
from threatmodeler.ports.schema_provider import SchemaProvider as SchemaProvider
from threatmodeler.ports.schema_registry import OutputSchemaRegistry as OutputSchemaRegistry
from threatmodeler.ports.schema_validator import SchemaValidator as SchemaValidator
from threatmodeler.ports.schema_validator import (
    SystemModelValidationRule as SystemModelValidationRule,
)
from threatmodeler.ports.system_model_loader import SystemModelLoader as SystemModelLoader
from threatmodeler.ports.tool_calling_provider import ToolCallingProvider as ToolCallingProvider
