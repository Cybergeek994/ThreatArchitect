"""Tests for the OWASP ASVS 5.0 catalog pipeline."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from threatmodeler.config.settings import Settings
from threatmodeler.contracts.artifacts import SecurityRequirementCategory
from threatmodeler.contracts.control_catalog import AsvsFlatDocument, RequirementMappingNeed
from threatmodeler.domain.control_catalogs.asvs_compact_index import AsvsCompactIndexBuilder
from threatmodeler.domain.control_catalogs.asvs_control_registry import AsvsControlRegistry
from threatmodeler.domain.control_catalogs.asvs_flat_parser import (
    canonical_control_id,
    normalize_req_id,
    parse_flat_document,
)
from threatmodeler.domain.control_catalogs.control_mapping_candidate_service import (
    ControlMappingCandidateService,
)
from threatmodeler.infrastructure.control_catalogs.asvs_control_registry_factory import (
    AsvsControlRegistryFactory,
)
from threatmodeler.domain.control_catalogs.llm_asvs_semantic_ranker import LlmAsvsSemanticRanker
from threatmodeler.errors import ConfigurationError
from threatmodeler.errors.application import AgentProviderError
from threatmodeler.infrastructure.control_catalogs.asvs_catalog_cache import AsvsCatalogCache
from threatmodeler.infrastructure.control_catalogs.asvs_catalog_loader import (
    AsvsCatalogLoaderFacade,
    PackagedAsvsCatalogLoader,
)
from threatmodeler.shared.constants import ControlFrameworkName
from threatmodeler.validation.control_mapping_candidate_validator import (
    build_candidate_membership_validator,
)

from tests.fixtures.mock_asvs_semantic_ranker import MockAsvsSemanticRanker
from tests.fixtures.mock_agent_provider import (
    create_mock_agent_provider,
    create_mock_agent_provider_for_agent_assisted,
)


class TestAsvsFlatParser:
    """Verify flat JSON normalization."""

    def test_normalize_req_id_strips_leading_v(self) -> None:
        assert normalize_req_id("V2.2.1") == "2.2.1"
        assert normalize_req_id("2.2.1") == "2.2.1"

    def test_canonical_control_id_includes_version(self) -> None:
        assert canonical_control_id("2.2.1", framework_version="5.0.0") == "v5.0.0-2.2.1"

    def test_parse_sample_fixture(self) -> None:
        payload = json.loads(
            Path("tests/fixtures/asvs_5_flat.sample.json").read_text(encoding="utf-8")
        )
        document = AsvsFlatDocument.model_validate(payload)
        snapshot = parse_flat_document(document, source_uri="fixture://sample")

        assert snapshot.provenance.control_count == 2
        assert snapshot.controls[0].id == "v5.0.0-2.2.1"

    def test_empty_document_raises_configuration_error(self) -> None:
        document = AsvsFlatDocument(requirements=())
        with pytest.raises(ConfigurationError) as captured:
            parse_flat_document(document, source_uri="fixture://empty")
        assert captured.value.error_code == "ASVS_FLAT_EMPTY"

    def test_invalid_level_raises_configuration_error(self) -> None:
        payload = json.loads(
            Path("tests/fixtures/asvs_5_flat.sample.json").read_text(encoding="utf-8")
        )
        payload["requirements"][0]["L"] = "invalid"
        document = AsvsFlatDocument.model_validate(payload)
        with pytest.raises(ConfigurationError) as captured:
            parse_flat_document(document, source_uri="fixture://invalid-level")
        assert captured.value.error_code == "ASVS_FLAT_LEVEL_INVALID"


class TestPackagedAsvsCatalog:
    """Verify packaged catalog loading and registry behavior."""

    def test_packaged_loader_returns_full_snapshot(self) -> None:
        snapshot = PackagedAsvsCatalogLoader().load_snapshot()

        assert snapshot.provenance.control_count >= 300
        assert any(control.short_id == "2.2.1" for control in snapshot.controls)

    def test_registry_resolves_short_and_canonical_ids(self) -> None:
        registry = AsvsControlRegistry(PackagedAsvsCatalogLoader().load_snapshot())

        assert registry.contains("v5.0.0-2.2.1")
        assert registry.contains("2.2.1")
        assert registry.resolve_id("2.2.1") == "v5.0.0-2.2.1"
        assert registry.get("missing") is None

    def test_empty_registry_raises_configuration_error(self) -> None:
        snapshot = PackagedAsvsCatalogLoader().load_snapshot().model_copy(update={"controls": ()})
        with pytest.raises(ConfigurationError) as captured:
            AsvsControlRegistry(snapshot)
        assert captured.value.error_code == "ASVS_REGISTRY_EMPTY"


class TestAsvsCatalogCache:
    """Verify snapshot cache read/write behavior."""

    def test_write_and_read_if_fresh(self, tmp_path: Path) -> None:
        snapshot = PackagedAsvsCatalogLoader().load_snapshot()
        cache = AsvsCatalogCache(tmp_path, ttl_hours=24)
        cache.write(snapshot)

        loaded = cache.read_if_fresh()
        assert loaded is not None
        assert loaded.provenance.control_count == snapshot.provenance.control_count

    def test_stale_cache_returns_none(self, tmp_path: Path) -> None:
        snapshot = PackagedAsvsCatalogLoader().load_snapshot()
        stale = snapshot.model_copy(
            update={
                "provenance": snapshot.provenance.model_copy(
                    update={
                        "fetched_at": (
                            datetime.now(tz=UTC) - timedelta(hours=48)
                        ).isoformat()
                    }
                )
            }
        )
        cache = AsvsCatalogCache(tmp_path, ttl_hours=1)
        cache.write(stale)

        assert cache.read_if_fresh() is None

    def test_read_or_raise_on_missing_cache(self, tmp_path: Path) -> None:
        cache = AsvsCatalogCache(tmp_path)
        with pytest.raises(ConfigurationError) as captured:
            cache.read_or_raise()
        assert captured.value.error_code == "ASVS_CACHE_MISS"

    def test_read_if_fresh_returns_none_when_cache_missing(self, tmp_path: Path) -> None:
        cache = AsvsCatalogCache(tmp_path)
        assert cache.read_if_fresh() is None

    def test_read_or_raise_loads_existing_snapshot(self, tmp_path: Path) -> None:
        snapshot = PackagedAsvsCatalogLoader().load_snapshot()
        cache = AsvsCatalogCache(tmp_path)
        cache.write(snapshot)

        loaded = cache.read_or_raise()
        assert loaded.provenance.control_count == snapshot.provenance.control_count


class TestControlMappingCandidateService:
    """Verify host-side pre-ranking for control mapping."""

    def test_rank_all_builds_prompt_payload(self, canonical_system_model) -> None:
        from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
        from threatmodeler.domain.mitigation_generation import MitigationGenerationService
        from threatmodeler.domain.risk_scoring import RiskScoringService
        from threatmodeler.domain.stride_generation import (
            AgentStrideThreatGenerationStrategy,
            StrideThreatGenerationService,
        )
        from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
        from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

        metadata = ArtifactMetadataService()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                create_mock_agent_provider_for_agent_assisted(),
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        mitigations = MitigationGenerationService(metadata).generate_plan(
            canonical_system_model, risks
        )
        requirements = MitigationGenerationService(metadata).generate_requirements(
            canonical_system_model, threats, risks
        )
        registry = AsvsControlRegistry(PackagedAsvsCatalogLoader().load_snapshot())
        service = ControlMappingCandidateService(
            registry,
            MockAsvsSemanticRanker(registry),
        )

        ranked, provenance, allowed = service.rank_all(
            canonical_system_model,
            requirements,
            risks,
            mitigations,
            threats,
        )

        assert ranked
        assert provenance["framework"] == ControlFrameworkName.OWASP_ASVS
        assert allowed


class TestControlMappingCandidateServiceHelpers:
    """Verify helper wiring for default candidate services."""

    def test_registry_and_compact_index_properties(self) -> None:
        registry = AsvsControlRegistryFactory.packaged().create()
        service = ControlMappingCandidateService(
            registry,
            MockAsvsSemanticRanker(registry),
        )

        assert service.registry is registry
        assert service.compact_index

    def test_registry_factory_from_settings(self, tmp_path: Path) -> None:
        settings = Settings(asvs_catalog_cache_dir=tmp_path)
        registry = AsvsControlRegistryFactory.from_settings(settings).create()

        assert registry.snapshot.provenance.control_count >= 300


class TestLlmAsvsSemanticRanker:
    """Verify LLM batch ranker validation and retries."""

    def test_empty_requirements_returns_empty_batch(self) -> None:
        registry = AsvsControlRegistryFactory.packaged().create()
        ranker = LlmAsvsSemanticRanker(create_mock_agent_provider(), registry)
        result = ranker.rank_all((), ())
        assert result.mappings == ()

    def test_valid_llm_response_is_normalized(self) -> None:
        registry = AsvsControlRegistry(PackagedAsvsCatalogLoader().load_snapshot())
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = create_mock_agent_provider(
            {
                LlmAsvsSemanticRanker.TASK_NAME: {
                    "mappings": [
                        {
                            "requirement_id": "req-1",
                            "control_id": "v5.0.0-2.2.1",
                            "alternates": ["v5.0.0-8.1.1"],
                            "confidence": "high",
                            "rationale": "Best authentication match.",
                        }
                    ]
                }
            }
        )
        ranker = LlmAsvsSemanticRanker(provider, registry)
        result = ranker.rank_all(
            (
                RequirementMappingNeed(
                    requirement_id="req-1",
                    implementation_need="Require MFA",
                    category=SecurityRequirementCategory.AUTHENTICATION.value,
                ),
            ),
            compact,
        )

        assert result.mappings[0].candidates[0].id == "v5.0.0-2.2.1"

    def test_unknown_control_id_raises_provider_error(self) -> None:
        registry = AsvsControlRegistry(PackagedAsvsCatalogLoader().load_snapshot())
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = create_mock_agent_provider(
            {
                LlmAsvsSemanticRanker.TASK_NAME: {
                    "mappings": [
                        {
                            "requirement_id": "req-1",
                            "control_id": "AC-1",
                            "alternates": [],
                            "confidence": "high",
                            "rationale": "Hallucinated id.",
                        }
                    ]
                }
            }
        )
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=1)

        with pytest.raises(AgentProviderError) as captured:
            ranker.rank_all(
                (
                    RequirementMappingNeed(
                        requirement_id="req-1",
                        implementation_need="Require MFA",
                        category=SecurityRequirementCategory.AUTHENTICATION.value,
                    ),
                ),
                compact,
            )
        assert captured.value.error_code == "ASVS_BATCH_RANK_UNKNOWN_CONTROL"

    def test_invalid_json_string_raises_provider_error(self) -> None:
        from unittest.mock import Mock

        from threatmodeler.contracts.integration import AgentResponse

        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = Mock()
        provider.complete.return_value = AgentResponse(
            output_payload="not-json",
            confidence=1.0,
            provider_name="mock",
            model_name="mock",
        )
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=1)

        with pytest.raises(AgentProviderError) as captured:
            ranker.rank_all(
                (
                    RequirementMappingNeed(
                        requirement_id="req-1",
                        implementation_need="Require MFA",
                        category=SecurityRequirementCategory.AUTHENTICATION.value,
                    ),
                ),
                compact,
            )
        assert captured.value.error_code == "ASVS_BATCH_RANK_INVALID_JSON"

    def test_non_object_json_string_raises_provider_error(self) -> None:
        from unittest.mock import Mock

        from threatmodeler.contracts.integration import AgentResponse

        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = Mock()
        provider.complete.return_value = AgentResponse(
            output_payload='["not-an-object"]',
            confidence=1.0,
            provider_name="mock",
            model_name="mock",
        )
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=1)

        with pytest.raises(AgentProviderError) as captured:
            ranker.rank_all(
                (
                    RequirementMappingNeed(
                        requirement_id="req-1",
                        implementation_need="Require MFA",
                        category=SecurityRequirementCategory.AUTHENTICATION.value,
                    ),
                ),
                compact,
            )
        assert captured.value.error_code == "ASVS_BATCH_RANK_INVALID_JSON"

    def test_retries_after_transient_ranker_failure(self) -> None:
        from unittest.mock import Mock

        from threatmodeler.contracts.integration import AgentResponse
        from threatmodeler.errors.application import AgentProviderError

        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = Mock()
        provider.complete.side_effect = [
            AgentProviderError(
                "temporary failure",
                error_code="ASVS_BATCH_RANK_SCHEMA_INVALID",
                retryable=True,
                context={},
            ),
            AgentResponse(
                output_payload={
                    "mappings": [
                        {
                            "requirement_id": "req-1",
                            "control_id": "v5.0.0-2.2.1",
                            "alternates": [],
                            "confidence": "high",
                            "rationale": "Recovered on retry.",
                        }
                    ]
                },
                confidence=1.0,
                provider_name="mock",
                model_name="mock",
            ),
        ]
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=2)
        result = ranker.rank_all(
            (
                RequirementMappingNeed(
                    requirement_id="req-1",
                    implementation_need="Require MFA",
                    category=SecurityRequirementCategory.AUTHENTICATION.value,
                ),
            ),
            compact,
        )

        assert result.mappings[0].candidates[0].id == "v5.0.0-2.2.1"

    def test_retries_after_validation_failure(self) -> None:
        from unittest.mock import Mock

        from threatmodeler.contracts.integration import AgentResponse

        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = Mock()
        provider.complete.side_effect = [
            AgentResponse(
                output_payload={"mappings": "invalid"},
                confidence=1.0,
                provider_name="mock",
                model_name="mock",
            ),
            AgentResponse(
                output_payload={
                    "mappings": [
                        {
                            "requirement_id": "req-1",
                            "control_id": "v5.0.0-2.2.1",
                            "alternates": [],
                            "confidence": "high",
                            "rationale": "Recovered after schema failure.",
                        }
                    ]
                },
                confidence=1.0,
                provider_name="mock",
                model_name="mock",
            ),
        ]
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=2)
        result = ranker.rank_all(
            (
                RequirementMappingNeed(
                    requirement_id="req-1",
                    implementation_need="Require MFA",
                    category=SecurityRequirementCategory.AUTHENTICATION.value,
                ),
            ),
            compact,
        )

        assert result.mappings[0].candidates[0].id == "v5.0.0-2.2.1"

    def test_raises_last_error_when_all_attempts_fail(self) -> None:
        from unittest.mock import Mock

        from threatmodeler.errors.application import AgentProviderError

        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = Mock()
        provider.complete.side_effect = AgentProviderError(
            "persistent failure",
            error_code="ASVS_BATCH_RANK_SCHEMA_INVALID",
            retryable=True,
            context={},
        )
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=2)

        with pytest.raises(AgentProviderError) as captured:
            ranker.rank_all(
                (
                    RequirementMappingNeed(
                        requirement_id="req-1",
                        implementation_need="Require MFA",
                        category=SecurityRequirementCategory.AUTHENTICATION.value,
                    ),
                ),
                compact,
            )

        assert captured.value.error_code == "ASVS_BATCH_RANK_SCHEMA_INVALID"
        assert provider.complete.call_count == 2

    def test_json_string_payload_is_accepted(self) -> None:
        from unittest.mock import Mock

        from threatmodeler.contracts.integration import AgentResponse

        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = Mock()
        provider.complete.return_value = AgentResponse(
            output_payload=json.dumps(
                {
                    "mappings": [
                        {
                            "requirement_id": "req-1",
                            "control_id": "v5.0.0-2.2.1",
                            "alternates": [],
                            "confidence": "high",
                            "rationale": "JSON string payload.",
                        }
                    ]
                }
            ),
            confidence=1.0,
            provider_name="mock",
            model_name="mock",
        )
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=1)
        result = ranker.rank_all(
            (
                RequirementMappingNeed(
                    requirement_id="req-1",
                    implementation_need="Require MFA",
                    category=SecurityRequirementCategory.AUTHENTICATION.value,
                ),
            ),
            compact,
        )

        assert result.mappings[0].candidates[0].id == "v5.0.0-2.2.1"

    def test_requirement_mismatch_raises_provider_error(self) -> None:
        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = create_mock_agent_provider(
            {
                LlmAsvsSemanticRanker.TASK_NAME: {
                    "mappings": [
                        {
                            "requirement_id": "missing-req",
                            "control_id": "v5.0.0-2.2.1",
                            "alternates": [],
                            "confidence": "high",
                            "rationale": "Wrong requirement id.",
                        }
                    ]
                }
            }
        )
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=1)

        with pytest.raises(AgentProviderError) as captured:
            ranker.rank_all(
                (
                    RequirementMappingNeed(
                        requirement_id="req-1",
                        implementation_need="Require MFA",
                        category=SecurityRequirementCategory.AUTHENTICATION.value,
                    ),
                ),
                compact,
            )
        assert captured.value.error_code == "ASVS_BATCH_RANK_REQUIREMENT_MISMATCH"

    def test_invalid_schema_payload_raises_provider_error(self) -> None:
        registry = AsvsControlRegistryFactory.packaged().create()
        compact = AsvsCompactIndexBuilder().build(registry.snapshot)
        provider = create_mock_agent_provider({LlmAsvsSemanticRanker.TASK_NAME: {"mappings": "bad"}})
        ranker = LlmAsvsSemanticRanker(provider, registry, max_attempts=1)

        with pytest.raises(AgentProviderError) as captured:
            ranker.rank_all(
                (
                    RequirementMappingNeed(
                        requirement_id="req-1",
                        implementation_need="Require MFA",
                        category=SecurityRequirementCategory.AUTHENTICATION.value,
                    ),
                ),
                compact,
            )
        assert captured.value.error_code == "ASVS_BATCH_RANK_SCHEMA_INVALID"

    def test_rank_all_propagates_ranker_failure(self, canonical_system_model) -> None:
        from threatmodeler.domain.artifact_metadata import ArtifactMetadataService
        from threatmodeler.domain.mitigation_generation import MitigationGenerationService
        from threatmodeler.domain.risk_scoring import RiskScoringService
        from threatmodeler.domain.stride_generation import (
            AgentStrideThreatGenerationStrategy,
            StrideThreatGenerationService,
        )
        from threatmodeler.orchestration.prompts import SecurePromptTemplate, StrideThreatPromptBuilder
        from threatmodeler.validation.pydantic_schema_provider import PydanticSchemaProvider

        class FailingRanker:
            def rank_all(self, requirements, compact_index, *, alternates_per_requirement=2):
                del requirements, compact_index, alternates_per_requirement
                raise AgentProviderError(
                    "ranker unavailable",
                    error_code="ASVS_BATCH_RANK_SCHEMA_INVALID",
                    retryable=True,
                    context={},
                )

        metadata = ArtifactMetadataService()
        schema_provider = PydanticSchemaProvider()
        stride_service = StrideThreatGenerationService(
            AgentStrideThreatGenerationStrategy(
                create_mock_agent_provider_for_agent_assisted(),
                StrideThreatPromptBuilder(SecurePromptTemplate(), schema_provider),
                schema_provider,
            ),
            metadata,
        )
        threats = stride_service.generate(canonical_system_model)
        risks = RiskScoringService(metadata).generate(canonical_system_model, threats)
        mitigations = MitigationGenerationService(metadata).generate_plan(
            canonical_system_model, risks
        )
        requirements = MitigationGenerationService(metadata).generate_requirements(
            canonical_system_model, threats, risks
        )
        registry = AsvsControlRegistryFactory.packaged().create()
        service = ControlMappingCandidateService(registry, FailingRanker())

        with pytest.raises(AgentProviderError) as captured:
            service.rank_all(
                canonical_system_model,
                requirements,
                risks,
                mitigations,
                threats,
            )

        assert captured.value.error_code == "ASVS_BATCH_RANK_SCHEMA_INVALID"


class TestCandidateMembershipValidator:
    """Verify add_control candidate membership checks."""

    def test_rejects_unranked_control_id(self) -> None:
        validator = build_candidate_membership_validator({"req-1": {"v5.0.0-2.2.1"}})
        violations = validator(
            "controls",
            {"framework_control_id": "v5.0.0-8.1.1", "requirement_ids": ["req-1"]},
            {},
        )
        assert violations

    def test_accepts_ranked_control_id(self) -> None:
        validator = build_candidate_membership_validator({"req-1": {"v5.0.0-2.2.1"}})
        violations = validator(
            "controls",
            {"framework_control_id": "v5.0.0-2.2.1", "requirement_ids": ["req-1"]},
            {},
        )
        assert not violations


class TestAsvsCatalogLoaderFacade:
    """Verify loader facade uses cache and packaged fallback."""

    def test_load_writes_and_reuses_cache(self, tmp_path: Path) -> None:
        settings = Settings(asvs_catalog_cache_dir=tmp_path)
        facade = AsvsCatalogLoaderFacade(settings)
        first = facade.load()
        second = facade.load()

        assert first.provenance.control_count == second.provenance.control_count
        assert facade.default_fetch_url
