"""Tests for the curated OWASP ASVS catalog."""

import pytest
from threatmodeler.contracts.artifacts import SecurityRequirementCategory
from threatmodeler.domain.control_catalogs.owasp_asvs import OwaspAsvsCatalog, OwaspAsvsControl
from threatmodeler.errors import ConfigurationError
from threatmodeler.shared.constants import AsvsChapter, ControlFrameworkName


class TestOwaspAsvsCatalogPositive:
    """Verify catalog loading and matching."""

    def test_default_catalog_contains_representative_controls(self) -> None:
        catalog = OwaspAsvsCatalog.load_default()

        assert catalog.contains("V2.2.1")
        assert catalog.contains("V8.1.1")
        serialized = catalog.serialize()
        assert isinstance(serialized, list)
        first = serialized[0]
        assert isinstance(first, dict)
        assert first["id"] == "V1.2.1"
        assert ControlFrameworkName.OWASP_ASVS.value == "OWASP ASVS 4.0"

    def test_match_prefers_keyword_hits(self) -> None:
        catalog = OwaspAsvsCatalog.load_default()

        matched = catalog.match(
            "Require OAuth and MFA at the public API",
            SecurityRequirementCategory.AUTHENTICATION,
        )

        assert matched.id == "V2.2.1"

    def test_match_falls_back_to_category_chapter(self) -> None:
        catalog = OwaspAsvsCatalog.load_default()

        matched = catalog.match(
            "Unrelated requirement text",
            SecurityRequirementCategory.AUTHORIZATION,
        )

        assert matched.chapter == AsvsChapter.V4


class TestOwaspAsvsCatalogErrors:
    """Verify empty catalogs are rejected."""

    def test_empty_catalog_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError) as captured:
            OwaspAsvsCatalog(tuple())

        assert captured.value.error_code == "OWASP_ASVS_CATALOG_EMPTY"

    def test_get_returns_none_for_unknown_id(self) -> None:
        catalog = OwaspAsvsCatalog(
            (
                OwaspAsvsControl(
                    control_id="V1.2.1",
                    chapter="V1",
                    name="Lifecycle",
                    keywords=("architecture",),
                ),
            )
        )

        assert catalog.get("missing") is None
        assert catalog.all_controls()[0].id == "V1.2.1"


    def test_owasp_catalog_chapter_fallbacks(self) -> None:
        catalog = OwaspAsvsCatalog(
            (
                OwaspAsvsControl("V5.1.1", "V5", "Integrity", ("integrity",)),
                OwaspAsvsControl("V12.1.1", "V12", "Availability", ("availability",)),
                OwaspAsvsControl("V1.1.1", "V1", "Default", ()),
                OwaspAsvsControl("V2.1.1", "V2", "Authentication", ()),
                OwaspAsvsControl("V8.1.1", "V8", "Confidentiality", ()),
            )
        )
        assert catalog.match("plain text", SecurityRequirementCategory.INTEGRITY).chapter == "V5"
        assert catalog.match("plain text", SecurityRequirementCategory.AVAILABILITY).chapter == "V12"
        assert catalog.match("plain text", SecurityRequirementCategory.PRIVACY).chapter == "V1"
        assert catalog.match("plain text", SecurityRequirementCategory.AUTHENTICATION).chapter == "V2"
        assert catalog.match("plain text", SecurityRequirementCategory.CONFIDENTIALITY).chapter == "V8"

        fallback_catalog = OwaspAsvsCatalog(
            (OwaspAsvsControl("V9.1.1", "V9", "Orphan", ()),)
        )
        assert (
            fallback_catalog.match("plain text", SecurityRequirementCategory.AUTHENTICATION).id
            == "V9.1.1"
        )
