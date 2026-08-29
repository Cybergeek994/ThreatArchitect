"""Tests for missing-information enforcement policy."""

import pytest
from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.domain.missing_information_policy import (
    BlockingMissingInformationPolicy,
    MissingInformationPolicyFactory,
    PermissiveMissingInformationPolicy,
)
from threatmodeler.errors import MissingInformationError


class TestMissingInformationPolicyPositive:
    """Verify gaps are allowed by default."""

    def test_permissive_policy_allows_gaps(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        PermissiveMissingInformationPolicy().enforce(canonical_system_model)

    def test_blocking_policy_allows_complete_models(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        complete_model = canonical_system_model.model_copy(update={"missing_information": []})

        BlockingMissingInformationPolicy().enforce(complete_model)

    def test_factory_returns_permissive_policy_by_default(self) -> None:
        policy = MissingInformationPolicyFactory.create(fail_on_missing_information=False)

        assert isinstance(policy, PermissiveMissingInformationPolicy)


class TestMissingInformationPolicyNegative:
    """Verify blocking policy context includes the full gap list."""

    def test_blocking_policy_includes_full_missing_information_list(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        with pytest.raises(MissingInformationError) as captured:
            BlockingMissingInformationPolicy().enforce(canonical_system_model)

        context = captured.value.context or {}
        assert context["missing_information"] == list(canonical_system_model.missing_information)
        assert context["missing_information_count"] == len(
            canonical_system_model.missing_information
        )


class TestMissingInformationPolicyErrors:
    """Verify blocking policy raises the expected application error."""

    def test_blocking_policy_raises_when_gaps_exist(
        self,
        canonical_system_model: CanonicalSystemModel,
    ) -> None:
        with pytest.raises(MissingInformationError) as captured:
            BlockingMissingInformationPolicy().enforce(canonical_system_model)

        assert captured.value.error_code == "MISSING_INFORMATION_BLOCKING"
        assert captured.value.retryable is False
        context = captured.value.context or {}
        assert context["missing_information_count"] == len(
            canonical_system_model.missing_information
        )

    def test_factory_returns_blocking_policy_when_configured(self) -> None:
        policy = MissingInformationPolicyFactory.create(fail_on_missing_information=True)

        assert isinstance(policy, BlockingMissingInformationPolicy)
