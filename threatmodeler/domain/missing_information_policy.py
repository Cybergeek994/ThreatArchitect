"""Policy objects for missing-information enforcement."""

from typing import Protocol

from threatmodeler.contracts.system_model import CanonicalSystemModel
from threatmodeler.errors import MissingInformationError


class MissingInformationPolicy(Protocol):
    """Define interchangeable policies for unresolved architecture gaps."""

    def enforce(self, model: CanonicalSystemModel) -> None:
        """Apply the configured missing-information policy to one canonical model.

        Args:
            model: Canonical model that may contain unresolved information gaps.

        Raises:
            MissingInformationError: If the policy requires resolved architecture data.
        """
        ...


class PermissiveMissingInformationPolicy:
    """Allow workflows to continue when architecture gaps remain."""

    def enforce(self, model: CanonicalSystemModel) -> None:
        """Allow the workflow to continue even when architecture gaps remain."""
        del model


class BlockingMissingInformationPolicy:
    """Fail workflows when architecture gaps remain unresolved."""

    def enforce(self, model: CanonicalSystemModel) -> None:
        """Fail the workflow when unresolved architecture gaps remain."""
        if not model.missing_information:
            return
        raise MissingInformationError(
            "Architecture information gaps must be resolved before threat modeling continues",
            error_code="MISSING_INFORMATION_BLOCKING",
            retryable=False,
            context={
                "missing_information": list(model.missing_information),
                "missing_information_count": len(model.missing_information),
            },
        )


class MissingInformationPolicyFactory:
    """Create the configured missing-information policy from settings."""

    @staticmethod
    def create(*, fail_on_missing_information: bool) -> MissingInformationPolicy:
        """Build either a permissive or blocking policy.

        Args:
            fail_on_missing_information: Whether unresolved gaps should fail the workflow.

        Returns:
            Policy implementation matching the requested enforcement mode.
        """
        if fail_on_missing_information:
            return BlockingMissingInformationPolicy()
        return PermissiveMissingInformationPolicy()
