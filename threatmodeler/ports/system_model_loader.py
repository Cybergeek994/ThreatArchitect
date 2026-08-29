"""Canonical system model loading port."""

from pathlib import Path
from typing import Protocol

from threatmodeler.contracts.system_model import CanonicalSystemModel


class SystemModelLoader(Protocol):
    """Define loading of canonical models from delivery-specific sources."""

    def load(self, path: Path) -> CanonicalSystemModel:
        """Load and return one validated canonical system model.

        Args:
            path: Delivery-specific location of serialized canonical-model data.

        Returns:
            Validated canonical system model.

        Raises:
            AgentSchemaValidationError: If the source cannot produce a valid model.
        """
        ...
