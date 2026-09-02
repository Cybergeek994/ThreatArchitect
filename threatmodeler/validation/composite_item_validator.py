"""Composite pattern for chaining construction-session item validators."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from pydantic import JsonValue

from threatmodeler.ports.artifact_construction_session_factory import ItemValidator


class CompositeItemValidator:
    """Run multiple item validators and concatenate their violations."""

    def __init__(self, validators: Sequence[ItemValidator]) -> None:
        self._validators = tuple(validators)

    @classmethod
    def of(cls, *validators: ItemValidator | None) -> ItemValidator | None:
        """Build a composite from optional validators, dropping ``None`` entries.

        Args:
            *validators: Validators to chain; ``None`` values are ignored.

        Returns:
            ``None`` when no validators remain, a single validator when only one
            remains, otherwise a composite that runs all validators.
        """
        active = [validator for validator in validators if validator is not None]
        if not active:
            return None
        if len(active) == 1:
            return active[0]
        return cls(active)

    def __call__(
        self,
        list_field: str,
        payload: dict[str, JsonValue],
        lists: Mapping[str, list[dict[str, JsonValue]]],
    ) -> list[str]:
        """Return the concatenated violations from every child validator."""
        violations: list[str] = []
        for validator in self._validators:
            violations.extend(validator(list_field, payload, lists))
        return violations
