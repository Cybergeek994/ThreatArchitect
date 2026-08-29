"""Curated OWASP ASVS 4.0 control catalog loader and matcher."""

from __future__ import annotations

import json
from importlib import resources

from pydantic import JsonValue, TypeAdapter

from threatmodeler.contracts.artifacts import SecurityRequirementCategory
from threatmodeler.errors import ConfigurationError
from threatmodeler.shared.constants import AsvsChapter, PackagedDataFile


class OwaspAsvsControl:
    """One curated OWASP ASVS control used for mapping constraints."""

    def __init__(self, control_id: str, chapter: str, name: str, keywords: tuple[str, ...]) -> None:
        self.id = control_id
        self.chapter = chapter
        self.name = name
        self.keywords = keywords


class OwaspAsvsCatalog:
    """Load and query the packaged OWASP ASVS control subset."""

    def __init__(self, controls: tuple[OwaspAsvsControl, ...]) -> None:
        if not controls:
            raise ConfigurationError(
                "OWASP ASVS catalog must contain at least one control",
                error_code="OWASP_ASVS_CATALOG_EMPTY",
                retryable=False,
                context={},
            )
        self._controls = controls
        self._by_id = {control.id: control for control in controls}

    @classmethod
    def load_default(cls) -> OwaspAsvsCatalog:
        """Load the packaged curated ASVS catalog.

        Returns:
            Catalog populated from ``threatmodeler.data.owasp_asvs_controls.json``.
        """
        payload = resources.files(PackagedDataFile.PACKAGE).joinpath(
            PackagedDataFile.OWASP_ASVS_CONTROLS
        )
        raw = json.loads(payload.read_text(encoding="utf-8"))
        controls = tuple(
            OwaspAsvsControl(
                control_id=str(entry["id"]),
                chapter=str(entry["chapter"]),
                name=str(entry["name"]),
                keywords=tuple(str(keyword) for keyword in entry.get("keywords", [])),
            )
            for entry in raw
        )
        return cls(controls)

    def contains(self, control_id: str) -> bool:
        """Return whether ``control_id`` is present in the catalog."""
        return control_id in self._by_id

    def get(self, control_id: str) -> OwaspAsvsControl | None:
        """Return a catalog entry by identifier when present."""
        return self._by_id.get(control_id)

    def all_controls(self) -> tuple[OwaspAsvsControl, ...]:
        """Return every catalogued control in definition order."""
        return self._controls

    def serialize(self) -> JsonValue:
        """Serialize catalog entries for agent prompt payloads."""
        adapter: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
        return adapter.validate_python(
            [
                {
                    "id": control.id,
                    "chapter": control.chapter,
                    "name": control.name,
                    "keywords": list(control.keywords),
                }
                for control in self._controls
            ]
        )

    def match(self, text: str, category: SecurityRequirementCategory) -> OwaspAsvsControl:
        """Select the best-matching ASVS control for a requirement.

        Args:
            text: Combined requirement name, statement, and description.
            category: Derived security-requirement category.

        Returns:
            Highest-scoring keyword match, or the first control in the category chapter.
        """
        haystack = text.lower()
        scored: list[tuple[int, OwaspAsvsControl]] = []
        for control in self._controls:
            score = sum(1 for keyword in control.keywords if keyword.lower() in haystack)
            if score:
                scored.append((score, control))
        if scored:
            scored.sort(key=lambda item: (-item[0], item[1].id))
            return scored[0][1]
        chapter = self._chapter_for(category)
        for control in self._controls:
            if control.chapter == chapter:
                return control
        return self._controls[0]

    def _chapter_for(self, category: SecurityRequirementCategory) -> str:
        if category is SecurityRequirementCategory.AUTHENTICATION:
            return AsvsChapter.V2
        if category is SecurityRequirementCategory.AUTHORIZATION:
            return AsvsChapter.V4
        if category is SecurityRequirementCategory.CONFIDENTIALITY:
            return AsvsChapter.V8
        if category is SecurityRequirementCategory.INTEGRITY:
            return AsvsChapter.V5
        if category is SecurityRequirementCategory.AVAILABILITY:
            return AsvsChapter.V12
        return AsvsChapter.V1
