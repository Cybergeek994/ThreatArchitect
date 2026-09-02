"""Build compact ASVS control indexes for LLM batch ranking."""

from __future__ import annotations

from threatmodeler.contracts.control_catalog import AsvsCompactControlRef, AsvsControlCatalogSnapshot


class AsvsCompactIndexBuilder:
    """Derive prompt-safe compact control rows from a catalog snapshot."""

    summary_max_length = 150

    def build(self, snapshot: AsvsControlCatalogSnapshot) -> tuple[AsvsCompactControlRef, ...]:
        """Build the compact index for ``snapshot``.

        Args:
            snapshot: Normalized ASVS catalog snapshot.

        Returns:
            Tuple of compact control references sorted by canonical id.
        """
        rows = [
            AsvsCompactControlRef(
                id=control.id,
                short_id=control.short_id,
                chapter_id=control.chapter_id,
                chapter_name=control.chapter_name,
                section_id=control.section_id,
                section_name=control.section_name,
                level=control.level,
                summary=self._truncate_summary(control.requirement_text),
            )
            for control in snapshot.controls
        ]
        return tuple(sorted(rows, key=lambda row: row.id))

    def _truncate_summary(self, text: str) -> str:
        normalized = " ".join(text.split())
        if len(normalized) <= self.summary_max_length:
            return normalized
        return normalized[: self.summary_max_length - 3].rstrip() + "..."
