"""Expected artifact and rendered-output inventories for tests."""

from pathlib import Path

EXPECTED_ARTIFACT_JSON_NAMES: frozenset[str] = frozenset(
    {
        "component-inventory.json",
        "asset-inventory.json",
        "actor-model.json",
        "dfd.json",
        "trust-boundary-map.json",
        "entry-points.json",
        "authz-model.json",
        "deployment-model.json",
        "stride-threats.json",
        "attack-tree.json",
        "abuse-cases.json",
        "risk-register.json",
        "mitigation-plan.json",
        "security-requirements.json",
        "assumptions.json",
        "missing-information.json",
        "control-mapping.json",
        "executive-summary.json",
        "technical-report.json",
        "completeness-report.json",
        "artifact-bundle.json",
    }
)

EXPECTED_RENDERED_PATHS: tuple[str, ...] = (
    "json/artifact-bundle.json",
    "mermaid/dfd.mmd",
    "mermaid/attack-tree.mmd",
    "mermaid/trust-boundaries.mmd",
    "markdown/technical-report.md",
    "flow/dfd.json",
)

EXPECTED_ANALYZE_JSON_COUNT = len(EXPECTED_ARTIFACT_JSON_NAMES) + 2


def assert_expected_artifact_json_files(output_dir: Path) -> None:
    """Assert every named model-stage artifact exists in ``output_dir``."""
    names = {path.name for path in output_dir.glob("*.json")}
    missing = EXPECTED_ARTIFACT_JSON_NAMES - names
    assert not missing, f"Missing artifact JSON files: {sorted(missing)}"


def assert_expected_rendered_outputs(rendered_dir: Path) -> None:
    """Assert every expected rendered output exists under ``rendered_dir``."""
    missing = [
        relative for relative in EXPECTED_RENDERED_PATHS if not (rendered_dir / relative).is_file()
    ]
    assert not missing, f"Missing rendered outputs: {missing}"
