"""Executable guardrails for the codebase's architectural constraints."""

import ast
from collections.abc import Callable
from pathlib import Path

import pytest


@pytest.fixture
def project_root() -> Path:
    """Return the repository root regardless of this test module's nesting depth."""
    return Path(__file__).resolve().parents[3]


@pytest.fixture
def production_files(project_root: Path) -> list[Path]:
    """Return production Python modules without generated cache content."""
    package_dir = project_root / "threatmodeler"
    return sorted(package_dir.rglob("*.py"))


@pytest.fixture
def suite_files(project_root: Path) -> list[Path]:
    """Return maintained Python test modules and fixtures."""
    return sorted((project_root / "tests").rglob("*.py"))


@pytest.fixture
def parsed_module_factory() -> Callable[[Path], ast.Module]:
    """Return a fixture factory for parsing Python modules."""

    def create(path: Path) -> ast.Module:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    return create


@pytest.fixture
def imported_modules_factory() -> Callable[[ast.Module], set[str]]:
    """Return a fixture factory that collects imports from a syntax tree."""

    def create(module: ast.Module) -> set[str]:
        imported: set[str] = set()
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
        return imported

    return create


class TestArchitectureRulesPositive:
    """Verify supported inputs and successful behavior."""

    def test_production_code_does_not_use_dataclasses(
        self,
        production_files: list[Path],
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        offenders = [
            path
            for path in production_files
            if any(
                name == "dataclasses"
                for name in imported_modules_factory(parsed_module_factory(path))
            )
        ]

        assert offenders == []

    def test_production_code_does_not_contain_test_agent_providers(
        self,
        production_files: list[Path],
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        offenders = [
            path
            for path in production_files
            if "mock" in path.name.lower()
            or any(
                "mock_provider" in name
                for name in imported_modules_factory(parsed_module_factory(path))
            )
        ]

        assert offenders == []

    def test_production_modules_have_no_mutable_collection_state(
        self,
        production_files: list[Path],
        parsed_module_factory: Callable[[Path], ast.Module],
    ) -> None:
        mutable_nodes = (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)
        mutable_factories = {"list", "dict", "set", "defaultdict"}
        offenders: list[str] = []
        for path in production_files:
            module = parsed_module_factory(path)
            for node in module.body:
                value: ast.expr | None = None
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                is_mutable_factory = (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id in mutable_factories
                )
                if isinstance(value, mutable_nodes) or is_mutable_factory:
                    offenders.append(str(path))

        assert offenders == []

    def test_validation_layer_does_not_import_orchestration(
        self,
        project_root: Path,
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        validation_dir = project_root / "threatmodeler" / "validation"
        forbidden = [
            f"{path}:{module_name}"
            for path in validation_dir.glob("*.py")
            for module_name in imported_modules_factory(parsed_module_factory(path))
            if module_name.startswith("threatmodeler.orchestration")
        ]

        assert forbidden == []

    def test_domain_layer_does_not_import_orchestration(
        self,
        project_root: Path,
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        domain_dir = project_root / "threatmodeler" / "domain"
        forbidden = [
            f"{path}:{module_name}"
            for path in domain_dir.rglob("*.py")
            for module_name in imported_modules_factory(parsed_module_factory(path))
            if module_name.startswith("threatmodeler.orchestration")
        ]

        assert forbidden == []

    def test_renderers_do_not_depend_on_agent_providers(
        self,
        project_root: Path,
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        renderer_dir = project_root / "threatmodeler" / "renderers"
        forbidden_imports: list[str] = []
        for path in renderer_dir.glob("*.py"):
            for module_name in imported_modules_factory(parsed_module_factory(path)):
                if ".agents" in module_name or module_name.endswith("agent_provider"):
                    forbidden_imports.append(f"{path}:{module_name}")

        assert forbidden_imports == []

    def test_prompt_builders_do_not_depend_on_agent_providers(
        self,
        project_root: Path,
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        prompt_dir = project_root / "threatmodeler" / "orchestration" / "prompts"
        forbidden_imports: list[str] = []
        for path in prompt_dir.glob("*.py"):
            for module_name in imported_modules_factory(parsed_module_factory(path)):
                if ".agents" in module_name or module_name.endswith("agent_provider"):
                    forbidden_imports.append(f"{path}:{module_name}")

        assert forbidden_imports == []

    def test_cli_command_module_has_no_infrastructure_or_domain_dependencies(
        self,
        project_root: Path,
        parsed_module_factory: Callable[[Path], ast.Module],
        imported_modules_factory: Callable[[ast.Module], set[str]],
    ) -> None:
        command_module = project_root / "threatmodeler" / "cli" / "app.py"
        forbidden = [
            module_name
            for module_name in imported_modules_factory(parsed_module_factory(command_module))
            if module_name.startswith("threatmodeler.infrastructure")
            or module_name.startswith("threatmodeler.domain")
        ]

        assert forbidden == []

    def test_tests_use_classes_without_test_only_types_or_double_classes(
        self,
        suite_files: list[Path],
        parsed_module_factory: Callable[[Path], ast.Module],
    ) -> None:
        top_level_tests: list[str] = []
        test_only_types: list[str] = []
        custom_double_classes: list[str] = []
        static_test_methods: list[str] = []
        public_non_fixture_helpers: list[str] = []
        private_module_helpers: list[str] = []
        for path in suite_files:
            module = parsed_module_factory(path)
            for node in module.body:
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and node.name.startswith("test_"):
                    top_level_tests.append(f"{path}:{node.name}")
                if (
                    path.name.startswith("test_")
                    and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not node.name.startswith(("test_", "_"))
                ):
                    is_fixture = any(
                        isinstance(decorator, ast.Attribute)
                        and isinstance(decorator.value, ast.Name)
                        and decorator.value.id == "pytest"
                        and decorator.attr == "fixture"
                        for decorator in node.decorator_list
                    )
                    if not is_fixture:
                        public_non_fixture_helpers.append(f"{path}:{node.name}")
                if (
                    path.name.startswith("test_")
                    and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("_")
                ):
                    private_module_helpers.append(f"{path}:{node.name}")
                if isinstance(node, ast.ClassDef) and not node.name.startswith("Test"):
                    custom_double_classes.append(f"{path}:{node.name}")
                if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                    for method in node.body:
                        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        if method.name.startswith("test_") and any(
                            isinstance(decorator, ast.Name) and decorator.id == "staticmethod"
                            for decorator in method.decorator_list
                        ):
                            static_test_methods.append(f"{path}:{node.name}.{method.name}")
                if isinstance(node, ast.ImportFrom) and node.module in {
                    "typing",
                    "typing_extensions",
                }:
                    for alias in node.names:
                        if alias.name in {"NamedTuple", "TypedDict"}:
                            test_only_types.append(f"{path}:{alias.name}")

        assert top_level_tests == []
        assert test_only_types == []
        assert custom_double_classes == []
        assert static_test_methods == []
        assert public_non_fixture_helpers == []
        assert private_module_helpers == []
