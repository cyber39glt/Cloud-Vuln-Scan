"""Architecture guards: rules stay pure, registered and fully mapped."""

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import app.rules
from app.domain.enums import Framework, Provider
from app.frameworks.catalog import FrameworkCatalog, load_catalog
from app.rules.base import Rule
from app.rules.registry import ALL_RULES

RULES_DIR = Path(app.rules.__file__).parent

# Rules must decide from the inventory alone: no cloud SDKs, network, processes or DB.
FORBIDDEN_IMPORTS = {
    "boto3", "botocore", "azure", "msgraph", "requests", "httpx", "httpx2", "aiohttp",
    "urllib", "http", "socket", "ssl", "subprocess", "sqlalchemy", "psycopg", "app.core.database",
}  # fmt: skip


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", sorted(RULES_DIR.rglob("*.py")), ids=lambda p: p.name)
def test_rule_code_has_no_io_imports(path):
    for name in _imports(path):
        root_matches = {name, name.split(".")[0]} & FORBIDDEN_IMPORTS
        assert not root_matches, f"{path.name} imports forbidden module {name!r}"


def _all_rule_classes() -> set[type[Rule]]:
    found = set()
    for module_info in pkgutil.walk_packages(app.rules.__path__, "app.rules."):
        module = importlib.import_module(module_info.name)
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, Rule)
                and value is not Rule
                and value.__module__ == module.__name__
            ):
                found.add(value)
    return found


def test_every_rule_class_is_registered():
    assert _all_rule_classes() == {type(rule) for rule in ALL_RULES}


def test_rule_ids_are_unique():
    ids = [rule.metadata.rule_id for rule in ALL_RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.metadata.rule_id)
def test_every_rule_maps_to_all_three_frameworks_per_provider(rule):
    catalog = load_catalog()
    cis = {Provider.AWS: Framework.CIS_AWS, Provider.AZURE: Framework.CIS_AZURE}
    for provider in rule.metadata.providers:
        assert catalog.frameworks_for(rule.metadata.rule_id, provider) == {
            cis[provider],
            Framework.NIST_CSF,
            Framework.SOC2,
        }


def test_catalog_rejects_unknown_framework_and_duplicates():
    framework = {"name": "N", "version": "1", "providers": ["aws"]}
    mapping = {"rule": "X-001", "framework": "nist_csf", "control": "A", "title": "t"}

    with pytest.raises(ValueError, match="undefined framework"):
        FrameworkCatalog({"mapping": [mapping | {"verified": True}]})
    with pytest.raises(ValueError, match="duplicate"):
        FrameworkCatalog(
            {
                "frameworks": {"nist_csf": framework},
                "mapping": [mapping | {"verified": True}, mapping | {"verified": False}],
            }
        )


def test_mapped_rules_all_exist():
    """A typo in mappings.toml must not silently attach references to nothing."""
    import tomllib

    from app.frameworks.catalog import DEFAULT_MAPPINGS_PATH

    data = tomllib.loads(DEFAULT_MAPPINGS_PATH.read_text(encoding="utf-8"))
    known = {rule.metadata.rule_id for rule in ALL_RULES}
    assert {m["rule"] for m in data["mapping"]} <= known
