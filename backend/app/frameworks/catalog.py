"""Loads framework mappings from mappings.toml and answers "which controls does this
rule relate to, for this cloud provider?".

TOML is used because Python reads it natively (no extra dependency) and, unlike
JSON, it allows comments, which matter for documenting mapping decisions.
"""

import tomllib
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from app.domain.enums import Framework, Provider
from app.domain.findings import FrameworkRef

DEFAULT_MAPPINGS_PATH = Path(__file__).with_name("mappings.toml")


class _FrameworkInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str
    version: str
    providers: tuple[Provider, ...]


class _Mapping(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    rule: str
    framework: Framework
    control: str
    title: str
    verified: bool


class FrameworkCatalog:
    def __init__(self, data: dict) -> None:
        self._frameworks = {
            Framework(key): _FrameworkInfo(**value)
            for key, value in data.get("frameworks", {}).items()
        }
        self._by_rule: dict[str, list[tuple[_Mapping, _FrameworkInfo]]] = defaultdict(list)
        seen: set[tuple[str, Framework, str]] = set()
        for raw in data.get("mapping", []):
            mapping = _Mapping(**raw)
            if mapping.framework not in self._frameworks:
                raise ValueError(f"mapping uses undefined framework {mapping.framework!r}")
            key = (mapping.rule, mapping.framework, mapping.control)
            if key in seen:
                raise ValueError(f"duplicate mapping {key}")
            seen.add(key)
            self._by_rule[mapping.rule].append((mapping, self._frameworks[mapping.framework]))

    def refs_for(self, rule_id: str, provider: Provider) -> tuple[FrameworkRef, ...]:
        """References relevant to a finding from `provider` (a CIS AWS control is
        never attached to an Azure finding)."""
        return tuple(
            FrameworkRef(
                framework=mapping.framework,
                framework_name=info.name,
                version=info.version,
                control_id=mapping.control,
                title=mapping.title,
                verified=mapping.verified,
            )
            for mapping, info in self._by_rule.get(rule_id, [])
            if provider in info.providers
        )

    def frameworks_for(self, rule_id: str, provider: Provider) -> set[Framework]:
        return {ref.framework for ref in self.refs_for(rule_id, provider)}


@lru_cache
def load_catalog(path: Path = DEFAULT_MAPPINGS_PATH) -> FrameworkCatalog:
    with path.open("rb") as file:
        return FrameworkCatalog(tomllib.load(file))
