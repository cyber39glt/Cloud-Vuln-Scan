"""Normalized cloud inventory: what a scan discovered, in one common shape.

Every AWS or Azure object becomes a `Resource` with the same envelope (provider,
account, region, type, ID, name, tags, properties). Concepts that exist in both clouds
get a typed *facet* so one rule can evaluate both, e.g. `NetworkIngressRule` for AWS
security group rules and Azure NSG rules alike.

An `Inventory` also records `CollectionGap`s: data the collector could NOT read. The
engine uses them to report "not evaluated" instead of a false pass.
"""

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.enums import Provider

# Source values meaning "any address on the internet". Collectors should normalize to
# CIDR notation, but Azure service tags ("Internet", "*") are accepted defensively.
INTERNET_SOURCES = frozenset({"0.0.0.0/0", "::/0", "*", "internet", "any"})


class _Frozen(BaseModel):
    # Frozen: once created, a model cannot be modified. Scan data is evidence and
    # must not change after collection.
    model_config = ConfigDict(frozen=True, extra="forbid")


class NetworkIngressRule(_Frozen):
    """One inbound firewall rule, normalized across AWS security groups and Azure NSGs."""

    protocol: Literal["tcp", "udp", "icmp", "all"]
    port_from: int = Field(ge=0, le=65535)
    port_to: int = Field(ge=0, le=65535)
    source: str = Field(min_length=1)
    action: Literal["allow", "deny"] = "allow"
    priority: int | None = None  # Azure NSG priority (lower = evaluated first); AWS has none.
    rule_name: str | None = None

    @model_validator(mode="after")
    def _check_port_range(self) -> Self:
        if self.port_to < self.port_from:
            raise ValueError("port_to must be greater than or equal to port_from")
        return self

    @property
    def is_from_internet(self) -> bool:
        return self.source.strip().lower() in INTERNET_SOURCES

    def covers_port(self, port: int, protocol: Literal["tcp", "udp"] = "tcp") -> bool:
        return self.protocol in (protocol, "all") and self.port_from <= port <= self.port_to


class Resource(_Frozen):
    provider: Provider
    account_id: str = Field(min_length=1)  # AWS account ID or Azure subscription ID
    region: str = Field(min_length=1)  # "global" for global services
    resource_type: str = Field(pattern=r"^(aws|azure)\.[a-z0-9_]+\.[a-z0-9_]+$")
    resource_id: str = Field(min_length=1)  # ARN or Azure resource ID
    name: str
    tags: dict[str, str] = Field(default_factory=dict)
    # Only the configuration fields rules need: collect less, expose less.
    properties: dict[str, Any] = Field(default_factory=dict)
    ingress_rules: tuple[NetworkIngressRule, ...] = ()
    # Where the data came from, for evidence: e.g. "ec2:DescribeSecurityGroups".
    source_operation: str = Field(min_length=1)
    collected_at: datetime


class CollectionGap(_Frozen):
    """Something the collector could not read, e.g. access denied in one region."""

    resource_type: str
    region: str | None = None  # None = every region / account-wide
    reason: str


class Inventory(_Frozen):
    """Everything collected from ONE AWS account or ONE Azure subscription."""

    provider: Provider
    account_id: str = Field(min_length=1)
    regions: tuple[str, ...]
    collected_at: datetime
    resources: tuple[Resource, ...] = ()
    gaps: tuple[CollectionGap, ...] = ()

    @model_validator(mode="after")
    def _resources_belong_to_this_account(self) -> Self:
        # Client separation starts here: an inventory may never mix accounts.
        for resource in self.resources:
            if resource.provider != self.provider or resource.account_id != self.account_id:
                raise ValueError(
                    f"resource {resource.resource_id!r} does not belong to "
                    f"{self.provider}:{self.account_id}"
                )
        return self

    def of_type(self, *resource_types: str) -> list[Resource]:
        return [r for r in self.resources if r.resource_type in resource_types]

    def gaps_for(self, resource_types: tuple[str, ...]) -> list[CollectionGap]:
        return [g for g in self.gaps if g.resource_type in resource_types]
