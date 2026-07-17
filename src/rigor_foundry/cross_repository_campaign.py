# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-repository dependency campaigns
"""Freeze many repositories at exact commits for detached historical replay."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from ._remediation_graph import assert_dag
from .model_primitives import (
    require_digest,
    require_git_object,
    require_identifier,
    require_semantic_version,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_mapping, require_string

CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION = "1.0"

Availability = Literal["available", "unavailable"]
_AVAILABILITIES: frozenset[str] = frozenset({"available", "unavailable"})
CampaignResolution = Literal["complete", "unavailable"]

_FROZEN_FIELDS = (
    "head_commit",
    "head_tree",
    "policy_digest",
    "rule_pack_version",
    "rule_pack_digest",
    "adapter_lock_digest",
    "toolchain_digest",
)


@dataclass(frozen=True)
class RepositorySnapshot:
    """One repository frozen at an exact commit, or an explicit unavailability.

    An available snapshot carries every frozen digest for detached, read-only
    replay. An unavailable snapshot carries only a reason and never any digest,
    so an unresolved historical dependency is never mistaken for a passing one.

    Parameters
    ----------
    repository_id:
        Stable repository identifier.
    availability:
        ``available`` or ``unavailable``.
    head_commit:
        Frozen commit object identifier (available only).
    head_tree:
        Frozen tree object identifier (available only).
    policy_digest:
        Frozen audit-policy digest (available only).
    rule_pack_version:
        Frozen rule-pack version (available only).
    rule_pack_digest:
        Frozen rule-pack digest (available only).
    adapter_lock_digest:
        Frozen adapter-lock digest (available only).
    toolchain_digest:
        Frozen toolchain digest (available only).
    unavailable_reason:
        Reason the historical snapshot could not be resolved (unavailable only).

    """

    repository_id: str
    availability: Availability
    head_commit: str
    head_tree: str
    policy_digest: str
    rule_pack_version: str
    rule_pack_digest: str
    adapter_lock_digest: str
    toolchain_digest: str
    unavailable_reason: str
    snapshot_digest: str

    @classmethod
    def build(
        cls,
        *,
        repository_id: str,
        availability: Availability,
        head_commit: str = "",
        head_tree: str = "",
        policy_digest: str = "",
        rule_pack_version: str = "",
        rule_pack_digest: str = "",
        adapter_lock_digest: str = "",
        toolchain_digest: str = "",
        unavailable_reason: str = "",
    ) -> RepositorySnapshot:
        """Build one validated repository snapshot with an explicit availability."""
        if availability not in _AVAILABILITIES:
            raise ValueError("snapshot.availability is unsupported")
        frozen = {
            "head_commit": head_commit,
            "head_tree": head_tree,
            "policy_digest": policy_digest,
            "rule_pack_version": rule_pack_version,
            "rule_pack_digest": rule_pack_digest,
            "adapter_lock_digest": adapter_lock_digest,
            "toolchain_digest": toolchain_digest,
        }
        if availability == "available":
            if unavailable_reason:
                raise ValueError("available snapshot must not carry an unavailable reason")
            resolved = _validate_frozen(frozen)
            reason = ""
        else:
            if any(frozen[name] for name in _FROZEN_FIELDS):
                raise ValueError("unavailable snapshot must not carry frozen digests")
            resolved = dict.fromkeys(_FROZEN_FIELDS, "")
            reason = require_string(unavailable_reason, "snapshot.unavailable_reason")
        body: dict[str, object] = {
            "schema_version": CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION,
            "repository_id": require_identifier(repository_id, "snapshot.repository_id"),
            "availability": availability,
            **resolved,
            "unavailable_reason": reason,
        }
        return cls(
            repository_id=cast(str, body["repository_id"]),
            availability=availability,
            head_commit=resolved["head_commit"],
            head_tree=resolved["head_tree"],
            policy_digest=resolved["policy_digest"],
            rule_pack_version=resolved["rule_pack_version"],
            rule_pack_digest=resolved["rule_pack_digest"],
            adapter_lock_digest=resolved["adapter_lock_digest"],
            toolchain_digest=resolved["toolchain_digest"],
            unavailable_reason=reason,
            snapshot_digest=canonical_digest(body),
        )

    @property
    def is_available(self) -> bool:
        """Return whether the snapshot is a resolved, frozen repository."""
        return self.availability == "available"

    def to_dict(self) -> dict[str, object]:
        """Serialise one repository snapshot."""
        return {
            "schema_version": CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION,
            "repository_id": self.repository_id,
            "availability": self.availability,
            "head_commit": self.head_commit,
            "head_tree": self.head_tree,
            "policy_digest": self.policy_digest,
            "rule_pack_version": self.rule_pack_version,
            "rule_pack_digest": self.rule_pack_digest,
            "adapter_lock_digest": self.adapter_lock_digest,
            "toolchain_digest": self.toolchain_digest,
            "unavailable_reason": self.unavailable_reason,
            "snapshot_digest": self.snapshot_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> RepositorySnapshot:
        """Parse and integrity-check one repository snapshot."""
        data = require_mapping(value, "snapshot")
        if data.get("schema_version") != CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION:
            raise ValueError("unsupported snapshot schema version")
        snapshot = cls.build(
            repository_id=require_string(data.get("repository_id"), "snapshot.repository_id"),
            availability=cast(
                Availability,
                require_string(data.get("availability"), "snapshot.availability"),
            ),
            head_commit=require_string(
                data.get("head_commit", ""), "snapshot.head_commit", allow_empty=True
            ),
            head_tree=require_string(
                data.get("head_tree", ""), "snapshot.head_tree", allow_empty=True
            ),
            policy_digest=require_string(
                data.get("policy_digest", ""), "snapshot.policy_digest", allow_empty=True
            ),
            rule_pack_version=require_string(
                data.get("rule_pack_version", ""), "snapshot.rule_pack_version", allow_empty=True
            ),
            rule_pack_digest=require_string(
                data.get("rule_pack_digest", ""), "snapshot.rule_pack_digest", allow_empty=True
            ),
            adapter_lock_digest=require_string(
                data.get("adapter_lock_digest", ""),
                "snapshot.adapter_lock_digest",
                allow_empty=True,
            ),
            toolchain_digest=require_string(
                data.get("toolchain_digest", ""), "snapshot.toolchain_digest", allow_empty=True
            ),
            unavailable_reason=require_string(
                data.get("unavailable_reason", ""), "snapshot.unavailable_reason", allow_empty=True
            ),
        )
        if data.get("snapshot_digest") != snapshot.snapshot_digest:
            raise ValueError("snapshot digest does not match its content")
        return snapshot


def _require_prefixed_version(value: str, field: str) -> str:
    """Validate one ``rigor-foundry/``-prefixed rule-pack version and return it."""
    if not value.startswith("rigor-foundry/"):
        raise ValueError(f"{field} must be a rigor-foundry-prefixed version")
    require_semantic_version(value.removeprefix("rigor-foundry/"), field)
    return value


def _validate_frozen(frozen: dict[str, str]) -> dict[str, str]:
    """Validate every frozen field of an available snapshot."""
    return {
        "head_commit": require_git_object(frozen["head_commit"], "snapshot.head_commit"),
        "head_tree": require_git_object(frozen["head_tree"], "snapshot.head_tree"),
        "policy_digest": require_digest(frozen["policy_digest"], "snapshot.policy_digest"),
        "rule_pack_version": _require_prefixed_version(
            frozen["rule_pack_version"], "snapshot.rule_pack_version"
        ),
        "rule_pack_digest": require_digest(
            frozen["rule_pack_digest"], "snapshot.rule_pack_digest"
        ),
        "adapter_lock_digest": require_digest(
            frozen["adapter_lock_digest"], "snapshot.adapter_lock_digest"
        ),
        "toolchain_digest": require_digest(
            frozen["toolchain_digest"], "snapshot.toolchain_digest"
        ),
    }


@dataclass(frozen=True)
class InterRepositoryEdge:
    """One directed dependency edge from a dependent repository to its dependency.

    Parameters
    ----------
    from_repository:
        The dependent repository identifier.
    to_repository:
        The dependency repository identifier.
    relationship:
        Neutral relationship label, for example ``depends-on``.
    rationale:
        Why the dependency exists.

    """

    from_repository: str
    to_repository: str
    relationship: str
    rationale: str
    edge_digest: str

    @classmethod
    def build(
        cls,
        *,
        from_repository: str,
        to_repository: str,
        relationship: str,
        rationale: str,
    ) -> InterRepositoryEdge:
        """Build one validated inter-repository dependency edge."""
        source = require_identifier(from_repository, "edge.from_repository")
        target = require_identifier(to_repository, "edge.to_repository")
        if source == target:
            raise ValueError("edge.from_repository must differ from to_repository")
        body: dict[str, object] = {
            "from_repository": source,
            "to_repository": target,
            "relationship": require_string(relationship, "edge.relationship"),
            "rationale": require_string(rationale, "edge.rationale"),
        }
        return cls(
            from_repository=source,
            to_repository=target,
            relationship=cast(str, body["relationship"]),
            rationale=cast(str, body["rationale"]),
            edge_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one inter-repository edge."""
        return {
            "from_repository": self.from_repository,
            "to_repository": self.to_repository,
            "relationship": self.relationship,
            "rationale": self.rationale,
            "edge_digest": self.edge_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> InterRepositoryEdge:
        """Parse one inter-repository edge."""
        data = require_mapping(value, "edge")
        return cls.build(
            from_repository=require_string(data.get("from_repository"), "edge.from_repository"),
            to_repository=require_string(data.get("to_repository"), "edge.to_repository"),
            relationship=require_string(data.get("relationship"), "edge.relationship"),
            rationale=require_string(data.get("rationale"), "edge.rationale"),
        )


@dataclass(frozen=True)
class CrossRepositoryCampaign:
    """A frozen, acyclic set of repository snapshots for historical replay.

    The campaign only ever references detached git objects and digests, never an
    operator's working tree, so replay never changes a checkout. A campaign with
    any unavailable snapshot resolves to ``unavailable``, never a passing result.

    Parameters
    ----------
    campaign_id:
        Stable campaign identifier.
    frozen_at:
        UTC instant the historical replay was frozen.
    snapshots:
        One snapshot per repository.
    edges:
        Inter-repository dependency edges forming an acyclic graph.

    """

    campaign_id: str
    frozen_at: str
    snapshots: tuple[RepositorySnapshot, ...]
    edges: tuple[InterRepositoryEdge, ...]
    campaign_digest: str

    @classmethod
    def build(
        cls,
        *,
        campaign_id: str,
        frozen_at: str,
        snapshots: tuple[RepositorySnapshot, ...],
        edges: tuple[InterRepositoryEdge, ...] = (),
    ) -> CrossRepositoryCampaign:
        """Build one validated cross-repository campaign with acyclic dependencies."""
        if not snapshots:
            raise ValueError("campaign.snapshots must not be empty")
        repository_ids = tuple(snapshot.repository_id for snapshot in snapshots)
        validate_unique_strings(repository_ids, "campaign.repository_ids", minimum=1)
        present = set(repository_ids)
        adjacency: dict[str, tuple[str, ...]] = dict.fromkeys(repository_ids, ())
        seen_edges: set[tuple[str, str]] = set()
        for edge in edges:
            if edge.from_repository not in present or edge.to_repository not in present:
                raise ValueError("edge references a repository absent from the campaign")
            pair = (edge.from_repository, edge.to_repository)
            if pair in seen_edges:
                raise ValueError("campaign edges must be unique")
            seen_edges.add(pair)
            adjacency[edge.from_repository] = (
                *adjacency[edge.from_repository],
                edge.to_repository,
            )
        assert_dag(present, adjacency, "campaign.edges")
        body: dict[str, object] = {
            "schema_version": CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": require_identifier(campaign_id, "campaign.campaign_id"),
            "frozen_at": require_utc_timestamp(frozen_at, "campaign.frozen_at"),
            "snapshots": [snapshot.to_dict() for snapshot in snapshots],
            "edges": [edge.to_dict() for edge in edges],
        }
        return cls(
            campaign_id=cast(str, body["campaign_id"]),
            frozen_at=cast(str, body["frozen_at"]),
            snapshots=snapshots,
            edges=edges,
            campaign_digest=canonical_digest(body),
        )

    def is_complete(self) -> bool:
        """Return whether every repository snapshot is available."""
        return all(snapshot.is_available for snapshot in self.snapshots)

    def unavailable_repositories(self) -> tuple[str, ...]:
        """Return the sorted identifiers of unavailable snapshots."""
        return tuple(
            sorted(
                snapshot.repository_id for snapshot in self.snapshots if not snapshot.is_available
            )
        )

    def unavailable_dependencies(self) -> tuple[str, ...]:
        """Return the sorted dependency targets that are unavailable."""
        unavailable = set(self.unavailable_repositories())
        return tuple(sorted({edge.to_repository for edge in self.edges} & unavailable))

    def resolution(self) -> CampaignResolution:
        """Return ``complete`` only when every dependency is available."""
        return "complete" if self.is_complete() else "unavailable"

    def to_dict(self) -> dict[str, object]:
        """Serialise one cross-repository campaign."""
        return {
            "schema_version": CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "frozen_at": self.frozen_at,
            "snapshots": [snapshot.to_dict() for snapshot in self.snapshots],
            "edges": [edge.to_dict() for edge in self.edges],
            "campaign_digest": self.campaign_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> CrossRepositoryCampaign:
        """Parse and integrity-check one cross-repository campaign."""
        data = require_mapping(value, "campaign")
        if data.get("schema_version") != CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION:
            raise ValueError("unsupported campaign schema version")
        snapshots_raw = data.get("snapshots")
        edges_raw = data.get("edges")
        if not isinstance(snapshots_raw, list) or not isinstance(edges_raw, list):
            raise ValueError("campaign snapshots and edges must be arrays")
        campaign = cls.build(
            campaign_id=require_string(data.get("campaign_id"), "campaign.campaign_id"),
            frozen_at=require_string(data.get("frozen_at"), "campaign.frozen_at"),
            snapshots=tuple(
                RepositorySnapshot.from_dict(item) for item in cast(list[object], snapshots_raw)
            ),
            edges=tuple(
                InterRepositoryEdge.from_dict(item) for item in cast(list[object], edges_raw)
            ),
        )
        if data.get("campaign_digest") != campaign.campaign_digest:
            raise ValueError("campaign digest does not match its content")
        return campaign
