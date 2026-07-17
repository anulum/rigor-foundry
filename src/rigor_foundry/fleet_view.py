# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only fleet views over execution claims
"""Summarise repository, campaign, claim, dependency, and conflict state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import combinations
from typing import cast

from ._remediation_graph import paths_overlap
from .claim_isolation import ExecutionClaim, holding_claims, stale_claims
from .models import canonical_digest

FLEET_VIEW_SCHEMA_VERSION = "1.0"


def _grouped_ids(claims: tuple[ExecutionClaim, ...], key: str) -> list[tuple[str, list[str]]]:
    """Return sorted ``(group, [claim_id, ...])`` pairs keyed by one field."""
    groups: dict[str, list[str]] = {}
    for claim in claims:
        group = cast(str, getattr(claim, key))
        groups.setdefault(group, []).append(claim.claim_id)
    return [(group, sorted(members)) for group, members in sorted(groups.items())]


def _write_conflicts(claims: tuple[ExecutionClaim, ...]) -> list[list[str]]:
    """Return sorted overlapping same-repository claim-id pairs."""
    conflicts: list[list[str]] = []
    for left, right in combinations(claims, 2):
        if left.repository_id != right.repository_id:
            continue
        if paths_overlap(left.write_set, right.write_set):
            conflicts.append(sorted((left.claim_id, right.claim_id)))
    return sorted(conflicts)


def _serialization_contention(claims: tuple[ExecutionClaim, ...]) -> list[tuple[str, list[str]]]:
    """Return sorted ``(key, [claim_id, ...])`` for keys held by more than one claim."""
    keys: dict[str, list[str]] = {}
    for claim in claims:
        for key in claim.serialization_keys:
            keys.setdefault(key, []).append(claim.claim_id)
    return [(key, sorted(members)) for key, members in sorted(keys.items()) if len(members) > 1]


def _dependency_edges(claims: tuple[ExecutionClaim, ...]) -> list[list[str]]:
    """Return sorted ``[claim_id, prerequisite_id]`` edges among the claims."""
    edges = [
        [claim.claim_id, prerequisite]
        for claim in claims
        for prerequisite in claim.prerequisite_claim_ids
    ]
    return sorted(edges)


@dataclass(frozen=True)
class FleetView:
    """A deterministic, read-only snapshot of concurrent execution-claim state.

    The view reports conflicts rather than rejecting them; it never mutates a
    claim or grants authority. Membership is computed at one evaluation instant.

    Parameters
    ----------
    instant:
        UTC evaluation instant.
    repositories:
        Repositories with a holding claim.
    campaigns:
        Campaigns with a holding claim.
    claims_by_repository:
        Holding claim ids grouped by repository.
    claims_by_campaign:
        Holding claim ids grouped by campaign.
    stale_claim_ids:
        Active-but-expired, recoverable claims.
    terminal_claim_ids:
        Completed, cancelled, or rolled-back claims.
    write_conflicts:
        Overlapping same-repository holding claim-id pairs.
    serialization_contention:
        Serialization keys held by more than one holding claim.
    dependency_edges:
        Prerequisite edges among holding claims.

    """

    instant: str
    repositories: tuple[str, ...]
    campaigns: tuple[str, ...]
    claims_by_repository: tuple[tuple[str, tuple[str, ...]], ...]
    claims_by_campaign: tuple[tuple[str, tuple[str, ...]], ...]
    stale_claim_ids: tuple[str, ...]
    terminal_claim_ids: tuple[str, ...]
    write_conflicts: tuple[tuple[str, str], ...]
    serialization_contention: tuple[tuple[str, tuple[str, ...]], ...]
    dependency_edges: tuple[tuple[str, str], ...]
    view_digest: str

    def to_dict(self) -> dict[str, object]:
        """Serialise the fleet view."""
        return {
            "schema_version": FLEET_VIEW_SCHEMA_VERSION,
            "instant": self.instant,
            "repositories": list(self.repositories),
            "campaigns": list(self.campaigns),
            "claims_by_repository": [
                [group, list(ids)] for group, ids in self.claims_by_repository
            ],
            "claims_by_campaign": [[group, list(ids)] for group, ids in self.claims_by_campaign],
            "stale_claim_ids": list(self.stale_claim_ids),
            "terminal_claim_ids": list(self.terminal_claim_ids),
            "write_conflicts": [list(pair) for pair in self.write_conflicts],
            "serialization_contention": [
                [key, list(ids)] for key, ids in self.serialization_contention
            ],
            "dependency_edges": [list(edge) for edge in self.dependency_edges],
            "view_digest": self.view_digest,
        }


def fleet_view(claims: tuple[ExecutionClaim, ...], instant: datetime) -> FleetView:
    """Compute one deterministic fleet view of the claim set at ``instant``.

    Parameters
    ----------
    claims:
        Every known claim across repositories and campaigns.
    instant:
        Timezone-aware UTC evaluation instant.

    Returns
    -------
    FleetView
        The read-only aggregate of repository, campaign, claim, dependency, and
        conflict state.
    """
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("fleet_view instant must be timezone-aware")
    stamp = instant.astimezone(UTC).isoformat().replace("+00:00", "Z")
    holding = holding_claims(claims, instant)
    repositories = sorted({claim.repository_id for claim in holding})
    campaigns = sorted({claim.campaign_id for claim in holding})
    by_repository = _grouped_ids(holding, "repository_id")
    by_campaign = _grouped_ids(holding, "campaign_id")
    stale = sorted(claim.claim_id for claim in stale_claims(claims, instant))
    terminal = sorted(claim.claim_id for claim in claims if claim.status != "active")
    conflicts = _write_conflicts(holding)
    contention = _serialization_contention(holding)
    edges = _dependency_edges(holding)
    body: dict[str, object] = {
        "schema_version": FLEET_VIEW_SCHEMA_VERSION,
        "instant": stamp,
        "repositories": repositories,
        "campaigns": campaigns,
        "claims_by_repository": [[group, ids] for group, ids in by_repository],
        "claims_by_campaign": [[group, ids] for group, ids in by_campaign],
        "stale_claim_ids": stale,
        "terminal_claim_ids": terminal,
        "write_conflicts": conflicts,
        "serialization_contention": [[key, ids] for key, ids in contention],
        "dependency_edges": edges,
    }
    return FleetView(
        instant=stamp,
        repositories=tuple(repositories),
        campaigns=tuple(campaigns),
        claims_by_repository=tuple((group, tuple(ids)) for group, ids in by_repository),
        claims_by_campaign=tuple((group, tuple(ids)) for group, ids in by_campaign),
        stale_claim_ids=tuple(stale),
        terminal_claim_ids=tuple(terminal),
        write_conflicts=tuple((pair[0], pair[1]) for pair in conflicts),
        serialization_contention=tuple((key, tuple(ids)) for key, ids in contention),
        dependency_edges=tuple((edge[0], edge[1]) for edge in edges),
        view_digest=canonical_digest(body),
    )
