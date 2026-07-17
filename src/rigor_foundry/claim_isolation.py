# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — concurrent execution-claim isolation
"""Isolate concurrent execution claims by write set, key, and repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
from pathlib import PurePosixPath
from typing import Literal, cast

from ._remediation_graph import assert_dag, paths_overlap
from .model_primitives import (
    parse_utc_timestamp,
    require_identifier,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_mapping, require_string

CLAIM_ISOLATION_SCHEMA_VERSION = "1.0"

ClaimStatus = Literal["active", "completed", "cancelled", "rolled-back"]
_STATUSES: frozenset[str] = frozenset({"active", "completed", "cancelled", "rolled-back"})
_TERMINAL_STATUSES: frozenset[str] = frozenset({"completed", "cancelled", "rolled-back"})


def _relative_paths(value: tuple[str, ...], field: str) -> tuple[str, ...]:
    """Return unique repository-relative write-set paths without traversal."""
    paths = validate_unique_strings(value, field, minimum=1)
    for path in paths:
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"{field} must contain repository-relative paths without traversal")
    return paths


def _require_instant(value: datetime, field: str) -> datetime:
    """Return one timezone-aware UTC evaluation instant."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value


@dataclass(frozen=True)
class ExecutionClaim:
    """One repository-bound claim over a disjoint write set and serialization keys.

    Parameters
    ----------
    claim_id:
        Unique claim identifier.
    repository_id:
        Repository the claim is bound to; a claim never grants cross-repository
        authority.
    campaign_id:
        Campaign the claim belongs to.
    lane_id:
        Remediation lane the claim executes.
    claimant:
        Identity that holds the claim.
    write_set:
        Repository-relative paths the claim may write.
    serialization_keys:
        Mutual-exclusion keys; two active claims never share one.
    prerequisite_claim_ids:
        Same-repository claims that must precede this one.
    claimed_at:
        UTC claim time.
    expires_at:
        UTC expiry after which an unfinished claim is stale and recoverable.
    status:
        Lifecycle state.

    """

    claim_id: str
    repository_id: str
    campaign_id: str
    lane_id: str
    claimant: str
    write_set: tuple[str, ...]
    serialization_keys: tuple[str, ...]
    prerequisite_claim_ids: tuple[str, ...]
    claimed_at: str
    expires_at: str
    status: ClaimStatus
    claim_digest: str

    @classmethod
    def build(
        cls,
        *,
        claim_id: str,
        repository_id: str,
        campaign_id: str,
        lane_id: str,
        claimant: str,
        write_set: tuple[str, ...],
        serialization_keys: tuple[str, ...] = (),
        prerequisite_claim_ids: tuple[str, ...] = (),
        claimed_at: str,
        expires_at: str,
        status: ClaimStatus = "active",
    ) -> ExecutionClaim:
        """Build one validated, content-addressed execution claim."""
        if status not in _STATUSES:
            raise ValueError("claim.status is unsupported")
        identifier = require_identifier(claim_id, "claim.claim_id")
        prerequisites = validate_unique_strings(
            prerequisite_claim_ids,
            "claim.prerequisite_claim_ids",
        )
        if identifier in prerequisites:
            raise ValueError("claim.prerequisite_claim_ids must not include the claim itself")
        claimed = require_utc_timestamp(claimed_at, "claim.claimed_at")
        expires = require_utc_timestamp(expires_at, "claim.expires_at")
        if parse_utc_timestamp(expires, "claim.expires_at") <= parse_utc_timestamp(
            claimed,
            "claim.claimed_at",
        ):
            raise ValueError("claim.expires_at must be later than claimed_at")
        body: dict[str, object] = {
            "schema_version": CLAIM_ISOLATION_SCHEMA_VERSION,
            "claim_id": identifier,
            "repository_id": require_identifier(repository_id, "claim.repository_id"),
            "campaign_id": require_identifier(campaign_id, "claim.campaign_id"),
            "lane_id": require_identifier(lane_id, "claim.lane_id"),
            "claimant": require_string(claimant, "claim.claimant"),
            "write_set": list(_relative_paths(write_set, "claim.write_set")),
            "serialization_keys": list(
                validate_unique_strings(serialization_keys, "claim.serialization_keys")
            ),
            "prerequisite_claim_ids": list(prerequisites),
            "claimed_at": claimed,
            "expires_at": expires,
            "status": status,
        }
        return cls(
            claim_id=identifier,
            repository_id=cast(str, body["repository_id"]),
            campaign_id=cast(str, body["campaign_id"]),
            lane_id=cast(str, body["lane_id"]),
            claimant=cast(str, body["claimant"]),
            write_set=tuple(cast(list[str], body["write_set"])),
            serialization_keys=tuple(cast(list[str], body["serialization_keys"])),
            prerequisite_claim_ids=prerequisites,
            claimed_at=claimed,
            expires_at=expires,
            status=status,
            claim_digest=canonical_digest(body),
        )

    def holds_at(self, instant: datetime) -> bool:
        """Return whether the claim actively holds its resources at ``instant``."""
        _require_instant(instant, "claim evaluation instant")
        if self.status != "active":
            return False
        return instant < parse_utc_timestamp(self.expires_at, "claim.expires_at")

    def is_stale_at(self, instant: datetime) -> bool:
        """Return whether the claim is active but expired, hence recoverable."""
        _require_instant(instant, "claim evaluation instant")
        if self.status != "active":
            return False
        return instant >= parse_utc_timestamp(self.expires_at, "claim.expires_at")

    def _transition(self, status: ClaimStatus) -> ExecutionClaim:
        """Return the claim in a new terminal state; only an active claim moves."""
        if self.status != "active":
            raise ValueError("only an active claim may change state")
        return ExecutionClaim.build(
            claim_id=self.claim_id,
            repository_id=self.repository_id,
            campaign_id=self.campaign_id,
            lane_id=self.lane_id,
            claimant=self.claimant,
            write_set=self.write_set,
            serialization_keys=self.serialization_keys,
            prerequisite_claim_ids=self.prerequisite_claim_ids,
            claimed_at=self.claimed_at,
            expires_at=self.expires_at,
            status=status,
        )

    def complete(self) -> ExecutionClaim:
        """Release the claim after a successful lane."""
        return self._transition("completed")

    def cancel(self) -> ExecutionClaim:
        """Release the claim by cancellation."""
        return self._transition("cancelled")

    def roll_back(self) -> ExecutionClaim:
        """Release the claim after a rolled-back partial failure."""
        return self._transition("rolled-back")

    def to_dict(self) -> dict[str, object]:
        """Serialise one execution claim."""
        return {
            "schema_version": CLAIM_ISOLATION_SCHEMA_VERSION,
            "claim_id": self.claim_id,
            "repository_id": self.repository_id,
            "campaign_id": self.campaign_id,
            "lane_id": self.lane_id,
            "claimant": self.claimant,
            "write_set": list(self.write_set),
            "serialization_keys": list(self.serialization_keys),
            "prerequisite_claim_ids": list(self.prerequisite_claim_ids),
            "claimed_at": self.claimed_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "claim_digest": self.claim_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExecutionClaim:
        """Parse and integrity-check one execution claim."""
        data = require_mapping(value, "claim")
        if data.get("schema_version") != CLAIM_ISOLATION_SCHEMA_VERSION:
            raise ValueError("unsupported claim schema version")
        claim = cls.build(
            claim_id=require_string(data.get("claim_id"), "claim.claim_id"),
            repository_id=require_string(data.get("repository_id"), "claim.repository_id"),
            campaign_id=require_string(data.get("campaign_id"), "claim.campaign_id"),
            lane_id=require_string(data.get("lane_id"), "claim.lane_id"),
            claimant=require_string(data.get("claimant"), "claim.claimant"),
            write_set=_string_tuple(data.get("write_set"), "claim.write_set"),
            serialization_keys=_string_tuple(
                data.get("serialization_keys"),
                "claim.serialization_keys",
            ),
            prerequisite_claim_ids=_string_tuple(
                data.get("prerequisite_claim_ids"),
                "claim.prerequisite_claim_ids",
            ),
            claimed_at=require_utc_timestamp(data.get("claimed_at"), "claim.claimed_at"),
            expires_at=require_utc_timestamp(data.get("expires_at"), "claim.expires_at"),
            status=cast(ClaimStatus, require_string(data.get("status"), "claim.status")),
        )
        if data.get("claim_digest") != claim.claim_digest:
            raise ValueError("claim digest does not match its content")
        return claim


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    """Return one string tuple from a JSON array."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return tuple(require_string(item, f"{field}[]") for item in cast(list[object], value))


def holding_claims(
    claims: tuple[ExecutionClaim, ...],
    instant: datetime,
) -> tuple[ExecutionClaim, ...]:
    """Return the claims that actively hold resources at ``instant``."""
    return tuple(claim for claim in claims if claim.holds_at(instant))


def stale_claims(
    claims: tuple[ExecutionClaim, ...],
    instant: datetime,
) -> tuple[ExecutionClaim, ...]:
    """Return the active-but-expired claims recoverable at ``instant``."""
    return tuple(claim for claim in claims if claim.is_stale_at(instant))


def assert_claim_isolation(claims: tuple[ExecutionClaim, ...], instant: datetime) -> None:
    """Prove that all claims holding at ``instant`` are mutually isolated.

    Isolation is enforced per repository: two claims in different repositories
    never conflict, which is how a claim is denied any implicit cross-repository
    authority. Stale (expired) claims do not hold resources and never block.

    Parameters
    ----------
    claims:
        Every known claim, across repositories.
    instant:
        Timezone-aware UTC evaluation instant.

    Raises
    ------
    ValueError
        On duplicate claim ids, overlapping write sets, shared serialization
        keys, a cross-repository prerequisite, or a prerequisite cycle.
    """
    holding = holding_claims(claims, instant)
    identifiers = tuple(claim.claim_id for claim in holding)
    validate_unique_strings(identifiers, "claims.claim_id")
    by_repository: dict[str, list[ExecutionClaim]] = {}
    for claim in holding:
        by_repository.setdefault(claim.repository_id, []).append(claim)
    for group in by_repository.values():
        _assert_group_isolated(group)


def _assert_group_isolated(group: list[ExecutionClaim]) -> None:
    """Prove one repository's holding claims are pairwise isolated and acyclic."""
    for left, right in combinations(group, 2):
        if paths_overlap(left.write_set, right.write_set):
            raise ValueError(
                f"claims {left.claim_id} and {right.claim_id} have overlapping write sets"
            )
        if set(left.serialization_keys) & set(right.serialization_keys):
            raise ValueError(
                f"claims {left.claim_id} and {right.claim_id} share a serialization key"
            )
    present = {claim.claim_id for claim in group}
    edges: dict[str, tuple[str, ...]] = {}
    for claim in group:
        for prerequisite in claim.prerequisite_claim_ids:
            if prerequisite not in present:
                raise ValueError(
                    f"claim {claim.claim_id} has an out-of-repository prerequisite: {prerequisite}"
                )
        edges[claim.claim_id] = claim.prerequisite_claim_ids
    assert_dag(present, edges, "claims.prerequisites")


def admit_claim(
    active: tuple[ExecutionClaim, ...],
    candidate: ExecutionClaim,
    instant: datetime,
) -> tuple[ExecutionClaim, ...]:
    """Admit a candidate claim into the active set or fail closed.

    The candidate must be active. It is checked against the claims that hold at
    ``instant``; stale claims are recovered implicitly by not blocking.

    Parameters
    ----------
    active:
        Currently tracked claims.
    candidate:
        The new claim to admit.
    instant:
        Timezone-aware UTC evaluation instant.

    Returns
    -------
    tuple[ExecutionClaim, ...]
        The tracked claims including the admitted candidate.

    Raises
    ------
    ValueError
        If the candidate is not active or conflicts with a holding claim.
    """
    if candidate.status != "active":
        raise ValueError("only an active claim can be admitted")
    combined = (*active, candidate)
    assert_claim_isolation(combined, instant)
    return combined
