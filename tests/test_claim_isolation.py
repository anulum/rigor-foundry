# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — execution-claim isolation tests
"""Verify concurrent claims stay disjoint, serialised, and repository-bound."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from rigor_foundry.claim_isolation import (
    ClaimStatus,
    ExecutionClaim,
    admit_claim,
    assert_claim_isolation,
    holding_claims,
    stale_claims,
)

CLAIMED_AT = "2026-07-15T10:00:00Z"
EXPIRES_AT = "2026-07-15T11:00:00Z"
AT = datetime(2026, 7, 15, 10, 30, tzinfo=UTC)


def claim(
    claim_id: str,
    *,
    repository_id: str = "repo-a",
    campaign_id: str = "campaign-1",
    write_set: tuple[str, ...] = ("src/pkg/a.py",),
    serialization_keys: tuple[str, ...] = (),
    prerequisite_claim_ids: tuple[str, ...] = (),
    expires_at: str = EXPIRES_AT,
    status: str = "active",
) -> ExecutionClaim:
    """Return one execution claim with test defaults."""
    return ExecutionClaim.build(
        claim_id=claim_id,
        repository_id=repository_id,
        campaign_id=campaign_id,
        lane_id=f"lane-{claim_id}",
        claimant="seat",
        write_set=write_set,
        serialization_keys=serialization_keys,
        prerequisite_claim_ids=prerequisite_claim_ids,
        claimed_at=CLAIMED_AT,
        expires_at=expires_at,
        status=cast(ClaimStatus, status),
    )


def test_claim_round_trips_and_reports_lifecycle_state() -> None:
    """A claim round-trips and reports holding, stale, and terminal state."""
    active = claim("c1")
    assert ExecutionClaim.from_dict(active.to_dict()) == active
    assert active.holds_at(AT) is True
    assert active.is_stale_at(AT) is False

    expired = claim("c2", expires_at="2026-07-15T10:15:00Z")
    assert expired.holds_at(AT) is False
    assert expired.is_stale_at(AT) is True

    done = active.complete()
    assert done.status == "completed"
    assert done.holds_at(AT) is False
    assert done.is_stale_at(AT) is False
    assert active.cancel().status == "cancelled"
    assert active.roll_back().status == "rolled-back"


def test_build_and_transition_reject_invalid_input() -> None:
    """Invalid status, self-prerequisite, expiry, and paths fail closed."""
    with pytest.raises(ValueError, match="status is unsupported"):
        claim("c1", status="paused")
    with pytest.raises(ValueError, match="must not include the claim itself"):
        claim("c1", prerequisite_claim_ids=("c1",))
    with pytest.raises(ValueError, match="later than claimed_at"):
        claim("c1", expires_at=CLAIMED_AT)
    with pytest.raises(ValueError, match="repository-relative"):
        claim("c1", write_set=("/etc/passwd",))
    with pytest.raises(ValueError, match="repository-relative"):
        claim("c1", write_set=("../escape.py",))
    with pytest.raises(ValueError, match="only an active claim"):
        claim("c1").complete().cancel()


def test_naive_instant_and_digest_and_schema_fail_closed() -> None:
    """A naive instant, a bad digest, and a bad schema fail closed."""
    active = claim("c1")
    with pytest.raises(ValueError, match="timezone-aware"):
        active.holds_at(datetime(2026, 7, 15, 10, 30))
    with pytest.raises(ValueError, match="timezone-aware"):
        active.is_stale_at(datetime(2026, 7, 15, 10, 30))
    tampered = active.to_dict()
    tampered["claim_digest"] = "0" * 64
    with pytest.raises(ValueError, match="claim digest"):
        ExecutionClaim.from_dict(tampered)
    bad_schema = active.to_dict()
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="schema version"):
        ExecutionClaim.from_dict(bad_schema)
    bad_array = active.to_dict()
    bad_array["write_set"] = "not-a-list"
    with pytest.raises(ValueError, match="must be an array"):
        ExecutionClaim.from_dict(bad_array)


def test_holding_and_stale_partition_claims() -> None:
    """Holding and stale helpers partition active claims by expiry."""
    active = claim("c1")
    expired = claim("c2", expires_at="2026-07-15T10:15:00Z")
    done = claim("c3").complete()
    claims = (active, expired, done)
    assert holding_claims(claims, AT) == (active,)
    assert stale_claims(claims, AT) == (expired,)


def test_isolation_enforces_disjoint_serialised_repo_bound_claims() -> None:
    """Overlap, shared keys, and cross-repository prerequisites fail closed."""
    overlap_a = claim("c1", write_set=("src/pkg/a.py",))
    overlap_b = claim("c2", write_set=("src/pkg",))
    with pytest.raises(ValueError, match="overlapping write sets"):
        assert_claim_isolation((overlap_a, overlap_b), AT)

    key_a = claim("c1", write_set=("src/a.py",), serialization_keys=("build",))
    key_b = claim("c2", write_set=("src/b.py",), serialization_keys=("build",))
    with pytest.raises(ValueError, match="share a serialization key"):
        assert_claim_isolation((key_a, key_b), AT)

    cross = claim("c3", repository_id="repo-b", prerequisite_claim_ids=("c1",))
    with pytest.raises(ValueError, match="out-of-repository prerequisite"):
        assert_claim_isolation((key_a, cross), AT)

    dup = claim("c1", write_set=("src/x.py",))
    with pytest.raises(ValueError, match="unique"):
        assert_claim_isolation((claim("c1", write_set=("src/y.py",)), dup), AT)


def test_valid_prerequisites_pass_and_cycles_fail() -> None:
    """A resolvable prerequisite chain passes; a prerequisite cycle fails closed."""
    root = claim("c1", write_set=("src/a.py",), serialization_keys=("k1",))
    dependent = claim(
        "c2",
        write_set=("src/b.py",),
        serialization_keys=("k2",),
        prerequisite_claim_ids=("c1",),
    )
    assert_claim_isolation((root, dependent), AT)

    cyclic_a = claim("c1", write_set=("src/a.py",), prerequisite_claim_ids=("c2",))
    cyclic_b = claim("c2", write_set=("src/b.py",), prerequisite_claim_ids=("c1",))
    with pytest.raises(ValueError, match="cycle"):
        assert_claim_isolation((cyclic_a, cyclic_b), AT)


def test_cross_repository_claims_never_conflict() -> None:
    """Two claims writing the same path in different repositories both hold."""
    same_path_a = claim("c1", repository_id="repo-a", write_set=("src/shared.py",))
    same_path_b = claim("c2", repository_id="repo-b", write_set=("src/shared.py",))
    assert_claim_isolation((same_path_a, same_path_b), AT)


def test_admit_recovers_stale_and_rejects_conflicts() -> None:
    """Admission ignores stale claims and rejects live conflicts and inactive candidates."""
    stale = claim("c1", write_set=("src/pkg/a.py",), expires_at="2026-07-15T10:15:00Z")
    fresh = claim("c2", write_set=("src/pkg/a.py",))
    admitted = admit_claim((stale,), fresh, AT)
    assert admitted == (stale, fresh)

    live = claim("c1", write_set=("src/pkg/a.py",))
    conflicting = claim("c2", write_set=("src/pkg/a.py",))
    with pytest.raises(ValueError, match="overlapping write sets"):
        admit_claim((live,), conflicting, AT)

    with pytest.raises(ValueError, match="only an active claim can be admitted"):
        admit_claim((), live.complete(), AT)
