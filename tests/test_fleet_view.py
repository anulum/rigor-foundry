# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fleet-view tests
"""Verify the read-only fleet view reports claim, dependency, and conflict state."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

import pytest

from rigor_foundry.claim_isolation import ClaimStatus, ExecutionClaim
from rigor_foundry.fleet_view import fleet_view

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
    """Return one active execution claim with test defaults."""
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


def test_empty_and_naive_instant() -> None:
    """An empty claim set yields an empty view; a naive instant fails closed."""
    view = fleet_view((), AT)
    assert view.repositories == ()
    assert view.claims_by_repository == ()
    assert view.stale_claim_ids == ()
    assert view.write_conflicts == ()
    with pytest.raises(ValueError, match="timezone-aware"):
        fleet_view((), datetime(2026, 7, 15, 10, 30))


def test_view_groups_and_reports_all_state() -> None:
    """The view groups holding claims and reports every conflict dimension."""
    conflict_a = claim("c1", write_set=("src/pkg/a.py",), serialization_keys=("build",))
    conflict_b = claim("c2", write_set=("src/pkg",), serialization_keys=("build",))
    other_campaign = claim("c3", campaign_id="campaign-2", write_set=("src/other.py",))
    cross_repo = claim("c4", repository_id="repo-b", write_set=("src/pkg/a.py",))
    dependent = claim("c5", write_set=("src/dep.py",), prerequisite_claim_ids=("c1",))
    stale = claim("c6", write_set=("src/old.py",), expires_at="2026-07-15T10:15:00Z")
    done = claim("c7", write_set=("src/done.py",)).complete()

    view = fleet_view(
        (conflict_a, conflict_b, other_campaign, cross_repo, dependent, stale, done),
        AT,
    )

    assert view.instant == "2026-07-15T10:30:00Z"
    assert view.repositories == ("repo-a", "repo-b")
    assert view.campaigns == ("campaign-1", "campaign-2")
    assert ("repo-b", ("c4",)) in view.claims_by_repository
    assert ("campaign-2", ("c3",)) in view.claims_by_campaign
    assert view.stale_claim_ids == ("c6",)
    assert view.terminal_claim_ids == ("c7",)
    # Same-repository overlap is reported; the cross-repository same path is not.
    assert view.write_conflicts == (("c1", "c2"),)
    assert view.serialization_contention == (("build", ("c1", "c2")),)
    assert view.dependency_edges == (("c5", "c1"),)


def test_single_key_is_not_contention_and_view_is_deterministic() -> None:
    """A key held by one claim is not contention; the view digest is stable."""
    solo = claim("c1", write_set=("src/a.py",), serialization_keys=("build",))
    other = claim("c2", write_set=("src/b.py",), serialization_keys=("test",))
    view = fleet_view((solo, other), AT)
    assert view.serialization_contention == ()
    assert fleet_view((other, solo), AT).view_digest == view.view_digest
    assert json.loads(json.dumps(view.to_dict())) == view.to_dict()
