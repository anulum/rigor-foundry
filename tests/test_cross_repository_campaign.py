# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-repository campaign tests
"""Verify frozen cross-repository replay distinguishes unavailable dependencies."""

from __future__ import annotations

from typing import cast

import pytest

from rigor_foundry.cross_repository_campaign import (
    Availability,
    CrossRepositoryCampaign,
    InterRepositoryEdge,
    RepositorySnapshot,
)

FROZEN_AT = "2026-07-15T10:00:00Z"


def available(repository_id: str) -> RepositorySnapshot:
    """Return one available, fully frozen repository snapshot."""
    return RepositorySnapshot.build(
        repository_id=repository_id,
        availability="available",
        head_commit="a" * 40,
        head_tree="b" * 40,
        policy_digest="c" * 64,
        rule_pack_version="rigor-foundry/1.1.0",
        rule_pack_digest="d" * 64,
        adapter_lock_digest="e" * 64,
        toolchain_digest="f" * 64,
    )


def unavailable(
    repository_id: str, reason: str = "historical commit was pruned"
) -> RepositorySnapshot:
    """Return one unavailable repository snapshot."""
    return RepositorySnapshot.build(
        repository_id=repository_id,
        availability="unavailable",
        unavailable_reason=reason,
    )


def edge(source: str, target: str) -> InterRepositoryEdge:
    """Return one dependency edge."""
    return InterRepositoryEdge.build(
        from_repository=source,
        to_repository=target,
        relationship="depends-on",
        rationale="shared component",
    )


def test_available_and_unavailable_snapshots_round_trip() -> None:
    """Both snapshot kinds validate, expose availability, and round-trip."""
    resolved = available("repo-app")
    assert resolved.is_available is True
    assert RepositorySnapshot.from_dict(resolved.to_dict()) == resolved

    missing = unavailable("repo-old")
    assert missing.is_available is False
    assert missing.head_commit == ""
    assert RepositorySnapshot.from_dict(missing.to_dict()) == missing


def test_snapshot_build_rejects_inconsistent_availability() -> None:
    """Availability, reason, digest, and version inconsistencies fail closed."""
    with pytest.raises(ValueError, match="availability is unsupported"):
        RepositorySnapshot.build(repository_id="r", availability=cast(Availability, "maybe"))
    with pytest.raises(ValueError, match="must not carry an unavailable reason"):
        RepositorySnapshot.build(
            repository_id="r",
            availability="available",
            head_commit="a" * 40,
            head_tree="b" * 40,
            policy_digest="c" * 64,
            rule_pack_version="rigor-foundry/1.1.0",
            rule_pack_digest="d" * 64,
            adapter_lock_digest="e" * 64,
            toolchain_digest="f" * 64,
            unavailable_reason="should not be here",
        )
    with pytest.raises(ValueError, match="must not carry frozen digests"):
        RepositorySnapshot.build(
            repository_id="r",
            availability="unavailable",
            head_commit="a" * 40,
            unavailable_reason="pruned",
        )
    with pytest.raises(ValueError, match="rigor-foundry-prefixed"):
        RepositorySnapshot.build(
            repository_id="r",
            availability="available",
            head_commit="a" * 40,
            head_tree="b" * 40,
            policy_digest="c" * 64,
            rule_pack_version="1.1.0",
            rule_pack_digest="d" * 64,
            adapter_lock_digest="e" * 64,
            toolchain_digest="f" * 64,
        )


def test_snapshot_from_dict_rejects_tampering() -> None:
    """Schema and digest tampering fail closed on parse."""
    good = available("repo-app").to_dict()
    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="snapshot schema version"):
        RepositorySnapshot.from_dict(bad_schema)
    bad_digest = dict(good)
    bad_digest["snapshot_digest"] = "0" * 64
    with pytest.raises(ValueError, match="snapshot digest"):
        RepositorySnapshot.from_dict(bad_digest)


def test_edge_rejects_self_reference_and_round_trips() -> None:
    """An edge round-trips and rejects a self-dependency."""
    dependency = edge("repo-app", "repo-lib")
    assert InterRepositoryEdge.from_dict(dependency.to_dict()) == dependency
    with pytest.raises(ValueError, match="must differ from to_repository"):
        edge("repo-app", "repo-app")


def test_campaign_resolution_distinguishes_unavailable_from_complete() -> None:
    """A complete campaign resolves complete; an unavailable dependency does not."""
    complete = CrossRepositoryCampaign.build(
        campaign_id="camp1",
        frozen_at=FROZEN_AT,
        snapshots=(available("repo-app"), available("repo-lib")),
        edges=(edge("repo-app", "repo-lib"),),
    )
    assert complete.is_complete() is True
    assert complete.resolution() == "complete"
    assert complete.unavailable_repositories() == ()
    assert complete.unavailable_dependencies() == ()
    assert CrossRepositoryCampaign.from_dict(complete.to_dict()) == complete

    degraded = CrossRepositoryCampaign.build(
        campaign_id="camp2",
        frozen_at=FROZEN_AT,
        snapshots=(available("repo-app"), unavailable("repo-lib")),
        edges=(edge("repo-app", "repo-lib"),),
    )
    assert degraded.is_complete() is False
    assert degraded.resolution() == "unavailable"
    assert degraded.unavailable_repositories() == ("repo-lib",)
    assert degraded.unavailable_dependencies() == ("repo-lib",)


def test_campaign_build_rejects_invalid_graphs() -> None:
    """Empty, duplicate, unknown-edge, duplicate-edge, and cyclic graphs fail closed."""
    with pytest.raises(ValueError, match="snapshots must not be empty"):
        CrossRepositoryCampaign.build(campaign_id="c", frozen_at=FROZEN_AT, snapshots=())
    with pytest.raises(ValueError, match="unique"):
        CrossRepositoryCampaign.build(
            campaign_id="c",
            frozen_at=FROZEN_AT,
            snapshots=(available("repo-app"), available("repo-app")),
        )
    with pytest.raises(ValueError, match="absent from the campaign"):
        CrossRepositoryCampaign.build(
            campaign_id="c",
            frozen_at=FROZEN_AT,
            snapshots=(available("repo-app"),),
            edges=(edge("repo-app", "repo-missing"),),
        )
    with pytest.raises(ValueError, match="edges must be unique"):
        CrossRepositoryCampaign.build(
            campaign_id="c",
            frozen_at=FROZEN_AT,
            snapshots=(available("repo-app"), available("repo-lib")),
            edges=(edge("repo-app", "repo-lib"), edge("repo-app", "repo-lib")),
        )
    with pytest.raises(ValueError, match="cycle"):
        CrossRepositoryCampaign.build(
            campaign_id="c",
            frozen_at=FROZEN_AT,
            snapshots=(available("repo-a"), available("repo-b")),
            edges=(edge("repo-a", "repo-b"), edge("repo-b", "repo-a")),
        )


def test_campaign_from_dict_rejects_tampering() -> None:
    """Schema, array shape, and digest tampering fail closed on parse."""
    good = CrossRepositoryCampaign.build(
        campaign_id="camp1",
        frozen_at=FROZEN_AT,
        snapshots=(available("repo-app"),),
    ).to_dict()

    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="campaign schema version"):
        CrossRepositoryCampaign.from_dict(bad_schema)

    bad_arrays = dict(good)
    bad_arrays["snapshots"] = "not-a-list"
    with pytest.raises(ValueError, match="must be arrays"):
        CrossRepositoryCampaign.from_dict(bad_arrays)

    bad_digest = dict(good)
    bad_digest["campaign_digest"] = "0" * 64
    with pytest.raises(ValueError, match="campaign digest"):
        CrossRepositoryCampaign.from_dict(bad_digest)
