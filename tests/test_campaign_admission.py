# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real campaign admission boundary tests
"""Exercise admission ordering through actual campaign filesystem operations."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_admission import CampaignCreation, create_admitted_campaign
from rigor_foundry.campaign_store import load_campaign


def _request(root: Path) -> CampaignCreation:
    """Bind one explicit local diagnostic campaign without native execution."""
    return CampaignCreation(
        repository_root=root,
        policy_path=Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="TEST-PROJECT",
        campaign_id="admitted-test",
        actor="test-owner",
        expected_runs=1,
    )


def _refuse(request: CampaignCreation) -> AbstractContextManager[None]:
    """Reject the request before entering any repository workflow."""
    raise PermissionError(request.campaign_id)


def test_refusal_precedes_nonexistent_repository_access(tmp_path: Path) -> None:
    """A denied request cannot create storage or fail first on missing Git input."""
    request = _request(tmp_path / "absent")
    with pytest.raises(PermissionError, match="admitted-test"):
        create_admitted_campaign(request, admission=_refuse)
    assert not request.repository_root.exists()


def test_lease_entry_refusal_precedes_storage(tmp_path: Path) -> None:
    """Deferred permission checks on context entry still precede every effect."""
    request = _request(tmp_path / "absent")

    @contextmanager
    def lease(received: CampaignCreation) -> Iterator[None]:
        """Use the same explicit refusal on context entry rather than construction."""
        _refuse(received)
        yield

    with pytest.raises(PermissionError):
        create_admitted_campaign(request, admission=lease)
    assert not request.repository_root.exists()


def test_refusal_preserves_real_repository(tmp_path: Path) -> None:
    """Real tracked and untracked input stays untouched when admission fails."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_policy()
    repo.commit()
    retained = repo.root / "owner-untracked.txt"
    retained.write_text("preserve these bytes")
    before = repo.git_command("status", "--porcelain").stdout
    with pytest.raises(PermissionError):
        create_admitted_campaign(_request(repo.root), admission=_refuse)
    assert not (repo.root / ".rigor").exists()
    assert retained.read_text() == "preserve these bytes"
    assert repo.git_command("status", "--porcelain").stdout == before


def test_creation_is_durable_before_lease_release(tmp_path: Path) -> None:
    """The actual campaign is persisted while its exact request lease is held."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_policy()
    repo.commit()
    request = _request(repo.root)
    observations: list[str] = []

    @contextmanager
    def lease(received: CampaignCreation) -> Iterator[None]:
        """Observe actual storage before admission and before releasing authority."""
        assert received is request
        assert not (repo.root / ".rigor").exists()
        observations.append("entered")
        try:
            yield
        finally:
            assert list((repo.root / ".rigor/audits").rglob("campaign.json"))
            observations.append("released")

    path, campaign = create_admitted_campaign(request, admission=lease)
    assert load_campaign(path) == campaign
    assert observations == ["entered", "released"]


def test_downstream_failure_releases_lease(tmp_path: Path) -> None:
    """A real missing-repository failure propagates after host lease cleanup."""
    released: list[bool] = []

    @contextmanager
    def lease(request: CampaignCreation) -> Iterator[None]:
        """Release host state even if the admitted operation fails."""
        assert not request.repository_root.exists()
        try:
            yield
        finally:
            released.append(True)

    with pytest.raises((ValueError, FileNotFoundError, RuntimeError)):
        create_admitted_campaign(_request(tmp_path / "absent"), admission=lease)
    assert released == [True]


def test_relative_repository_is_refused(tmp_path: Path) -> None:
    """Ambient working-directory changes cannot choose a different root."""
    with pytest.raises(ValueError, match="absolute"):
        replace(_request(tmp_path), repository_root=Path("relative"))


def test_suppressed_workflow_failure_cannot_look_successful(tmp_path: Path) -> None:
    """A misconfigured trusted provider cannot turn a failed creation into None."""

    @contextmanager
    def suppressing(request: CampaignCreation) -> Iterator[None]:
        """Deliberately violate the host contract to exercise explicit refusal."""
        assert not request.repository_root.exists()
        try:
            yield
        except (ValueError, FileNotFoundError, RuntimeError):
            return

    with pytest.raises(RuntimeError, match="suppressed"):
        create_admitted_campaign(_request(tmp_path / "absent"), admission=suppressing)
