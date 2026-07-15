# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable campaign storage tests
"""Verify canonical ignored storage paths and create-only persistence."""

from __future__ import annotations

from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_store import campaign_relative_path, store_campaign
from rigor_foundry.campaign_workflow import create_campaign


def _repository(path: Path) -> GitRepository:
    """Create one real repository suitable for a frozen campaign."""
    repository = GitRepository.create(path)
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_policy()
    repository.commit()
    return repository


def test_campaign_storage_is_canonical_ignored_and_create_only(tmp_path: Path) -> None:
    """A campaign has one ignored path and cannot overwrite its immutable manifest."""
    repository = _repository(tmp_path / "repository")
    path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="campaign-one",
        actor="coordinator/one",
        expected_independent_runs=1,
    )

    expected = campaign_relative_path(
        Path(".rigor/audits"),
        "SAMPLE-PROJECT",
        "campaign-one",
    )
    assert path == repository.root / expected
    assert repository.git_command("check-ignore", expected.as_posix()).returncode == 0
    with pytest.raises(FileExistsError):
        store_campaign(repository.root, Path(".rigor/audits"), campaign)
