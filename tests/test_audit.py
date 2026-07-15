# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Repository conformance audit tests
"""Exercise the production repository through its composed audit boundary."""

from pathlib import Path

from repository_audit_git_repository import GitRepository

from tools._repository import visible_files
from tools.audit import audit_errors


def test_repository_passes_portable_conformance_audit() -> None:
    """All required surfaces and nested guards agree on the worktree."""
    assert audit_errors() == []


def test_visible_inventory_omits_tracked_paths_deleted_during_authoring(tmp_path: Path) -> None:
    """A planned rename does not make validators dereference the removed source path."""
    repository = GitRepository.create(tmp_path / "repository")
    obsolete = repository.write_text("obsolete.txt", "old\n")
    repository.commit()
    obsolete.unlink()
    assert Path("obsolete.txt") not in visible_files(repository.root)
