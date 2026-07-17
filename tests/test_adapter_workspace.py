# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tracked-only adapter workspace tests
"""Verify real Git inventory selection and stable-copy boundaries."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapter_workspace import (
    MAX_PROFILE_FILE_BYTES,
    create_adapter_workspace,
    validate_profile_paths,
)
from rigor_foundry.git_inventory import load_git_inventory


def test_workspace_contains_only_selected_tracked_bytes(tmp_path: Path) -> None:
    """Ignored, untracked, and out-of-target files never enter the adapter snapshot."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(".gitignore", "ignored/\n")
    repository.write_text(".rigor/semgrep.yml", "rules: []\n")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.write_text("docs/guide.md", "not selected\n")
    repository.commit()
    repository.write_text("ignored/secret.txt", "must not cross boundary\n")
    repository.write_text("untracked.txt", "must not cross boundary\n")
    inventory = load_git_inventory(repository.root)

    with create_adapter_workspace(
        repository.root,
        configuration_path=".rigor/semgrep.yml",
        target_paths=("src",),
        expected_tracked_content_digest=inventory.tracked_content_digest,
    ) as workspace:
        assert (workspace.root / ".rigor/semgrep.yml").read_text() == "rules: []\n"
        assert (workspace.root / "src/module.py").read_text() == "VALUE = 1\n"
        assert not (workspace.root / "docs").exists()
        assert not (workspace.root / "ignored").exists()
        assert not (workspace.root / "untracked.txt").exists()
        assert workspace.input_files == 2
        snapshot_root = workspace.root
    assert not snapshot_root.exists()


def test_workspace_rejects_dirty_missing_oversize_and_mismatched_inputs(
    tmp_path: Path,
) -> None:
    """The snapshot fails closed for every input state it cannot reproduce exactly."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("config.yml", "rules: []\n")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)

    with pytest.raises(RuntimeError, match="does not match"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("src",),
            expected_tracked_content_digest="0" * 64,
        )
    repository.write_text("src/module.py", "VALUE = 2\n")
    with pytest.raises(RuntimeError, match="clean tracked worktree"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("src",),
        )
    repository.commit("test: update tracked input")
    with pytest.raises(RuntimeError, match="tracked regular file"):
        create_adapter_workspace(
            repository.root,
            configuration_path="absent.yml",
            target_paths=("src",),
        )
    with pytest.raises(RuntimeError, match="contains no tracked files"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("missing",),
        )
    assert (
        inventory.tracked_content_digest
        != load_git_inventory(repository.root).tracked_content_digest
    )

    repository.write_text("large/input.bin", "x" * (MAX_PROFILE_FILE_BYTES + 1))
    repository.commit("test: add oversized profile input")
    with pytest.raises(RuntimeError, match="per-file bound"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("large",),
        )


def test_workspace_rejects_multiple_links_and_noncanonical_paths(tmp_path: Path) -> None:
    """Hard links and ambiguous target spellings cannot cross the stable-read boundary."""
    repository = GitRepository.create(tmp_path / "repository")
    configuration = repository.write_text("config.yml", "rules: []\n")
    source = repository.write_text("src/module.py", "VALUE = 1\n")
    repository.commit()
    os.link(source, repository.root / "untracked-hardlink.py")

    with pytest.raises(RuntimeError, match="multiple hard links"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("src",),
        )
    os.unlink(repository.root / "untracked-hardlink.py")
    os.link(configuration, repository.root / "untracked-config-link.yml")
    with pytest.raises(RuntimeError, match="multiple hard links"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("src",),
        )

    for configuration_path, targets in (
        ("../config.yml", ("src",)),
        ("./config.yml", ("src",)),
        ("config.yml", ()),
        ("config.yml", ("src", "src")),
        ("config.yml", ("../src",)),
    ):
        with pytest.raises(ValueError):
            validate_profile_paths(configuration_path, targets)


def test_workspace_root_target_and_symlink_inputs_are_exact(tmp_path: Path) -> None:
    """The root target selects tracked regular files but never tracked symlink bytes."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("config.yml", "rules: []\n")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.commit()
    with create_adapter_workspace(
        repository.root,
        configuration_path="config.yml",
        target_paths=(".",),
    ) as workspace:
        assert workspace.input_files == 3

    (repository.root / "linked.py").symlink_to("src/module.py")
    repository.commit("test: add tracked symlink")
    with pytest.raises(RuntimeError, match="not a regular tracked file"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=(".",),
        )


def test_workspace_rejects_symlinked_parent_components(tmp_path: Path) -> None:
    """Tracked paths whose live parent becomes a symlink fail the no-follow walk."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("config.yml", "rules: []\n")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.commit()
    source = repository.root / "src"
    moved = repository.root / "moved-src"
    source.rename(moved)
    source.symlink_to(moved.name, target_is_directory=True)
    with pytest.raises(RuntimeError, match="cannot open tracked parent"):
        create_adapter_workspace(
            repository.root,
            configuration_path="config.yml",
            target_paths=("src",),
        )
