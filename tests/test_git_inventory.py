# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real Git inventory tests
"""Verify exact tracked-content inventory against real Git worktrees."""

from __future__ import annotations

from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import (
    MAX_TEXT_BYTES,
    is_git_ignored,
    load_git_inventory,
)


def test_inventory_classifies_real_tracked_content_and_dirty_state(tmp_path: Path) -> None:
    """Text, binary, non-UTF8, symlink, oversize, and missing paths fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/text.py", "VALUE = 1\n")
    repository.write_bytes("src/pkg/binary.bin", b"a\0b")
    repository.write_bytes("src/pkg/non_utf8.py", b"\xff\xfe")
    repository.symlink("src/pkg/link.py", "text.py")
    large = repository.root / "src/pkg/large.py"
    large.parent.mkdir(parents=True, exist_ok=True)
    with large.open("wb") as handle:
        handle.seek(MAX_TEXT_BYTES)
        handle.write(b"x")
    head = repository.commit()
    (repository.root / "src/pkg/text.py").unlink()

    inventory = load_git_inventory(repository.root / "src")
    by_path = {item.path: item for item in inventory.files}
    assert inventory.head == head
    assert inventory.branch == "main"
    assert len(inventory.head_tree) == 40
    assert len(inventory.tracked_content_digest) == 64
    assert inventory.dirty_paths == ("src/pkg/text.py",)
    assert by_path["src/pkg/text.py"].content_kind == "missing"
    assert by_path["src/pkg/binary.bin"].content_kind == "binary"
    assert by_path["src/pkg/non_utf8.py"].content_kind == "non-utf8"
    assert by_path["src/pkg/link.py"].content_kind == "symlink"
    assert by_path["src/pkg/large.py"].content_kind == "oversize"
    assert all(len(item.content_digest) == 64 for item in inventory.files)
    assert not any(item.path == "src/pkg/text.py" for item in inventory.text_files())


def test_inventory_digest_tracks_worktree_bytes_and_rename_records(tmp_path: Path) -> None:
    """Tracked-content identity changes before commit and rename paths are both retained."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/a.py", "VALUE = 1\n")
    repository.commit()
    original = load_git_inventory(repository.root)
    repository.write_text("src/pkg/a.py", "VALUE = 2\n")
    changed = load_git_inventory(repository.root)
    assert changed.head == original.head
    assert changed.tracked_content_digest != original.tracked_content_digest
    repository.git_command("mv", "src/pkg/a.py", "src/pkg/b.py")
    renamed = load_git_inventory(repository.root)
    assert renamed.dirty_paths == ("src/pkg/a.py", "src/pkg/b.py")


def test_git_ignore_check_uses_real_repository_rules(tmp_path: Path) -> None:
    """Internal storage is accepted only when real Git ignore rules cover it."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    assert is_git_ignored(repository.root, Path(".coordination/audits/run.json"))
    assert is_git_ignored(repository.root, Path("docs/internal/work/INDEX.md"))
    assert not is_git_ignored(repository.root, Path("public-report.json"))
    with pytest.raises(ValueError, match="repository-relative"):
        is_git_ignored(repository.root, Path("../outside"))


def test_inventory_rejects_non_repository(tmp_path: Path) -> None:
    """Repository discovery fails closed outside a real Git worktree."""
    path = tmp_path / "not-a-repository"
    path.mkdir()
    with pytest.raises(RuntimeError, match=r"git .* failed"):
        load_git_inventory(path)
