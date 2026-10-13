# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptor-bound path admission tests
"""Exercise selected roots, nested repositories and no-follow path descent."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from threading import Event, Thread
from types import FrameType

import pytest

from rigor_foundry.tier0_builtin import path_admission_v2
from rigor_foundry.tier0_builtin.path_admission_v2 import (
    PinnedDirectoryV2,
    PinnedPathScopeV2,
    RegisteredRootUnavailableV2,
    canonicalize_atomic_path_v2,
    is_bare_repository_layout,
    open_admitted_parent_v2,
)


def _pin(path: Path) -> PinnedDirectoryV2:
    """Pin one canonical test directory path."""
    return PinnedDirectoryV2(str(path))


def _scope(
    mono: Path,
    project: Path,
    *,
    root: Path | None = None,
    groups: tuple[Path, ...] = (),
    other_projects: tuple[Path, ...] = (),
    selected_project: Path | None = None,
) -> PinnedPathScopeV2:
    """Build a protected-selection shaped fixture with pinned roots."""
    return PinnedPathScopeV2(
        _pin(mono),
        _pin(root or project),
        str(selected_project or project),
        tuple(_pin(path) for path in (project, *other_projects)),
        tuple(_pin(path) for path in groups),
    )


def test_project_and_monorepo_git_entries_are_allowed(tmp_path: Path) -> None:
    """Normal project writes survive the two exempt repository roots."""
    mono = tmp_path / "mono"
    project = mono / "group" / "repositories" / "project"
    (project / "src").mkdir(parents=True)
    (mono / ".git").mkdir()
    (project / ".git").mkdir()
    target = project / "src" / "new.txt"
    scope = _scope(mono, project)
    with open_admitted_parent_v2(str(target), scope) as admitted:
        assert admitted.target_name == "new.txt"
        assert not admitted.target_exists
        assert os.fstat(admitted.parent_fd).st_ino == (project / "src").stat().st_ino
        assert os.fstat(admitted.root_fd).st_ino == project.stat().st_ino
    assert canonicalize_atomic_path_v2(str(target), scope) == {
        "form": "path",
        "value": str(target),
    }
    target.write_bytes(b"old")
    with open_admitted_parent_v2(str(target), scope) as admitted:
        assert admitted.target_exists


@pytest.mark.parametrize("git_kind", ["directory", "file", "symlink"])
def test_nested_git_entry_of_any_kind_refuses(tmp_path: Path, git_kind: str) -> None:
    """Nested repository, submodule and symlink spellings all refuse."""
    mono = tmp_path / "mono"
    project = mono / "project"
    child = project / "vendor"
    child.mkdir(parents=True)
    if git_kind == "directory":
        (child / ".git").mkdir()
    elif git_kind == "file":
        (child / ".git").write_text("gitdir: elsewhere")
    else:
        (child / ".git").symlink_to(project)
    with pytest.raises(PermissionError, match="nested repository"):
        canonicalize_atomic_path_v2(str(child / "new.txt"), _scope(mono, project))


def test_git_path_segment_and_root_git_file_refuse(tmp_path: Path) -> None:
    """A direct internal target and a worktree-style root both refuse."""
    mono = tmp_path / "mono"
    project = mono / "project"
    project.mkdir(parents=True)
    (project / ".git").mkdir()
    with pytest.raises(PermissionError, match=r"\.git path segment"):
        canonicalize_atomic_path_v2(str(project / ".git" / "config"), _scope(mono, project))
    (project / ".git").rmdir()
    (project / ".git").write_text("gitdir: elsewhere")
    with pytest.raises(PermissionError, match="nested repository at selected root"):
        canonicalize_atomic_path_v2(str(project / "new.txt"), _scope(mono, project))


def test_git_directory_at_selected_project_subdirectory_refuses(tmp_path: Path) -> None:
    """A path selector cannot exempt a nested repository by making it R."""
    mono = tmp_path / "mono"
    project = mono / "project"
    docs = project / "docs"
    (docs / ".git").mkdir(parents=True)
    scope = _scope(mono, project, root=docs)
    with pytest.raises(PermissionError, match="nested repository at selected root"):
        canonicalize_atomic_path_v2(str(docs / "new.txt"), scope)


def test_first_operation_requires_selected_project_root(tmp_path: Path) -> None:
    """A plain project subdirectory cannot become the first operation's root."""
    mono = tmp_path / "mono"
    project = mono / "group" / "project"
    docs = project / "docs"
    docs.mkdir(parents=True)
    assert canonicalize_atomic_path_v2(str(project / "new.txt"), _scope(mono, project))
    with pytest.raises(PermissionError, match="selected root differs from registered project"):
        canonicalize_atomic_path_v2(str(docs / "new.txt"), _scope(mono, project, root=docs))


def _rename_during_root_reresolution(root: Path, *, replace_root: bool) -> None:
    """Move a real directory after descent, before its registered-root lookup."""
    mono = root / "mono"
    project = mono / "group" / "project"
    other = mono / "other"
    moved = mono / "moved"
    project.mkdir(parents=True)
    if replace_root:
        other.mkdir()
    scope = _scope(mono, project)
    target = str(project / "new.txt")
    started = Event()
    finished = Event()
    errors: list[OSError] = []

    def rename_root() -> None:
        """Perform the actual rename in a concurrent thread."""
        if not started.wait(5):
            return
        try:
            project.rename(moved)
            if replace_root:
                other.rename(project)
        except OSError as exc:
            errors.append(exc)
        finally:
            finished.set()

    worker = Thread(target=rename_root)
    worker.start()
    lookup_code = path_admission_v2._current_root_identity.__code__
    old_profile = sys.getprofile()
    reached_lookup = False

    def at_lookup(frame: FrameType, event: str, _arg: object) -> None:
        """Pause scheduling only; leave the real lookup and OS calls intact."""
        nonlocal reached_lookup
        if (
            event == "call"
            and not reached_lookup
            and frame.f_code is lookup_code
            and frame.f_locals.get("path") == str(project)
        ):
            reached_lookup = True
            started.set()
            assert finished.wait(5), "concurrent renamer did not finish"

    try:
        sys.setprofile(at_lookup)
        with pytest.raises(PermissionError, match="root-moved"):
            canonicalize_atomic_path_v2(target, scope)
    finally:
        sys.setprofile(old_profile)
        started.set()
        worker.join(timeout=5)
    assert reached_lookup
    assert not worker.is_alive()
    assert not errors
    assert moved.is_dir()
    assert project.is_dir() == replace_root


@pytest.mark.parametrize("replace_root", [False, True])
def test_real_concurrent_root_move_refuses(tmp_path: Path, replace_root: bool) -> None:
    """Sixteen actual remove or replace races never admit a mismatched root."""
    for round_number in range(16):
        _rename_during_root_reresolution(
            tmp_path / f"round-{round_number}", replace_root=replace_root
        )


def test_git_directory_at_selected_group_root_refuses(tmp_path: Path) -> None:
    """A group selector cannot exempt its own repository entry."""
    mono = tmp_path / "mono"
    group = mono / "group"
    group.mkdir(parents=True)
    (group / ".git").mkdir()
    scope = PinnedPathScopeV2(_pin(mono), _pin(group), None, (), (_pin(group),))
    with pytest.raises(PermissionError, match="nested repository at selected root"):
        canonicalize_atomic_path_v2(str(group / "new.txt"), scope)


def test_bare_selected_group_root_refuses(tmp_path: Path) -> None:
    """The same bare-layout rule applies when a group directory is R."""
    mono = tmp_path / "mono"
    group = mono / "group"
    group.mkdir(parents=True)
    (group / "HEAD").write_text("ref: refs/heads/main")
    (group / "objects").mkdir()
    (group / "refs").mkdir()
    scope = PinnedPathScopeV2(_pin(mono), _pin(group), None, (), (_pin(group),))
    with pytest.raises(PermissionError, match="bare repository"):
        canonicalize_atomic_path_v2(str(group / "new.txt"), scope)


def test_bare_layout_and_near_miss(tmp_path: Path) -> None:
    """One bare-layout predicate distinguishes directory refs from a file."""
    mono = tmp_path / "mono"
    project = mono / "project"
    project.mkdir(parents=True)
    (project / "HEAD").write_text("ref: refs/heads/main")
    (project / "objects").mkdir()
    (project / "refs").write_text("near miss")
    fd = os.open(project, os.O_PATH | os.O_DIRECTORY)
    try:
        assert not is_bare_repository_layout(fd)
    finally:
        os.close(fd)
    assert canonicalize_atomic_path_v2(str(project / "new.txt"), _scope(mono, project))
    (project / "refs").unlink()
    (project / "refs").mkdir()
    with pytest.raises(PermissionError, match="bare repository"):
        canonicalize_atomic_path_v2(str(project / "new.txt"), _scope(mono, project))


def test_unregistered_ancestor_repository_added_after_pin_refuses(tmp_path: Path) -> None:
    """A later git init between monorepo and root is seen on re-resolution."""
    mono = tmp_path / "mono"
    middle = mono / "unregistered"
    project = middle / "project"
    project.mkdir(parents=True)
    scope = _scope(mono, project)
    assert canonicalize_atomic_path_v2(str(project / "new.txt"), scope)
    (middle / ".git").mkdir()
    with pytest.raises(PermissionError, match="unregistered-ancestor-repository"):
        canonicalize_atomic_path_v2(str(project / "new.txt"), scope)


def test_symlink_and_directory_target_refuse(tmp_path: Path) -> None:
    """Neither a symlinked parent nor a non-regular final target is admitted."""
    mono = tmp_path / "mono"
    project = mono / "project"
    project.mkdir(parents=True)
    (project / "link").symlink_to(mono)
    with pytest.raises(OSError):
        canonicalize_atomic_path_v2(str(project / "link" / "new.txt"), _scope(mono, project))
    (project / "directory").mkdir()
    with pytest.raises(PermissionError, match="not a regular file"):
        canonicalize_atomic_path_v2(str(project / "directory"), _scope(mono, project))


def test_registered_project_below_group_root_refuses(tmp_path: Path) -> None:
    """A group selector cannot write into a registered project tree."""
    mono = tmp_path / "mono"
    group = mono / "group"
    project = group / "project"
    project.mkdir(parents=True)
    scope = PinnedPathScopeV2(_pin(mono), _pin(group), None, (_pin(project),), (_pin(group),))
    with pytest.raises(PermissionError, match="nested registered project"):
        canonicalize_atomic_path_v2(str(project / "new.txt"), scope)


def test_missing_registered_root_does_not_match_current_descent(tmp_path: Path) -> None:
    """A project absent in this admission cannot alias a group child."""
    mono = tmp_path / "mono"
    group = mono / "group"
    (group / "docs").mkdir(parents=True)
    missing = group / "project"
    scope = PinnedPathScopeV2(_pin(mono), _pin(group), None, (_pin(missing),), (_pin(group),))
    assert canonicalize_atomic_path_v2(str(group / "docs" / "new.txt"), scope) == {
        "form": "path",
        "value": str(group / "docs" / "new.txt"),
    }


@pytest.mark.parametrize("broken_kind", ["symlink", "file"])
def test_broken_registered_root_refuses_with_operator_identity(
    tmp_path: Path, broken_kind: str
) -> None:
    """Real symlink or non-directory roots halt with operator-only identity."""
    mono = tmp_path / "mono"
    group = mono / "group"
    (group / "docs").mkdir(parents=True)
    broken = group / "other-project"
    if broken_kind == "symlink":
        broken.symlink_to(group / "docs", target_is_directory=True)
    else:
        broken.write_text("not a directory")
    scope = PinnedPathScopeV2(_pin(mono), _pin(group), None, (_pin(broken),), (_pin(group),))
    with pytest.raises(RegisteredRootUnavailableV2) as caught:
        canonicalize_atomic_path_v2(str(group / "docs" / "new.txt"), scope)
    assert caught.value.root_path == str(broken)
    assert str(broken) not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    with pytest.raises(RegisteredRootUnavailableV2):
        canonicalize_atomic_path_v2(str(group / "direct.txt"), scope)


def test_pinned_root_identity_and_nearest_project_refuse(tmp_path: Path) -> None:
    """A moved selected root or mismatched project selection cannot admit."""
    mono = tmp_path / "mono"
    project = mono / "project"
    project.mkdir(parents=True)
    scope = _scope(mono, project)
    project.rename(mono / "moved")
    with pytest.raises((PermissionError, OSError)):
        canonicalize_atomic_path_v2(str(project / "new.txt"), scope)
    project.mkdir()
    assert canonicalize_atomic_path_v2(str(project / "new.txt"), scope)
    with pytest.raises(PermissionError, match="nearest registered project differs"):
        canonicalize_atomic_path_v2(
            str(project / "new.txt"),
            PinnedPathScopeV2(_pin(mono), _pin(project), str(mono), (_pin(project),), ()),
        )


def test_invalid_scope_relations_refuse_before_descent(tmp_path: Path) -> None:
    """A forged root, registry or group selection cannot redirect admission."""
    mono = tmp_path / "mono"
    project = mono / "project"
    outside = tmp_path / "outside"
    project.mkdir(parents=True)
    outside.mkdir()
    target = str(project / "new.txt")
    valid = _scope(mono, project)
    with pytest.raises(PermissionError, match="outside the selected root"):
        canonicalize_atomic_path_v2(str(outside / "new.txt"), valid)
    with pytest.raises(PermissionError, match="outside the selected root"):
        canonicalize_atomic_path_v2(str(project), valid)
    with pytest.raises(ValueError, match="duplicate roots"):
        canonicalize_atomic_path_v2(
            target,
            PinnedPathScopeV2(
                _pin(mono), _pin(project), str(project), (_pin(project), _pin(project)), ()
            ),
        )
    with pytest.raises(ValueError, match="outside monorepo"):
        canonicalize_atomic_path_v2(
            target,
            PinnedPathScopeV2(
                _pin(mono), _pin(project), str(project), (_pin(project), _pin(outside)), ()
            ),
        )
    with pytest.raises(PermissionError, match="group selector root is not registered"):
        canonicalize_atomic_path_v2(
            target,
            PinnedPathScopeV2(_pin(mono), _pin(project), None, (_pin(project),), ()),
        )
    with pytest.raises(PermissionError, match="roots must be below"):
        canonicalize_atomic_path_v2(
            target,
            PinnedPathScopeV2(
                PinnedDirectoryV2("/"), _pin(project), str(project), (_pin(project),), ()
            ),
        )


def test_nested_bare_layout_refuses(tmp_path: Path) -> None:
    """A bare repository strictly below the selected project is excluded."""
    mono = tmp_path / "mono"
    project = mono / "project"
    child = project / "bare"
    child.mkdir(parents=True)
    (child / "HEAD").write_text("ref: refs/heads/main")
    (child / "objects").mkdir()
    (child / "refs").mkdir()
    with pytest.raises(PermissionError, match="nested repository"):
        canonicalize_atomic_path_v2(str(child / "new.txt"), _scope(mono, project))
