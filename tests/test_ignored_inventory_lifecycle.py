# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — POSIX ignored inventory lifecycle
"""Verify public scanner refusal and recovery during changes to live Linux inputs."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ParamSpec, TypeVar

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry import ignored_inventory, scan_repository
from rigor_foundry.git_inventory import (
    StableRegularRead,
    open_directory_no_follow,
    read_stable_regular_file_at,
)
from rigor_foundry.ignored_inventory import IgnoredCapture, IgnoredInventoryEvidence

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="requires Linux descriptor I/O")

_P = ParamSpec("_P")
_T = TypeVar("_T")


@dataclass(frozen=True)
class _Observation:
    """Own a Git repository and its single disposable ignored input."""

    repository: GitRepository
    path: Path
    head: str

    def scan(self) -> IgnoredInventoryEvidence:
        """Read the declared observation through the package's public entry point."""
        return scan_repository(self.repository.root).ignored_inventory_evidence[0]


def _observation(root: Path, capture: IgnoredCapture, *, directory: bool) -> _Observation:
    """Create a real tracked anchor and a declaration for an ignored input."""
    repository = GitRepository.create(root)
    relative = ".rigor/input/measurement"
    repository.write_text("src/pkg/value.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[{"evidence_id": "measurement", "path": relative, "capture": capture}]
    )
    head = repository.commit()
    path = root / relative
    if directory:
        path.mkdir(parents=True)
    else:
        repository.write_text(relative, "measured value\n")
    return _Observation(repository, path, head)


def _assert_recovered(observation: _Observation, healthy: IgnoredInventoryEvidence) -> None:
    """Verify the refusal released its handles and left Git state intact."""
    assert healthy.status == "observed"
    assert observation.scan() == healthy
    assert (
        observation.repository.git_command("rev-parse", "HEAD").stdout.strip() == observation.head
    )
    assert observation.repository.git_command("status", "--porcelain").stdout == ""


def _assert_refused(evidence: IgnoredInventoryEvidence, reason: str) -> None:
    """Require the actual refusal reason and absence of byte or digest evidence."""
    assert (evidence.status, evidence.reason) == ("unavailable", reason)
    assert evidence.byte_size is None and evidence.content_sha256 is None


def _after(
    function: Callable[_P, _T], change: Callable[[], None], *, occurrence: int = 1
) -> Callable[_P, _T]:
    """Schedule one fixture change after an otherwise unmodified real call."""
    calls = 0

    def invoke(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        """Return the original call result after applying the scheduled change."""
        nonlocal calls
        result = function(*args, **kwargs)
        calls += 1
        if calls == occurrence:
            change()
        return result

    return invoke


@contextmanager
def _restore_path(path: Path, displaced: Path) -> Iterator[Callable[[], None]]:
    """Provide a reversible move for a disposable filesystem entry."""

    def move() -> None:
        """Move the entry out of reach of the original observed pathname."""
        path.rename(displaced)

    try:
        yield move
    finally:
        assert displaced.exists()
        displaced.rename(path)


@pytest.mark.parametrize("phase", ["before-open", "after-open", "metadata-change"])
def test_presence_refuses_changes_to_bound_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    """Exercise a disappearing directory or identity change during presence capture."""
    observation = _observation(tmp_path / "repository", "presence", directory=True)
    path = observation.path
    healthy = observation.scan()
    original = ignored_inventory._observe_present
    metadata = path.stat()

    def observe(
        parent: int,
        name: str,
        declaration: ignored_inventory.IgnoredInventoryDeclaration,
        expected: tuple[int, int, int, int, int, int, int],
    ) -> IgnoredInventoryEvidence:
        """Apply the chosen fixture change after the expected identity is available."""
        if phase == "before-open":
            move()
        elif phase == "after-open":
            patch.setattr(os, "fstat", _after(os.fstat, move))
        else:
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000))
        return original(parent, name, declaration, expected)

    if phase == "metadata-change":
        with monkeypatch.context() as patch:
            patch.setattr(ignored_inventory, "_observe_present", observe)
            _assert_refused(observation.scan(), "changed-while-read")
        os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    else:
        with _restore_path(path, tmp_path / "displaced") as move, monkeypatch.context() as patch:
            patch.setattr(ignored_inventory, "_observe_present", observe)
            _assert_refused(observation.scan(), "changed-while-read")

    _assert_recovered(observation, healthy)


@pytest.mark.parametrize(
    ("phase", "expectation"),
    [
        ("before-entry-stat", "changed-while-read"),
        ("before-child-open", "inaccessible"),
        ("after-child-read", "inaccessible"),
        ("before-content-read", "inaccessible"),
    ],
)
def test_directory_refuses_disappearing_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, expectation: str
) -> None:
    """Verify several disappearance boundaries using a real directory digest scan."""
    observation = _observation(tmp_path / "repository", "directory-sha256", directory=True)
    child = observation.path / "nested"
    target = observation.path / "reading.txt"
    if phase in {"before-child-open", "after-child-read"}:
        child.mkdir()
        target = child
    else:
        target.write_text("measured value\n", encoding="utf-8")
    healthy = observation.scan()
    original = ignored_inventory._directory_entries

    with _restore_path(target, tmp_path / "displaced") as move, monkeypatch.context() as patch:
        if phase == "after-child-read":
            patch.setattr(ignored_inventory, "_directory_entries", _after(original, move))
        else:

            def entries(
                descriptor: int, *, prefix: bytes, depth: int, counters: list[int]
            ) -> list[dict[str, object]]:
                """Move the selected entry between real directory and file operations."""
                with patch.context() as scheduling:
                    if phase == "before-entry-stat":
                        scheduling.setattr(os, "listdir", _after(os.listdir, move))
                    elif phase == "before-child-open":
                        scheduling.setattr(os, "stat", _after(os.stat, move))
                    else:

                        def read(
                            parent: int,
                            name: str,
                            relative: str,
                            *,
                            buffer_limit: int,
                            maximum_bytes: int,
                            require_single_link: bool,
                        ) -> StableRegularRead:
                            """Attempt the genuine read after moving the listed file."""
                            move()
                            return read_stable_regular_file_at(
                                parent,
                                name,
                                relative,
                                buffer_limit=buffer_limit,
                                maximum_bytes=maximum_bytes,
                                require_single_link=require_single_link,
                            )

                        scheduling.setattr(ignored_inventory, "read_stable_regular_file_at", read)
                    return original(descriptor, prefix=prefix, depth=depth, counters=counters)

            patch.setattr(ignored_inventory, "_directory_entries", entries)
        _assert_refused(observation.scan(), expectation)

    _assert_recovered(observation, healthy)


@pytest.mark.parametrize(
    ("occurrence", "reason"), [(1, "inaccessible"), (2, "changed-while-read")]
)
def test_directory_refuses_native_descriptor_exhaustion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, occurrence: int, reason: str
) -> None:
    """Restore the current process's limit immediately after the genuine failed listdir."""
    import resource

    observation = _observation(tmp_path / "repository", "directory-sha256", directory=True)
    healthy = observation.scan()
    listdir = os.listdir
    original = ignored_inventory._directory_entries
    limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    calls = 0

    def list_directory(descriptor: int) -> list[str]:
        """Exhaust descriptor allocation for one call only."""
        nonlocal calls
        calls += 1
        if calls != occurrence:
            return listdir(descriptor)
        resource.setrlimit(resource.RLIMIT_NOFILE, (0, limit[1]))
        try:
            return listdir(descriptor)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, limit)

    def entries(
        descriptor: int, *, prefix: bytes, depth: int, counters: list[int]
    ) -> list[dict[str, object]]:
        """Limit the scheduling to the scanner's actual directory walk."""
        with monkeypatch.context() as patch:
            patch.setattr(os, "listdir", list_directory)
            return original(descriptor, prefix=prefix, depth=depth, counters=counters)

    with monkeypatch.context() as patch:
        patch.setattr(ignored_inventory, "_directory_entries", entries)
        _assert_refused(observation.scan(), reason)
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == limit
    _assert_recovered(observation, healthy)


def test_directory_refuses_metadata_change_after_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Change a directory timestamp after the complete real directory read."""
    observation = _observation(tmp_path / "repository", "directory-sha256", directory=True)
    healthy = observation.scan()
    metadata = observation.path.stat()

    def change() -> None:
        """Advance the owned directory timestamp before pathname revalidation."""
        os.utime(observation.path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000))

    with monkeypatch.context() as patch:
        patch.setattr(
            ignored_inventory,
            "_directory_entries",
            _after(ignored_inventory._directory_entries, change),
        )
        _assert_refused(observation.scan(), "changed-while-read")

    _assert_recovered(observation, healthy)


@pytest.mark.parametrize("change", ["parent-move", "file-type"])
def test_file_refuses_parent_move_or_type_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """Check parent and regular-entry binding after real filesystem changes."""
    capture: IgnoredCapture = "file-sha256" if change == "parent-move" else "presence"
    observation = _observation(tmp_path / "repository", capture, directory=False)
    healthy = observation.scan()
    target = (
        observation.repository.root / ".rigor" if change == "parent-move" else observation.path
    )

    with _restore_path(target, tmp_path / "displaced") as move, monkeypatch.context() as patch:
        if change == "parent-move":
            patch.setattr(
                ignored_inventory,
                "read_stable_regular_file_at",
                _after(read_stable_regular_file_at, move),
            )
            with pytest.raises(
                RuntimeError, match="repository root changed during ignored inventory"
            ):
                observation.scan()
        else:

            def read(
                parent: int,
                name: str,
                relative: str,
                *,
                buffer_limit: int,
                require_single_link: bool,
            ) -> StableRegularRead:
                """Replace the original regular file and attempt the real stable read."""
                move()
                target.mkdir()
                try:
                    return read_stable_regular_file_at(
                        parent,
                        name,
                        relative,
                        buffer_limit=buffer_limit,
                        require_single_link=require_single_link,
                    )
                finally:
                    target.rmdir()

            patch.setattr(ignored_inventory, "read_stable_regular_file_at", read)
            _assert_refused(observation.scan(), "changed-while-read")

    _assert_recovered(observation, healthy)


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() == 0, reason="requires unprivileged Linux"
)
def test_file_refuses_loss_of_parent_search_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Make the owned directory unsearchable after its descriptor opens."""
    observation = _observation(tmp_path / "repository", "file-sha256", directory=False)
    healthy = observation.scan()
    parent = observation.path.parent
    mode = parent.stat().st_mode
    original = ignored_inventory._collect_one

    def deny_search() -> None:
        """Temporarily revoke search access to the scanner's bound parent."""
        parent.chmod(0)

    def collect(
        root_descriptor: int, declaration: ignored_inventory.IgnoredInventoryDeclaration
    ) -> IgnoredInventoryEvidence:
        """Hold the real permission change just for ignored evidence collection."""
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", _after(os.open, deny_search, occurrence=2))
            try:
                return original(root_descriptor, declaration)
            finally:
                parent.chmod(mode)

    with monkeypatch.context() as patch:
        patch.setattr(ignored_inventory, "_collect_one", collect)
        _assert_refused(observation.scan(), "inaccessible")

    _assert_recovered(observation, healthy)


def test_displaced_repository_root_refuses_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revalidate the original root pathname after an owned repository moves."""
    observation = _observation(tmp_path / "repository", "file-sha256", directory=False)
    healthy = observation.scan()
    root = observation.repository.root

    with _restore_path(root, tmp_path / "displaced") as move, monkeypatch.context() as patch:
        opens = 0

        def open_root(path: Path) -> int:
            """Move the root just before its final native reopen."""
            nonlocal opens
            opens += 1
            if opens == 2:
                move()
            return open_directory_no_follow(path)

        patch.setattr(ignored_inventory, "open_directory_no_follow", open_root)
        with pytest.raises(RuntimeError, match="repository root changed during ignored inventory"):
            observation.scan()

    _assert_recovered(observation, healthy)
