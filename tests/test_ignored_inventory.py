# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — ignored-inventory production-contract tests
"""Verify bounded ignored evidence through real Git repositories and public APIs."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy
from rigor_foundry.ignored_inventory import (
    IGNORED_INVENTORY_SCHEMA_VERSION,
    IgnoredCapture,
    IgnoredInventoryDeclaration,
    IgnoredInventoryEvidence,
    ignored_inventory_digest,
    parse_ignored_evidence_array,
    parse_ignored_inventory,
)
from rigor_foundry.models import AuditPolicy, AuditReport

_SENTINEL = "private-token-do-not-serialize"


def _declaration(
    evidence_id: str,
    path: str,
    capture: str = "presence",
) -> dict[str, str]:
    """Return one policy declaration document."""
    return {"evidence_id": evidence_id, "path": path, "capture": capture}


def test_policy_declarations_are_exact_sorted_unique_and_versioned() -> None:
    """Policy schema 1.1 rejects ambiguous or duplicate ignored-path declarations."""
    assert IGNORED_INVENTORY_SCHEMA_VERSION == "1.0"
    declarations = parse_ignored_inventory(
        [
            _declaration("cache", ".rigor/cache"),
            _declaration("token", ".rigor/token.txt", "file-sha256"),
        ]
    )
    assert declarations == (
        IgnoredInventoryDeclaration("cache", ".rigor/cache", "presence"),
        IgnoredInventoryDeclaration("token", ".rigor/token.txt", "file-sha256"),
    )
    policy = AuditPolicy(ignored_inventory=declarations)
    assert AuditPolicy.from_dict(policy.to_dict()) == policy
    invalid_declarations: tuple[object, ...] = (
        {},
        [{}],
        [_declaration("bad identifier!", ".rigor/token")],
        [_declaration("token", ".rigor/token", "unsupported")],
        [_declaration("token", "/tmp/token")],
        [_declaration("token", "../token")],
        [_declaration("token", ".rigor/*.txt")],
        [_declaration("token", ".rigor/./token")],
        [_declaration("token", ".rigor/token\0suffix")],
        [_declaration("token", ".rigor/token\nsuffix")],
        [_declaration("token", ".rigor/other"), _declaration("token", ".rigor/token")],
        [_declaration("one", ".rigor/token"), _declaration("two", ".rigor/token")],
        [_declaration("z", ".rigor/z"), _declaration("a", ".rigor/a")],
    )
    for invalid in invalid_declarations:
        with pytest.raises(ValueError):
            parse_ignored_inventory(invalid)

    with pytest.raises(ValueError):
        IgnoredInventoryDeclaration("bad identifier!", ".rigor/state", "presence")
    with pytest.raises(ValueError):
        IgnoredInventoryDeclaration("state", "../state", "presence")
    with pytest.raises(ValueError):
        IgnoredInventoryDeclaration(
            "state",
            ".rigor/state",
            cast(IgnoredCapture, "unsupported"),
        )


def test_public_scan_collects_bounded_file_directory_missing_and_symlink_evidence(
    tmp_path: Path,
) -> None:
    """A real scan records only declared metadata and never ignored content or link targets."""
    repository = GitRepository.create(tmp_path / "repository")
    declarations = [
        _declaration("directory", ".rigor/evidence"),
        _declaration("directory-sha", ".rigor/evidence-sha", "file-sha256"),
        _declaration("fifo", ".rigor/fifo"),
        _declaration("fifo-sha", ".rigor/fifo-sha", "file-sha256"),
        _declaration("file", ".rigor/evidence/secret.txt", "file-sha256"),
        _declaration("missing", ".rigor/missing.txt"),
        _declaration("missing-parent", ".rigor/absent/child.txt"),
        _declaration("symlink", ".rigor/link"),
        _declaration("unsafe-parent", ".rigor/escape/secret.txt"),
    ]
    repository.write_policy(ignored_inventory=declarations)
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    repository.write_text(".rigor/evidence/secret.txt", _SENTINEL)
    (repository.root / ".rigor/evidence-sha").mkdir()
    repository.symlink(".rigor/link", "/tmp/never-serialise-this-target")
    repository.symlink(".rigor/escape", "/tmp")
    os.mkfifo(repository.root / ".rigor/fifo")
    os.mkfifo(repository.root / ".rigor/fifo-sha")

    report = rigor_foundry.scan_repository(repository.root)
    evidence = {item.evidence_id: item for item in report.ignored_inventory_evidence}
    assert evidence["directory"].observed_kind == "directory"
    assert evidence["directory-sha"].reason == "not-regular-file"
    assert evidence["fifo"].observed_kind == "other"
    assert evidence["fifo-sha"].reason == "not-regular-file"
    assert evidence["file"] == IgnoredInventoryEvidence(
        "file",
        ".rigor/evidence/secret.txt",
        "file-sha256",
        "observed",
        "regular-file",
        len(_SENTINEL.encode()),
        hashlib.sha256(_SENTINEL.encode()).hexdigest(),
        "observed",
    )
    assert evidence["missing"].status == "missing"
    assert evidence["missing-parent"].reason == "missing-parent"
    assert evidence["symlink"].status == "unavailable"
    assert evidence["symlink"].reason == "symlink"
    assert evidence["unsafe-parent"].reason == "unsafe-parent"
    assert report.ignored_inventory_digest == ignored_inventory_digest(
        report.ignored_inventory_evidence
    )
    serialised = report.to_json()
    markdown = rigor_foundry.report_markdown(report)
    assert _SENTINEL not in serialised
    assert _SENTINEL not in markdown
    assert "never-serialise-this-target" not in serialised
    assert "never-serialise-this-target" not in markdown
    assert "Ignored inventory" in markdown
    assert AuditReport.from_dict(json.loads(serialised)) == report


def test_evidence_parser_rejects_contradictory_or_unbounded_records() -> None:
    """Public evidence parsing rejects every contradictory bounded-field relation."""
    base: dict[str, object] = {
        "schema_version": "1.0",
        "evidence_id": "state",
        "path": ".rigor/state",
        "capture": "presence",
        "status": "missing",
        "observed_kind": None,
        "byte_size": None,
        "content_sha256": None,
        "reason": "missing",
    }
    mutations: tuple[dict[str, object], ...] = (
        {"extra": "field"},
        {"schema_version": "0.9"},
        {"status": "unknown"},
        {"observed_kind": "symlink"},
        {"observed_kind": []},
        {"byte_size": True},
        {"content_sha256": "not-a-digest"},
        {"reason": []},
        {"reason": "arbitrary"},
        {"observed_kind": "directory"},
        {"status": "observed"},
        {"status": "observed", "observed_kind": "regular-file"},
        {
            "status": "observed",
            "observed_kind": "directory",
            "capture": "file-sha256",
        },
        {"content_sha256": "a" * 64},
        {
            "status": "observed",
            "observed_kind": "directory",
            "content_sha256": "a" * 64,
        },
        {
            "status": "unavailable",
            "reason": "inaccessible",
            "byte_size": 1,
        },
        {
            "status": "unavailable",
            "reason": "not-regular-file",
        },
        {
            "status": "observed",
            "observed_kind": "regular-file",
            "reason": "observed",
        },
        {
            "status": "observed",
            "observed_kind": "regular-file",
            "capture": "file-sha256",
            "byte_size": 1,
            "reason": "observed",
        },
        {
            "status": "observed",
            "observed_kind": "regular-file",
            "byte_size": 1,
            "content_sha256": "a" * 64,
            "reason": "observed",
        },
    )
    for mutation in mutations:
        value = {**base, **mutation}
        with pytest.raises(ValueError):
            IgnoredInventoryEvidence.from_dict(value, 0)
    with pytest.raises(ValueError):
        IgnoredInventoryEvidence(
            "state",
            ".rigor/state",
            "presence",
            "missing",
            None,
            None,
            None,
            "observed",
        )


def test_evidence_array_requires_canonical_order_and_unique_declarations() -> None:
    """Durable evidence arrays cannot reorder or duplicate declaration identities."""
    first = IgnoredInventoryEvidence(
        "first",
        ".rigor/first",
        "presence",
        "missing",
        None,
        None,
        None,
        "missing",
    ).to_dict()
    second = IgnoredInventoryEvidence(
        "second",
        ".rigor/second",
        "presence",
        "missing",
        None,
        None,
        None,
        "missing",
    ).to_dict()
    parsed = parse_ignored_evidence_array([first, second])
    assert tuple(item.evidence_id for item in parsed) == ("first", "second")
    with pytest.raises(ValueError, match="must be an array"):
        parse_ignored_evidence_array({})
    with pytest.raises(ValueError, match="must be sorted"):
        parse_ignored_evidence_array([second, first])
    with pytest.raises(ValueError, match="evidence_id values must be unique"):
        parse_ignored_evidence_array([first, {**first, "path": ".rigor/other"}])
    with pytest.raises(ValueError, match="paths must be unique"):
        parse_ignored_evidence_array([first, {**second, "path": ".rigor/first"}])
    with pytest.raises(ValueError):
        IgnoredInventoryEvidence(
            "state",
            ".rigor/state",
            "presence",
            "observed",
            "directory",
            1,
            None,
            "observed",
        )


def test_public_scan_rejects_tracked_and_nonignored_declarations(tmp_path: Path) -> None:
    """Declarations cannot smuggle tracked or ordinary unignored repository paths."""
    tracked = GitRepository.create(tmp_path / "tracked")
    tracked.write_policy(ignored_inventory=[_declaration("owner", "src/pkg/module.py")])
    tracked.write_text("src/pkg/module.py", "VALUE = 1\n")
    tracked.commit()
    with pytest.raises(ValueError, match="is tracked"):
        rigor_foundry.scan_repository(tracked.root)

    unignored = GitRepository.create(tmp_path / "unignored")
    unignored.write_policy(ignored_inventory=[_declaration("runtime", "runtime/state.json")])
    unignored.write_text("src/pkg/module.py", "VALUE = 1\n")
    unignored.commit()
    with pytest.raises(ValueError, match="is not ignored"):
        rigor_foundry.scan_repository(unignored.root)


@pytest.mark.parametrize("capture", ["presence", "file-sha256"])
def test_public_scan_rejects_ignored_hardlink_metadata_oracle(
    tmp_path: Path,
    capture: str,
) -> None:
    """An ignored hard link cannot expose the size or digest of another path."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(ignored_inventory=[_declaration("state", ".rigor/state.bin", capture)])
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    outside = tmp_path / "outside-secret.bin"
    outside.write_bytes(b"outside-secret")
    inside = repository.root / ".rigor/state.bin"
    inside.parent.mkdir()
    os.link(outside, inside)
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert evidence.status == "unavailable"
    assert evidence.reason == "multiple-links"
    assert evidence.byte_size is None
    assert evidence.content_sha256 is None


def test_public_scan_rejects_raced_ignored_hardlink_metadata_oracle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A final-entry race to a hard link cannot expose aliased metadata."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state.bin", "presence")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    target = repository.root / ".rigor/state.bin"
    target.parent.mkdir()
    outside = tmp_path / "outside-secret.bin"
    outside.write_bytes(b"outside-secret")
    os.link(outside, target)
    initial = repository.root / ".rigor/initial-state"
    os.mkfifo(initial)
    real_stat = os.stat
    intercepted = False

    def stale_initial_stat(
        path: os.PathLike[str] | str | bytes | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal intercepted
        if path == target.name and dir_fd is not None and not follow_symlinks and not intercepted:
            intercepted = True
            return real_stat(initial, follow_symlinks=False)
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", stale_initial_stat)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            stale_initial_stat if function is real_stat else function
            for function in os.supports_dir_fd
        ),
    )
    monkeypatch.setattr(
        os,
        "supports_follow_symlinks",
        frozenset(
            stale_initial_stat if function is real_stat else function
            for function in os.supports_follow_symlinks
        ),
    )
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert intercepted
    assert evidence.status == "unavailable"
    assert evidence.reason == "multiple-links"
    assert evidence.byte_size is None
    assert evidence.content_sha256 is None


@pytest.mark.parametrize("attempt", range(5))
def test_public_scan_fails_closed_on_ignored_final_replacement(
    tmp_path: Path,
    attempt: int,
) -> None:
    """A real final-path replacement after open cannot authenticate stale bytes."""
    repository = GitRepository.create(tmp_path / f"replacement-{attempt}")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state.bin", "file-sha256")]
    )
    mutator = repository.write_text(
        "controls/replace.py",
        """
import ctypes
import os
import pathlib
import sys

target, replacement, ready, changed = map(pathlib.Path, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
notify = libc.inotify_init1(os.O_CLOEXEC)
if notify < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1")
if libc.inotify_add_watch(notify, os.fsencode(target), 0x20) < 0:
    raise OSError(ctypes.get_errno(), "inotify_add_watch")
temporary = ready.with_suffix(".tmp")
temporary.write_text("ready", encoding="utf-8")
os.replace(temporary, ready)
os.read(notify, 4096)
target.rename(target.with_suffix(".old"))
os.replace(replacement, target)
temporary = changed.with_suffix(".tmp")
temporary.write_text("changed", encoding="utf-8")
os.replace(temporary, changed)
os.close(notify)
""".lstrip(),
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    target = repository.write_bytes(".rigor/state.bin", b"A" * (32 * 1024 * 1024))
    replacement = repository.write_bytes(".rigor/replacement.bin", b"B" * (32 * 1024 * 1024))
    ready = repository.root / ".rigor/ready"
    changed = repository.root / ".rigor/changed"
    original_affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(original_affinity)})
    process = subprocess.Popen(  # nosec B603
        [sys.executable, str(mutator), str(target), str(replacement), str(ready), str(changed)],
        cwd=repository.root,
        shell=False,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.is_file() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert ready.read_text(encoding="utf-8") == "ready"
        report = rigor_foundry.scan_repository(repository.root)
        assert changed.read_text(encoding="utf-8") == "changed"
        evidence = report.ignored_inventory_evidence[0]
        assert evidence.status == "unavailable"
        assert evidence.reason == "changed-while-read"
        assert evidence.content_sha256 is None
    finally:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
            raise
        finally:
            os.sched_setaffinity(0, original_affinity)


def test_collection_rejects_symlinked_repository_root(tmp_path: Path) -> None:
    """Ignored inventory cannot bind evidence through a symlinked root alias."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy()
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    alias = tmp_path / "repository-alias"
    alias.symlink_to(repository.root, target_is_directory=True)
    runner = GitRunner()
    with pytest.raises(RuntimeError, match="repository root"):
        rigor_foundry.collect_ignored_inventory(
            replace(inventory, root=alias),
            (IgnoredInventoryDeclaration("state", ".rigor/state", "presence"),),
            git_runner=runner,
        )


def test_empty_ignored_inventory_does_not_open_repository_root(tmp_path: Path) -> None:
    """An empty declaration tuple returns before any repository path traversal."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy()
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    alias = tmp_path / "repository-alias"
    alias.symlink_to(repository.root, target_is_directory=True)
    assert (
        rigor_foundry.collect_ignored_inventory(
            replace(inventory, root=alias),
            (),
            git_runner=GitRunner(),
        )
        == ()
    )


def test_public_scan_fails_closed_on_repository_root_replacement(tmp_path: Path) -> None:
    """A repository root replaced during ignored collection cannot retain evidence."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state.bin", "file-sha256")]
    )
    mutator = repository.write_text(
        "controls/replace_root.py",
        """
import ctypes
import os
import pathlib
import signal
import sys

root, target, ready, changed = map(pathlib.Path, sys.argv[1:5])
scanner_pid = int(sys.argv[5])
libc = ctypes.CDLL(None, use_errno=True)
notify = libc.inotify_init1(os.O_CLOEXEC)
if notify < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1")
if libc.inotify_add_watch(notify, os.fsencode(target), 0x20) < 0:
    raise OSError(ctypes.get_errno(), "inotify_add_watch")
temporary = ready.with_suffix(".tmp")
temporary.write_text("ready", encoding="utf-8")
os.replace(temporary, ready)
os.read(notify, 4096)
os.kill(scanner_pid, signal.SIGSTOP)
try:
    root.rename(root.with_name("repository-old"))
    root.mkdir()
    temporary = changed.with_suffix(".tmp")
    temporary.write_text("changed", encoding="utf-8")
    os.replace(temporary, changed)
finally:
    os.kill(scanner_pid, signal.SIGCONT)
    os.close(notify)
""".lstrip(),
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    target = repository.write_bytes(".rigor/state.bin", b"A" * (32 * 1024 * 1024))
    ready = tmp_path / "root-ready"
    changed = tmp_path / "root-changed"
    original_affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(original_affinity)})
    process = subprocess.Popen(  # nosec B603
        [
            sys.executable,
            str(mutator),
            str(repository.root),
            str(target),
            str(ready),
            str(changed),
            str(os.getpid()),
        ],
        cwd=repository.root,
        shell=False,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.is_file() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert ready.read_text(encoding="utf-8") == "ready"
        with pytest.raises(RuntimeError, match="repository root changed"):
            rigor_foundry.scan_repository(repository.root)
        assert changed.read_text(encoding="utf-8") == "changed"
    finally:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
            raise
        finally:
            os.sched_setaffinity(0, original_affinity)


def test_git_check_ignore_failure_is_not_reinterpreted_as_ancestor_success(
    tmp_path: Path,
) -> None:
    """A real failing Git executable remains a fatal provenance-bound error."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(ignored_inventory=[_declaration("state", ".rigor/state.bin")])
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    tools = tmp_path / "tools"
    tools.mkdir()
    wrapper = tools / "git"
    wrapper.write_text(
        '#!/bin/sh\ncase " $* " in *" check-ignore "*) exit 2;; '
        '*) exec /usr/bin/git "$@";; esac\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    policy = GitTrustPolicy(executable=str(wrapper), trusted_roots=(str(tools),))
    with pytest.raises(RuntimeError, match="check-ignore"):
        rigor_foundry.scan_repository(repository.root, git_trust_policy=policy)


@pytest.mark.parametrize("attempt", range(5))
def test_public_scan_fails_closed_on_concurrent_ignored_file_mutation(
    tmp_path: Path,
    attempt: int,
) -> None:
    """A real inotify-synchronised mutation cannot produce mixed file evidence."""
    repository = GitRepository.create(tmp_path / f"repository-{attempt}")
    repository.write_policy(
        ignored_inventory=[_declaration("large-state", ".rigor/large-state.bin", "file-sha256")]
    )
    mutator = repository.write_text(
        "controls/mutate.py",
        """
import ctypes
import os
import pathlib
import sys

target, ready, changed, stop = map(pathlib.Path, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
notify = libc.inotify_init1(os.O_CLOEXEC)
if notify < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1")
if libc.inotify_add_watch(notify, os.fsencode(target), 0x20) < 0:
    raise OSError(ctypes.get_errno(), "inotify_add_watch")
temporary_ready = ready.with_suffix(".tmp")
temporary_ready.write_text("ready", encoding="utf-8")
os.replace(temporary_ready, ready)
os.read(notify, 4096)
descriptor = os.open(target, os.O_RDWR)
size = os.fstat(descriptor).st_size
os.ftruncate(descriptor, size + 1)
os.pwrite(descriptor, b"X", 0)
temporary = changed.with_suffix(".tmp")
temporary.write_text("mutated", encoding="utf-8")
os.replace(temporary, changed)
value = b"A"
while not stop.exists():
    os.pwrite(descriptor, value, 0)
    value = b"B" if value == b"A" else b"A"
os.close(descriptor)
os.close(notify)
""".lstrip(),
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    target = repository.write_bytes(".rigor/large-state.bin", b"0" * (32 * 1024 * 1024))
    ready = repository.root / ".rigor/ready"
    changed = repository.root / ".rigor/changed"
    stop = repository.root / ".rigor/stop"
    process = subprocess.Popen(  # nosec B603
        [
            sys.executable,
            str(mutator),
            str(target),
            str(ready),
            str(changed),
            str(stop),
        ],
        cwd=repository.root,
        shell=False,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.is_file() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert ready.is_file()
        report = rigor_foundry.scan_repository(repository.root)
        assert changed.is_file()
        evidence = report.ignored_inventory_evidence[0]
        assert evidence.status == "unavailable"
        assert evidence.reason == "changed-while-read"
        assert evidence.content_sha256 is None
    finally:
        stop.touch()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
