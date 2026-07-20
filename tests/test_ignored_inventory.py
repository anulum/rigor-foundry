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
import rigor_foundry.ignored_inventory as ignored_inventory_module
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.git_inventory import load_git_inventory, open_directory_no_follow
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
    """Policy schema 1.2 rejects ambiguous or duplicate ignored-path declarations."""
    assert IGNORED_INVENTORY_SCHEMA_VERSION == "1.0"
    declarations = parse_ignored_inventory(
        [
            _declaration("cache", ".rigor/cache"),
            _declaration("state", ".rigor/state", "directory-sha256"),
            _declaration("token", ".rigor/token.txt", "file-sha256"),
        ]
    )
    assert declarations == (
        IgnoredInventoryDeclaration("cache", ".rigor/cache", "presence"),
        IgnoredInventoryDeclaration("state", ".rigor/state", "directory-sha256"),
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
        _declaration("directory-digest", ".rigor/tree", "directory-sha256"),
        _declaration("directory-fifo", ".rigor/fifo-directory", "directory-sha256"),
        _declaration("directory-regular", ".rigor/not-directory", "directory-sha256"),
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
    repository.write_bytes(".rigor/tree/alpha.txt", b"alpha")
    repository.write_bytes(".rigor/tree/nested/beta.bin", b"\x00\xff")
    (repository.root / ".rigor/tree/empty").mkdir()
    repository.write_text(".rigor/not-directory", "regular")
    (repository.root / ".rigor/evidence-sha").mkdir()
    repository.symlink(".rigor/link", "/tmp/never-serialise-this-target")
    repository.symlink(".rigor/escape", "/tmp")
    os.mkfifo(repository.root / ".rigor/fifo")
    os.mkfifo(repository.root / ".rigor/fifo-directory")
    os.mkfifo(repository.root / ".rigor/fifo-sha")

    report = rigor_foundry.scan_repository(repository.root)
    evidence = {item.evidence_id: item for item in report.ignored_inventory_evidence}
    assert evidence["directory"].observed_kind == "directory"
    expected_manifest = {
        "schema_version": "1.0",
        "entries": [
            {
                "path_bytes_hex": b"alpha.txt".hex(),
                "kind": "regular-file",
                "byte_size": 5,
                "content_sha256": hashlib.sha256(b"alpha").hexdigest(),
            },
            {"path_bytes_hex": b"empty".hex(), "kind": "directory"},
            {"path_bytes_hex": b"nested".hex(), "kind": "directory"},
            {
                "path_bytes_hex": b"nested/beta.bin".hex(),
                "kind": "regular-file",
                "byte_size": 2,
                "content_sha256": hashlib.sha256(b"\x00\xff").hexdigest(),
            },
        ],
    }
    assert evidence["directory-digest"] == IgnoredInventoryEvidence(
        "directory-digest",
        ".rigor/tree",
        "directory-sha256",
        "observed",
        "directory",
        7,
        canonical_digest(expected_manifest),
        "observed",
    )
    assert evidence["directory-fifo"].reason == "not-regular-file"
    assert evidence["directory-regular"].reason == "not-regular-file"
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
            "status": "observed",
            "observed_kind": "directory",
            "capture": "directory-sha256",
            "byte_size": 1,
            "reason": "observed",
        },
        {
            "status": "observed",
            "observed_kind": "regular-file",
            "capture": "directory-sha256",
            "byte_size": 1,
            "content_sha256": "a" * 64,
            "reason": "observed",
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


def test_directory_digest_changes_for_exact_ignored_content_mutation(tmp_path: Path) -> None:
    """A real ignored-tree mutation changes both evidence and report identities."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    repository.write_text(".rigor/state/value.txt", "before\n")
    before = rigor_foundry.scan_repository(repository.root)
    repository.write_text(".rigor/state/value.txt", "after\n")
    after = rigor_foundry.scan_repository(repository.root)
    assert before.ignored_inventory_digest != after.ignored_inventory_digest
    assert before.report_digest != after.report_digest


@pytest.mark.parametrize(
    ("entry_kind", "expected_reason"),
    [
        ("symlink", "symlink"),
        ("fifo", "not-regular-file"),
        ("hardlink", "multiple-links"),
    ],
)
def test_directory_digest_rejects_unsafe_nested_entry_kinds(
    tmp_path: Path,
    entry_kind: str,
    expected_reason: str,
) -> None:
    """A declared tree never traverses links or reads special and multiply linked files."""
    repository = GitRepository.create(tmp_path / entry_kind)
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    state = repository.root / ".rigor/state"
    state.mkdir(parents=True)
    entry = state / "entry"
    if entry_kind == "symlink":
        entry.symlink_to(tmp_path / "outside")
    elif entry_kind == "fifo":
        os.mkfifo(entry)
    else:
        outside = tmp_path / "outside"
        outside.write_text("private", encoding="utf-8")
        os.link(outside, entry)
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert evidence.status == "unavailable"
    assert evidence.reason == expected_reason


def test_directory_digest_canonically_hashes_non_utf8_entry_names(tmp_path: Path) -> None:
    """Manifest paths preserve arbitrary filesystem bytes without exposing raw names."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    state = repository.root / ".rigor/state"
    state.mkdir(parents=True)
    raw_path = os.fsencode(state) + b"/\xff"
    descriptor = os.open(raw_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        assert os.write(descriptor, b"value") == 5
    finally:
        os.close(descriptor)
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    manifest = {
        "schema_version": "1.0",
        "entries": [
            {
                "path_bytes_hex": "ff",
                "kind": "regular-file",
                "byte_size": 5,
                "content_sha256": hashlib.sha256(b"value").hexdigest(),
            }
        ],
    }
    assert evidence.content_sha256 == canonical_digest(manifest)


def test_directory_digest_rejects_nested_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replacing a nested directory after its read produces unavailable evidence."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    nested = repository.root / ".rigor/state/nested"
    repository.write_text(".rigor/state/nested/value", "content")
    displaced = nested.with_name("nested-displaced")
    real_stat = os.stat
    nested_stats = 0

    def replace_after_nested_read(
        path: os.PathLike[str] | str | bytes | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal nested_stats
        if path == "nested" and dir_fd is not None and not follow_symlinks:
            nested_stats += 1
            if nested_stats == 2:
                nested.rename(displaced)
                nested.mkdir()
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", replace_after_nested_read)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            replace_after_nested_read if function is real_stat else function
            for function in os.supports_dir_fd
        ),
    )
    monkeypatch.setattr(
        os,
        "supports_follow_symlinks",
        frozenset(
            replace_after_nested_read if function is real_stat else function
            for function in os.supports_follow_symlinks
        ),
    )
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert nested_stats == 2
    assert evidence.status == "unavailable"
    assert evidence.reason == "changed-while-read"


def test_directory_digest_rejects_entry_inserted_during_manifest_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory entry inserted before final enumeration invalidates the manifest."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    state = repository.root / ".rigor/state"
    state.mkdir(parents=True)
    initial = state.stat()
    real_listdir = os.listdir
    enumerations = 0

    def insert_before_final_enumeration(path: os.PathLike[str] | str | bytes | int) -> list[str]:
        nonlocal enumerations
        if isinstance(path, int):
            observed = os.fstat(path)
            if (observed.st_dev, observed.st_ino) == (initial.st_dev, initial.st_ino):
                enumerations += 1
                if enumerations == 2:
                    (state / "inserted").write_text("new", encoding="utf-8")
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", insert_before_final_enumeration)
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert enumerations == 2
    assert evidence.status == "unavailable"
    assert evidence.reason == "changed-while-read"


@pytest.mark.parametrize("blocked_name", ["state", "nested"])
def test_directory_digest_reports_inaccessible_directory_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked_name: str,
) -> None:
    """An inaccessible declared or nested directory yields bounded unavailable evidence."""
    repository = GitRepository.create(tmp_path / blocked_name)
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    (repository.root / ".rigor/state/nested").mkdir(parents=True)
    expected_parent = (
        repository.root / ".rigor" if blocked_name == "state" else repository.root / ".rigor/state"
    ).stat()
    real_open = os.open

    def reject_selected_directory(
        path: os.PathLike[str] | str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == blocked_name and dir_fd is not None and flags & os.O_DIRECTORY:
            observed_parent = os.fstat(dir_fd)
            if (observed_parent.st_dev, observed_parent.st_ino) == (
                expected_parent.st_dev,
                expected_parent.st_ino,
            ):
                raise PermissionError("blocked by test filesystem boundary")
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", reject_selected_directory)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            reject_selected_directory if function is real_open else function
            for function in os.supports_dir_fd
        ),
    )
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert evidence.status == "unavailable"
    assert evidence.reason == "inaccessible"


def test_presence_capture_reports_missing_platform_primitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A platform without final-entry path descriptors yields unavailable evidence."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(ignored_inventory=[_declaration("state", ".rigor/state")])
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    state = repository.root / ".rigor/state"
    state.parent.mkdir()
    os.mkfifo(state)
    monkeypatch.delattr(os, "O_PATH")
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert evidence.status == "unavailable"
    assert evidence.reason == "platform-unavailable"


def test_directory_digest_rejects_stale_initial_directory_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale pre-open directory identity cannot authenticate another tree."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state", "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    state = repository.root / ".rigor/state"
    decoy = repository.root / ".rigor/decoy"
    state.mkdir(parents=True)
    decoy.mkdir()
    parent_identity = state.parent.stat()
    real_stat = os.stat
    intercepted = False

    def stale_initial_directory_stat(
        path: os.PathLike[str] | str | bytes | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal intercepted
        if path == "state" and dir_fd is not None and not follow_symlinks and not intercepted:
            parent = os.fstat(dir_fd)
            if (parent.st_dev, parent.st_ino) == (
                parent_identity.st_dev,
                parent_identity.st_ino,
            ):
                intercepted = True
                return real_stat(decoy, follow_symlinks=False)
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", stale_initial_directory_stat)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            stale_initial_directory_stat if function is real_stat else function
            for function in os.supports_dir_fd
        ),
    )
    monkeypatch.setattr(
        os,
        "supports_follow_symlinks",
        frozenset(
            stale_initial_directory_stat if function is real_stat else function
            for function in os.supports_follow_symlinks
        ),
    )
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert intercepted
    assert evidence.status == "unavailable"
    assert evidence.reason == "changed-while-read"


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "relative_path"),
    [
        ("_DIRECTORY_MAX_ENTRIES", 1, ".rigor/entry-limit"),
        ("_DIRECTORY_MAX_BYTES", 1, ".rigor/byte-limit"),
        ("_DIRECTORY_MAX_DEPTH", 0, ".rigor/depth-limit"),
    ],
)
def test_directory_digest_fails_closed_at_each_resource_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit_value: int,
    relative_path: str,
) -> None:
    """Directory capture reports bounded unavailable evidence at every finite limit."""
    repository = GitRepository.create(tmp_path / limit_name)
    repository.write_policy(
        ignored_inventory=[_declaration("state", relative_path, "directory-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    if limit_name == "_DIRECTORY_MAX_ENTRIES":
        repository.write_text(f"{relative_path}/one", "")
        repository.write_text(f"{relative_path}/two", "")
    elif limit_name == "_DIRECTORY_MAX_BYTES":
        repository.write_text(f"{relative_path}/two-bytes", "12")
    else:
        repository.write_text(f"{relative_path}/nested/value", "")
    monkeypatch.setattr(ignored_inventory_module, limit_name, limit_value)
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert evidence.status == "unavailable"
    assert evidence.reason == "limit-exceeded"
    assert evidence.byte_size is None
    assert evidence.content_sha256 is None


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


def test_public_scan_fails_closed_on_ignored_parent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real parent replacement before revalidation invalidates its evidence."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/runtime/state.bin", "file-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    target = repository.write_bytes(
        ".rigor/runtime/state.bin",
        b"authenticated-state",
    )
    parent = target.parent
    displaced = parent.with_name("runtime-displaced")
    real_stat = os.stat
    target_stats = 0
    replaced = False

    def replace_parent_before_revalidation(
        path: os.PathLike[str] | str | bytes | int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal replaced, target_stats
        if path == target.name and dir_fd is not None and not follow_symlinks:
            target_stats += 1
        if (
            path == parent.name
            and dir_fd is not None
            and not follow_symlinks
            and target_stats == 3
            and not replaced
        ):
            parent.rename(displaced)
            parent.mkdir()
            replaced = True
        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", replace_parent_before_revalidation)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(
            replace_parent_before_revalidation if function is real_stat else function
            for function in os.supports_dir_fd
        ),
    )
    monkeypatch.setattr(
        os,
        "supports_follow_symlinks",
        frozenset(
            replace_parent_before_revalidation if function is real_stat else function
            for function in os.supports_follow_symlinks
        ),
    )
    evidence = rigor_foundry.scan_repository(repository.root).ignored_inventory_evidence[0]
    assert replaced
    assert target_stats == 3
    assert displaced.joinpath(target.name).read_bytes() == b"authenticated-state"
    assert evidence.status == "unavailable"
    assert evidence.reason == "changed-while-read"
    assert evidence.byte_size is None
    assert evidence.content_sha256 is None


def test_public_scan_fails_closed_on_repository_root_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real root replacement before post-collection binding aborts the scan."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy(
        ignored_inventory=[_declaration("state", ".rigor/state.bin", "file-sha256")]
    )
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    target = repository.write_bytes(".rigor/state.bin", b"authenticated-state")
    displaced = repository.root.with_name("repository-displaced")
    root_opens = 0
    replaced = False

    def replace_root_before_revalidation(path: Path) -> int:
        nonlocal replaced, root_opens
        root_opens += 1
        if root_opens == 2:
            repository.root.rename(displaced)
            repository.root.mkdir()
            replaced = True
        return cast(int, open_directory_no_follow(path))

    monkeypatch.setattr(
        "rigor_foundry.ignored_inventory.open_directory_no_follow",
        replace_root_before_revalidation,
    )
    with pytest.raises(RuntimeError, match="repository root changed"):
        rigor_foundry.scan_repository(repository.root)
    assert replaced
    assert root_opens == 2
    assert displaced.joinpath(target.relative_to(repository.root)).read_bytes() == (
        b"authenticated-state"
    )


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
        deadline = time.monotonic() + 10
        while not changed.is_file() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert changed.read_text(encoding="utf-8") == "mutated"
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
