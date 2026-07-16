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
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.ignored_inventory import (
    IGNORED_INVENTORY_SCHEMA_VERSION,
    IgnoredInventoryDeclaration,
    IgnoredInventoryEvidence,
    ignored_inventory_digest,
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
    for invalid in (
        {},
        [{}],
        [_declaration("bad identifier!", ".rigor/token")],
        [_declaration("token", ".rigor/token", "unsupported")],
        [_declaration("token", "/tmp/token")],
        [_declaration("token", "../token")],
        [_declaration("token", ".rigor/*.txt")],
        [_declaration("token", ".rigor/./token")],
        [_declaration("token", ".rigor/other"), _declaration("token", ".rigor/token")],
        [_declaration("one", ".rigor/token"), _declaration("two", ".rigor/token")],
        [_declaration("z", ".rigor/z"), _declaration("a", ".rigor/a")],
    ):
        with pytest.raises(ValueError):
            parse_ignored_inventory(invalid)


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
    mutations = (
        {"extra": "field"},
        {"schema_version": "0.9"},
        {"status": "unknown"},
        {"observed_kind": "symlink"},
        {"byte_size": True},
        {"content_sha256": "not-a-digest"},
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
    )
    for mutation in mutations:
        value = {**base, **mutation}
        with pytest.raises(ValueError):
            IgnoredInventoryEvidence.from_dict(value, 0)


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
    process = subprocess.Popen(
        [
            sys.executable,
            str(mutator),
            str(target),
            str(ready),
            str(changed),
            str(stop),
        ],
        cwd=repository.root,
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
        assert evidence.reason == "changed-or-inaccessible"
        assert evidence.content_sha256 is None
    finally:
        stop.touch()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
