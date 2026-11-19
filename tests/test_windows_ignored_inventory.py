# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows declared ignored inventory
"""Exercise declared ignored observations through the ordinary Windows scanner."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry import scan_repository
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.models import AuditReport
from rigor_foundry.windows_directory_inventory import WindowsDirectoryEntry
from rigor_foundry.windows_handles import WindowsChildSnapshot, WindowsDirectory

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires a native NTFS scanner")


def test_cli_collects_native_ignored_tree_and_file_evidence(tmp_path: Path) -> None:
    """Observe all three capture modes using real Git, NTFS and the ordinary CLI."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "present", "path": ".rigor/work", "capture": "presence"},
            {"evidence_id": "reading", "path": ".rigor/reading.dat", "capture": "file-sha256"},
            {"evidence_id": "tree", "path": ".rigor/work/tree", "capture": "directory-sha256"},
        ]
    )
    head = repository.commit()
    raw_reading = b"private fixture measurement\r\n"
    file_payload = b"nested bytes \x00\xff"
    repository.write_bytes(".rigor/reading.dat", raw_reading)
    repository.write_bytes(".rigor/work/tree/nested/měření.dat", file_payload)
    (repository.root / ".rigor/work/tree/empty").mkdir()
    repository.write_text(".rigor/undeclared.dat", "undeclared fixture input")
    report_path = tmp_path / "result.json"

    result = repository.run_audit(
        "scan", "--root", str(repository.root), "--json-out", str(report_path)
    )

    assert result.returncode == 0, result.stderr
    report = AuditReport.from_path(report_path)
    assert report.head == head and not report.dirty_paths
    observations = {entry.evidence_id: entry for entry in report.ignored_inventory_evidence}
    assert set(observations) == {"present", "tree", "reading"}
    assert (observations["present"].observed_kind, observations["present"].byte_size) == (
        "directory",
        None,
    )
    assert observations["present"].content_sha256 is None
    assert observations["reading"].byte_size == len(raw_reading)
    assert observations["reading"].content_sha256 == hashlib.sha256(raw_reading).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "entries": [
            {"path_bytes_hex": b"empty".hex(), "kind": "directory"},
            {"path_bytes_hex": b"nested".hex(), "kind": "directory"},
            {
                "path_bytes_hex": "nested/měření.dat".encode().hex(),
                "kind": "regular-file",
                "byte_size": len(file_payload),
                "content_sha256": hashlib.sha256(file_payload).hexdigest(),
            },
        ],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    assert observations["tree"].byte_size == len(file_payload)
    assert observations["tree"].content_sha256 == hashlib.sha256(manifest_bytes).hexdigest()
    encoded = report_path.read_bytes()
    assert b"private fixture measurement" not in encoded
    assert b"undeclared.dat" not in encoded
    assert b"undeclared fixture input" not in encoded


def test_api_distinguishes_absence_unsafe_names_and_observed_kinds(tmp_path: Path) -> None:
    """Report native refusal reasons without serialising content from refused entries."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "alias-leaf", "path": ".rigor/lower", "capture": "presence"},
            {
                "evidence_id": "alias-parent",
                "path": ".rigor/exact/child",
                "capture": "file-sha256",
            },
            {"evidence_id": "directory-as-file", "path": ".rigor/dir", "capture": "file-sha256"},
            {"evidence_id": "linked", "path": ".rigor/linked", "capture": "file-sha256"},
            {"evidence_id": "missing", "path": ".rigor/missing", "capture": "presence"},
            {"evidence_id": "parent", "path": ".rigor/absent/file", "capture": "presence"},
            {"evidence_id": "present", "path": ".rigor/present", "capture": "presence"},
            {"evidence_id": "wrong", "path": ".rigor/ordinary", "capture": "directory-sha256"},
        ]
    )
    head = repository.commit()
    linked = repository.write_bytes(".rigor/linked", b"refused fixture input")
    os.link(linked, linked.with_name("second-link"))
    repository.write_bytes(".rigor/Lower", b"case-sensitive observation")
    repository.write_bytes(".rigor/Exact/child", b"case-sensitive ancestor")
    (linked.parent / "dir").mkdir()
    repository.write_bytes(".rigor/present", b"fixture")
    repository.write_bytes(".rigor/ordinary", b"a regular file")
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))

    report = scan_repository(repository.root, git_trust_policy=policy)

    assert report.head == head and not report.dirty_paths
    assert {
        entry.evidence_id: (entry.status, entry.reason, entry.content_sha256, entry.byte_size)
        for entry in report.ignored_inventory_evidence
    } == {
        "alias-leaf": ("unavailable", "inaccessible", None, None),
        "alias-parent": ("unavailable", "unsafe-parent", None, None),
        "directory-as-file": ("unavailable", "not-regular-file", None, None),
        "linked": ("unavailable", "multiple-links", None, None),
        "missing": ("missing", "missing", None, None),
        "parent": ("missing", "missing-parent", None, None),
        "present": ("observed", "observed", None, len(b"fixture")),
        "wrong": ("unavailable", "not-regular-file", None, None),
    }
    assert b"refused fixture input" not in report.to_json().encode()


def test_cli_refuses_junctions_in_declared_paths(tmp_path: Path) -> None:
    """Keep metadata-only refusal for a junction leaf, ancestor and tree member."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "leaf", "path": ".rigor/link", "capture": "presence"},
            {"evidence_id": "parent", "path": ".rigor/link/private", "capture": "file-sha256"},
            {"evidence_id": "tree", "path": ".rigor/tree", "capture": "directory-sha256"},
        ]
    )
    repository.commit()
    target = tmp_path / "owned-junction-target"
    target.mkdir()
    (target / "private").write_text("unobservable fixture data", encoding="utf-8")
    root = repository.root / ".rigor"
    (root / "tree").mkdir(parents=True)
    junctions = (root / "link", root / "tree" / "member")
    try:
        for junction in junctions:
            subprocess.run(  # nosec B603
                [os.environ["COMSPEC"], "/d", "/c", "mklink", "/J", str(junction), str(target)],
                check=True,
                capture_output=True,
                shell=False,
            )
        report_path = tmp_path / "junctions.json"
        result = repository.run_audit(
            "scan", "--root", str(repository.root), "--json-out", str(report_path)
        )

        assert result.returncode == 0, result.stderr
        report = AuditReport.from_path(report_path)
        assert {
            entry.evidence_id: (entry.status, entry.reason, entry.content_sha256, entry.byte_size)
            for entry in report.ignored_inventory_evidence
        } == {
            "leaf": ("unavailable", "symlink", None, None),
            "parent": ("unavailable", "unsafe-parent", None, None),
            "tree": ("unavailable", "symlink", None, None),
        }
        encoded = report_path.read_bytes()
        assert b"owned-junction-target" not in encoded
        assert b"unobservable fixture data" not in encoded
    finally:
        for junction in junctions:
            with suppress(FileNotFoundError):
                junction.rmdir()


@pytest.mark.parametrize(
    ("declared", "reason"),
    [
        ("src/pkg/module.py", "tracked"),
        ("unignored.dat", "not ignored"),
        ("C:relative", "not a native relative path"),
    ],
)
def test_cli_requires_git_ignore_ownership(tmp_path: Path, declared: str, reason: str) -> None:
    """Reject a tracked or unignored input before producing any observation report."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[{"evidence_id": "input", "path": declared, "capture": "presence"}]
    )
    head = repository.commit()
    report_path = tmp_path / "must-not-exist.json"

    result = repository.run_audit(
        "scan", "--root", str(repository.root), "--json-out", str(report_path)
    )

    assert result.returncode == 2
    assert f"ignored inventory path is {reason}: {declared}" in result.stderr
    assert not report_path.exists()
    assert repository.git_command("rev-parse", "HEAD").stdout.strip() == head


def test_directory_digest_refuses_membership_change_during_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Use the public collector while a real late entry appears under its retained handle."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "tree", "path": ".rigor/tree", "capture": "directory-sha256"}
        ]
    )
    head = repository.commit()
    original = repository.write_bytes(".rigor/tree/original.dat", b"original")
    directory = original.parent
    late = directory / "late.dat"
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))
    initial = scan_repository(repository.root, git_trust_policy=policy)
    assert initial.ignored_inventory_evidence[0].status == "observed"
    original_list = WindowsDirectory.list_entries
    with monkeypatch.context() as scoped:

        def change_after_listing(
            owner: WindowsDirectory, *, maximum_entries: int
        ) -> tuple[WindowsDirectoryEntry, ...]:
            """Add the owned fixture entry after an unchanged native enumeration."""
            assert owner.path == directory
            entries = original_list(owner, maximum_entries=maximum_entries)
            scoped.setattr(WindowsDirectory, "list_entries", original_list)
            late.write_bytes(b"late observation")
            return entries

        scoped.setattr(WindowsDirectory, "list_entries", change_after_listing)
        changed = scan_repository(repository.root, git_trust_policy=policy)

    assert late.is_file()
    observation = changed.ignored_inventory_evidence[0]
    assert (observation.status, observation.reason) == ("unavailable", "changed-while-read")
    assert observation.content_sha256 is None and observation.byte_size is None
    late.unlink()
    recovered = scan_repository(repository.root, git_trust_policy=policy)
    assert recovered.ignored_inventory_evidence == initial.ignored_inventory_evidence
    assert recovered.head == changed.head == initial.head == head
    assert original.read_bytes() == b"original"


def test_directory_digest_refuses_real_file_over_the_byte_limit(tmp_path: Path) -> None:
    """Refuse the aggregate directory budget before reading an oversized native child."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "tree", "path": ".rigor/tree", "capture": "directory-sha256"}
        ]
    )
    repository.commit()
    large = repository.write_bytes(".rigor/tree/large.dat", b"")
    with large.open("r+b") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))

    report = scan_repository(repository.root, git_trust_policy=policy)

    observation = report.ignored_inventory_evidence[0]
    assert (observation.status, observation.reason) == ("unavailable", "limit-exceeded")
    assert observation.content_sha256 is None and observation.byte_size is None


def test_scan_refuses_parent_change_after_policy_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bind the parent approved for Git ignore validation to the eventual disk read."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "reading", "path": ".rigor/work/reading", "capture": "file-sha256"}
        ]
    )
    head = repository.commit()
    current = repository.write_bytes(".rigor/work/reading", b"approved fixture input")
    directory = current.parent
    added = directory / "added"
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))
    original_close = WindowsDirectory.close
    with monkeypatch.context() as scoped:

        def change_after_closing(owner: WindowsDirectory) -> None:
            """Add an actual child after the real preflight handle release."""
            original_close(owner)
            if owner.path == directory:
                scoped.setattr(WindowsDirectory, "close", original_close)
                added.write_bytes(b"new fixture input")

        scoped.setattr(WindowsDirectory, "close", change_after_closing)
        report = scan_repository(repository.root, git_trust_policy=policy)

    observed = report.ignored_inventory_evidence[0]
    assert (observed.status, observed.reason) == ("unavailable", "changed-while-read")
    assert observed.content_sha256 is None and observed.byte_size is None
    assert report.head == head
    assert current.read_bytes() == b"approved fixture input"
    assert added.read_bytes() == b"new fixture input"


def test_scan_refuses_file_change_before_opening_the_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Match the content handle to the previously inspected native file identity."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "reading", "path": ".rigor/reading", "capture": "file-sha256"}
        ]
    )
    head = repository.commit()
    current = repository.write_bytes(".rigor/reading", b"first measurement")
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))
    original_inspect = WindowsDirectory.inspect_child
    with monkeypatch.context() as scoped:

        def write_after_inspection(owner: WindowsDirectory, name: str) -> WindowsChildSnapshot:
            """Capture real metadata before appending to the owned fixture file."""
            identity = original_inspect(owner, name)
            if name == current.name:
                scoped.setattr(WindowsDirectory, "inspect_child", original_inspect)
                with current.open("r+b") as stream:
                    stream.seek(0, os.SEEK_END)
                    stream.write(b" changed")
            return identity

        scoped.setattr(WindowsDirectory, "inspect_child", write_after_inspection)
        report = scan_repository(repository.root, git_trust_policy=policy)

    observed = report.ignored_inventory_evidence[0]
    assert (observed.status, observed.reason) == ("unavailable", "changed-while-read")
    assert observed.content_sha256 is None and observed.byte_size is None
    assert report.head == head
    assert current.read_bytes() == b"first measurement changed"


def test_directory_digest_rechecks_an_earlier_subtree_before_reporting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catch a real nested-file edit that occurs after its own directory was read."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "tree", "path": ".rigor/tree", "capture": "directory-sha256"}
        ]
    )
    head = repository.commit()
    earlier = repository.write_bytes(".rigor/tree/a/nested/value.dat", b"first observation")
    later = repository.write_bytes(".rigor/tree/z/value.dat", b"later branch")
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))
    initial = scan_repository(repository.root, git_trust_policy=policy)
    original = initial.ignored_inventory_evidence[0]
    assert original.status == "observed"
    original_listing = WindowsDirectory.list_entries
    with monkeypatch.context() as scoped:

        def edit_earlier_file(
            owner: WindowsDirectory, *, maximum_entries: int
        ) -> tuple[WindowsDirectoryEntry, ...]:
            """Append to the owned first branch while the scanner reads the last branch."""
            entries = original_listing(owner, maximum_entries=maximum_entries)
            if owner.path == later.parent:
                scoped.setattr(WindowsDirectory, "list_entries", original_listing)
                with earlier.open("ab") as stream:
                    stream.write(b" changed")
            return entries

        scoped.setattr(WindowsDirectory, "list_entries", edit_earlier_file)
        changed = scan_repository(repository.root, git_trust_policy=policy)

    assert earlier.read_bytes() == b"first observation changed"
    refusal = changed.ignored_inventory_evidence[0]
    assert (refusal.status, refusal.reason) == ("unavailable", "changed-while-read")
    assert refusal.byte_size is None and refusal.content_sha256 is None
    recovered = scan_repository(repository.root, git_trust_policy=policy)
    current = recovered.ignored_inventory_evidence[0]
    assert current.status == "observed"
    assert current.content_sha256 != original.content_sha256
    assert current.byte_size == len(b"first observation changed") + len(b"later branch")
    assert initial.head == changed.head == recovered.head == head


def test_scan_distinguishes_denied_parent_and_recovers_after_access_restoration(
    tmp_path: Path,
) -> None:
    """An actual unreadable NTFS parent yields unavailable evidence with no digest."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "value", "path": ".rigor/parent/value", "capture": "file-sha256"}
        ]
    )
    head = repository.commit()
    value = repository.write_bytes(".rigor/parent/value", b"native fixture")
    git = Path(repository.git)
    policy = GitTrustPolicy(executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),))
    healthy = scan_repository(repository.root, git_trust_policy=policy)
    system = Path(os.environ["SYSTEMROOT"]) / "System32"
    account = subprocess.run(  # nosec B603
        [str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=True,
        text=True,
    )
    sid = next(csv.reader(account.stdout.splitlines()))[-1]
    assert sid.startswith("S-1-")
    principal = "*" + sid
    acl = [str(system / "icacls.exe"), str(value.parent)]
    subprocess.run([*acl, "/deny", f"{principal}:(RA,RD)"], check=True, capture_output=True)
    try:
        refused = scan_repository(repository.root, git_trust_policy=policy)
    finally:
        subprocess.run([*acl, "/remove:d", principal], check=True, capture_output=True)

    observation = refused.ignored_inventory_evidence[0]
    assert (observation.status, observation.reason) == ("unavailable", "inaccessible-parent")
    assert observation.byte_size is None and observation.content_sha256 is None
    recovered = scan_repository(repository.root, git_trust_policy=policy)
    assert recovered.ignored_inventory_evidence == healthy.ignored_inventory_evidence
    assert healthy.head == refused.head == recovered.head == head
    assert value.read_bytes() == b"native fixture"
