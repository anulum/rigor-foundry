# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact revision CLI and Python audit journeys
"""Verify historical reports against actual local Git objects."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry import AuditReport, GitTrustPolicy, scan_repository
from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.historical_checkout import (
    load_verified_historical_inventory,
    materialise_historical_commit,
)

_SOURCE = "src/pkg/optional.py"
_OLD_BYTES = b"try:\n    import pkg.extension\nexcept Exception:\n    extension = None\n"
_POLICY = "rigor-foundry-policy.json"


def _arguments(repository: GitRepository, commit: str) -> list[str]:
    """Use the production scan command and explicit native Git trust."""
    return [
        "scan-revision",
        "--root",
        str(repository.root / "src"),
        commit,
        "--git-executable",
        Path(repository.git).as_posix(),
        "--git-trust-root",
        Path(repository.git).parent.as_posix(),
    ]


def _state(repository: GitRepository) -> tuple[str, bytes, bytes, bytes]:
    """Capture the original refs, index, options and owned working file."""
    return (
        repository.git_command("show-ref", "--head").stdout,
        (repository.root / ".git" / "index").read_bytes(),
        (repository.root / ".git" / "config").read_bytes(),
        (repository.root / _SOURCE).read_bytes(),
    )


def _prepare(root: Path, object_format: str = "sha1") -> tuple[GitRepository, str]:
    """Commit an authored finding, explicit checkout attributes and tracked policy."""
    repository = GitRepository.create(root, object_format=object_format)
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text(".gitattributes", "*.py text eol=crlf\n")
    repository.write_bytes(_SOURCE, _OLD_BYTES)
    repository.write_policy(
        ignored_inventory=[
            {"evidence_id": "runtime", "path": ".rigor/runtime", "capture": "file-sha256"}
        ]
    )
    return repository, repository.commit("test: commit the historical audit input")


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_historical_scan_uses_pinned_bytes_and_preserves_live_checkout(
    tmp_path: Path, object_format: str
) -> None:
    """A detached audit is deterministic on both object formats and ignores live edits."""
    repository, commit = _prepare(tmp_path / "source repo #1", object_format)
    old_tree = repository.git_command("rev-parse", f"{commit}^{{tree}}").stdout.strip()
    old_blob = repository.git_command("rev-parse", f"{commit}:{_SOURCE}").stdout.strip()
    (repository.root / _SOURCE).unlink()
    repository.git_command("checkout-index", "--force", "--", _SOURCE)
    assert b"\r\n" in (repository.root / _SOURCE).read_bytes()
    repository.write_text(_SOURCE, "VALUE = 1\n")
    repository.write_policy()
    live = repository.commit("test: advance the live checkout")
    repository.write_text(_SOURCE, "VALUE = 2\n")
    repository.git_command("add", "--", _SOURCE)
    repository.write_text(_SOURCE, "VALUE = 3\n")
    repository.write_text(".rigor/runtime", "live runtime only\n")
    before = _state(repository)

    json_output = tmp_path / "report.json"
    markdown_output = tmp_path / "report.md"
    result = repository.run_audit(
        *_arguments(repository, commit),
        "--policy",
        _POLICY,
        "--json-out",
        str(json_output),
        "--markdown-out",
        str(markdown_output),
        "--fail-on-candidates",
    )
    assert result.returncode == 1 and not result.stderr
    report = AuditReport.from_path(json_output)
    assert report.head != live
    assert report.head == commit and report.head_tree == old_tree and report.branch == "HEAD"
    assert report.git_object_format == object_format
    assert report.repository_root == str(repository.root.resolve()) and not report.dirty_paths
    (candidate,) = [
        item
        for item in report.candidates
        if item.rule_id == "AR003-broad-optional-import-boundary" and item.path == _SOURCE
    ]
    assert isinstance(candidate.anchor, TrackedBlobAnchor)
    assert candidate.anchor.blob_oid == old_blob
    assert candidate.anchor.content_sha256 == hashlib.sha256(_OLD_BYTES).hexdigest()
    assert _SOURCE in markdown_output.read_text(encoding="utf-8")
    (observed,) = report.ignored_inventory_evidence
    assert observed.status == "unavailable" and observed.reason == "historical-state-unavailable"

    policy = GitTrustPolicy(
        executable=Path(repository.git).as_posix(),
        trusted_roots=(Path(repository.git).parent.as_posix(),),
    )
    api_report = scan_repository(
        repository.root, Path(_POLICY), git_trust_policy=policy, revision=commit
    )
    assert api_report == report
    ordinary = scan_repository(repository.root, Path(_POLICY), git_trust_policy=policy)
    assert ordinary.head == live and ordinary.dirty_paths == (_SOURCE,)
    assert not any(item.rule_id == candidate.rule_id for item in ordinary.candidates)
    assert _state(repository) == before


def test_historical_scan_refuses_missing_objects_tags_and_conflicting_selection(
    tmp_path: Path,
) -> None:
    """Only a full local commit can emit historical JSON or Markdown."""
    repository, commit = _prepare(tmp_path / "source")
    repository.git_command("tag", "-a", "tagged", "-m", "annotated object", commit)
    tag = repository.git_command("rev-parse", "tagged").stdout.strip()
    before = _state(repository)
    output = tmp_path / "report.json"

    for invalid in ("HEAD", commit[:12], "f" * 40, tag):
        result = repository.run_audit(*_arguments(repository, invalid), "--json-out", str(output))
        assert result.returncode == 2 and not result.stdout, (invalid, result)
        assert not output.exists()
        if invalid == tag:
            assert "must identify the exact commit object" in result.stderr
    conflict = repository.run_audit(
        *_arguments(repository, commit), "--changed-since", "HEAD", "--json-out", str(output)
    )
    assert (
        conflict.returncode == 2 and "unrecognized arguments: --changed-since" in conflict.stderr
    )
    assert not output.exists() and _state(repository) == before


def test_historical_scan_refuses_temporary_storage_in_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OS temp override cannot introduce a checkout into the source tree."""
    repository, commit = _prepare(tmp_path / "source")
    temporary = repository.root / ".rigor" / "temporary"
    temporary.mkdir(parents=True)
    before = _state(repository)
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, os.fspath(temporary))

    result = repository.run_audit(*_arguments(repository, commit))
    assert result.returncode == 2
    assert "temporary directory must be outside the source repository" in result.stderr
    assert not list(temporary.iterdir()) and _state(repository) == before


def test_pinned_submodule_remains_a_gitlink_without_checkout(tmp_path: Path) -> None:
    """The verified checkout retains the Gitlink identity without loading child files."""
    repository, commit = _prepare(tmp_path / "source")
    link_path = "src/pkg/dependency.py"
    repository.git_command("update-index", "--add", "--cacheinfo", f"160000,{commit},{link_path}")
    repository.git_command("commit", "-m", "test: retain one explicit gitlink")
    selected = repository.git_command("rev-parse", "HEAD").stdout.strip()

    result = repository.run_audit(*_arguments(repository, selected))
    assert result.returncode == 0, result.stderr
    report = AuditReport.from_dict(json.loads(result.stdout))
    assert report.head == selected
    (observed,) = [item for item in report.candidates if item.path == link_path]
    assert "content_kind=gitlink" in observed.evidence
    assert not (repository.root / link_path).exists()


def test_checkout_readback_rejects_wrong_head_and_hidden_worktree_change(tmp_path: Path) -> None:
    """Git's clean status alone cannot attest the actual inspected bytes."""
    repository, commit = _prepare(tmp_path / "source")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    runner = GitRunner(
        GitTrustPolicy(
            executable=Path(repository.git).as_posix(),
            trusted_roots=(Path(repository.git).parent.as_posix(),),
        )
    )
    materialise_historical_commit(repository.root, checkout, commit, runner)

    wrong_commit = "f" * len(commit)
    with pytest.raises(RuntimeError, match="not clean, detached and at the selected commit"):
        load_verified_historical_inventory(checkout, wrong_commit, runner)

    snapshot = GitRepository(checkout, repository.git)
    snapshot.git_command("update-index", "--assume-unchanged", "--", _SOURCE)
    snapshot.write_text(_SOURCE, "VALUE = 2\n")
    assert snapshot.git_command("status", "--porcelain").stdout == ""
    with pytest.raises(RuntimeError, match="historical checkout bytes differ from Git"):
        load_verified_historical_inventory(checkout, commit, runner)


@pytest.mark.skipif(os.name == "nt", reason="Win32 file names cannot contain line breaks")
def test_git_object_database_path_cannot_add_an_alternate_line(tmp_path: Path) -> None:
    """A real Git directory with a line break cannot create a second object-store entry."""
    repository, commit = _prepare(tmp_path / "source\nother")
    before = _state(repository)

    result = repository.run_audit(*_arguments(repository, commit))

    assert result.returncode == 2
    assert "historical Git object store must have a single absolute path" in result.stderr
    assert _state(repository) == before


@pytest.mark.parametrize(
    ("path", "message"),
    [
        (_SOURCE, "ignored inventory path is tracked"),
        ("runtime/file", "ignored inventory path is not ignored"),
    ],
)
def test_historical_policy_validates_declared_ignored_paths(
    tmp_path: Path, path: str, message: str
) -> None:
    """The historical mode retains the requirement for an actually ignored path."""
    repository, _ = _prepare(tmp_path / "source")
    repository.write_policy(
        ignored_inventory=[{"evidence_id": "checked", "path": path, "capture": "presence"}]
    )
    selected = repository.commit("test: declare a non-ignored historical path")

    result = repository.run_audit(*_arguments(repository, selected))

    assert result.returncode == 2 and message in result.stderr
