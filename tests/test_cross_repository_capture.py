# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only cross-repository capture tests
"""Exercise cross-repository capture against real local Git repositories."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cross_repository_campaign import InterRepositoryEdge
from rigor_foundry.cross_repository_capture import (
    MAX_CAPTURE_REPOSITORIES,
    CrossRepositoryCapture,
    RepositoryCaptureRequest,
    capture_cross_repository_campaign,
)
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy

FROZEN_AT = "2026-07-20T14:00:00Z"
POLICY_DIGEST = "a" * 64
RULE_PACK_DIGEST = "b" * 64
ADAPTER_LOCK_DIGEST = "c" * 64
TOOLCHAIN_DIGEST = "d" * 64


def request(
    repository: GitRepository,
    repository_id: str,
    commit: str,
) -> RepositoryCaptureRequest:
    """Build one fully frozen request for a real repository."""
    return RepositoryCaptureRequest.build(
        repository_id=repository_id,
        repository_root=repository.root,
        requested_commit=commit,
        policy_digest=POLICY_DIGEST,
        rule_pack_version="rigor-foundry/0.1.1",
        rule_pack_digest=RULE_PACK_DIGEST,
        adapter_lock_digest=ADAPTER_LOCK_DIGEST,
        toolchain_digest=TOOLCHAIN_DIGEST,
    )


def dependency(source: str, target: str) -> InterRepositoryEdge:
    """Build one explicit inter-repository dependency edge."""
    return InterRepositoryEdge.build(
        from_repository=source,
        to_repository=target,
        relationship="depends-on",
        rationale="test dependency",
    )


def source_state(repository: GitRepository) -> tuple[str, str, str]:
    """Return exact HEAD, tree, and complete non-ignored worktree status."""
    return (
        repository.git_command("rev-parse", "HEAD").stdout,
        repository.git_command("rev-parse", "HEAD^{tree}").stdout,
        repository.git_command(
            "status",
            "--porcelain=v2",
            "--branch",
            "-z",
            "--untracked-files=all",
        ).stdout,
    )


def request_from_mapping(arguments: dict[str, object]) -> RepositoryCaptureRequest:
    """Call the typed public builder from a mutation-test mapping."""
    return RepositoryCaptureRequest.build(
        repository_id=cast(str, arguments["repository_id"]),
        repository_root=cast(Path, arguments["repository_root"]),
        requested_commit=cast(str, arguments["requested_commit"]),
        policy_digest=cast(str, arguments["policy_digest"]),
        rule_pack_version=cast(str, arguments["rule_pack_version"]),
        rule_pack_digest=cast(str, arguments["rule_pack_digest"]),
        adapter_lock_digest=cast(str, arguments["adapter_lock_digest"]),
        toolchain_digest=cast(str, arguments["toolchain_digest"]),
    )


def test_capture_reads_historical_objects_without_changing_checkout(tmp_path: Path) -> None:
    """Two dirty source checkouts retain state while old commit trees are captured."""
    app = GitRepository.create(tmp_path / "app")
    app.write_text("src/app.py", "VALUE = 1\n")
    old_app = app.commit("initial app")
    old_app_tree = app.git_command("rev-parse", f"{old_app}^{{tree}}").stdout.strip()
    app.write_text("src/app.py", "VALUE = 2\n")
    app.commit("new app")
    app.write_text("src/app.py", "VALUE = 3\n")
    app.write_text("scratch.txt", "untracked\n")

    library = GitRepository.create(tmp_path / "library")
    library.write_text("src/library.py", "VALUE = 1\n")
    old_library = library.commit("initial library")
    old_library_tree = library.git_command("rev-parse", f"{old_library}^{{tree}}").stdout.strip()
    library.write_text("src/library.py", "VALUE = 2\n")
    library.commit("new library")
    library.write_text("notes.txt", "untracked\n")

    before = (source_state(app), source_state(library))
    result = capture_cross_repository_campaign(
        campaign_id="historical-release",
        frozen_at=FROZEN_AT,
        requests=(request(app, "app", old_app), request(library, "library", old_library)),
        edges=(dependency("app", "library"),),
        git_trust_policy=GitTrustPolicy(trusted_roots=("/usr/bin",)),
    )

    assert (source_state(app), source_state(library)) == before
    assert result.campaign.resolution() == "complete"
    assert result.campaign.snapshots[0].head_commit == old_app
    assert result.campaign.snapshots[0].head_tree == old_app_tree
    assert result.campaign.snapshots[1].head_commit == old_library
    assert result.campaign.snapshots[1].head_tree == old_library_tree
    assert result.request_digests == tuple(
        item.request_digest
        for item in (request(app, "app", old_app), request(library, "library", old_library))
    )
    assert len(result.capture_digest) == 64
    assert result.git_provenance.resolved_path == app.git


def test_missing_historical_commit_is_unavailable_not_complete(tmp_path: Path) -> None:
    """A missing exact object stays explicit while another repository still captures."""
    app = GitRepository.create(tmp_path / "app")
    app.write_text("src/app.py", "VALUE = 1\n")
    app_head = app.commit()
    library = GitRepository.create(tmp_path / "library")
    library.write_text("src/library.py", "VALUE = 1\n")
    library.commit()
    missing = "f" * 40

    result = capture_cross_repository_campaign(
        campaign_id="missing-history",
        frozen_at=FROZEN_AT,
        requests=(request(app, "app", app_head), request(library, "library", missing)),
        edges=(dependency("app", "library"),),
    )

    assert result.campaign.resolution() == "unavailable"
    assert result.campaign.unavailable_repositories() == ("library",)
    assert result.campaign.unavailable_dependencies() == ("library",)
    unavailable = result.campaign.snapshots[1]
    assert unavailable.unavailable_reason == "requested commit object is unavailable"
    assert unavailable.head_commit == ""
    assert unavailable.policy_digest == ""


def test_capture_rejects_implicit_or_ambiguous_repository_scope(tmp_path: Path) -> None:
    """Relative, symlinked, nested, duplicate, and absent roots fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/module.py", "VALUE = 1\n")
    head = repository.commit()
    with pytest.raises(ValueError, match="must be absolute"):
        RepositoryCaptureRequest.build(
            repository_id="repo",
            repository_root=Path("repository"),
            requested_commit=head,
            policy_digest=POLICY_DIGEST,
            rule_pack_version="rigor-foundry/0.1.1",
            rule_pack_digest=RULE_PACK_DIGEST,
            adapter_lock_digest=ADAPTER_LOCK_DIGEST,
            toolchain_digest=TOOLCHAIN_DIGEST,
        )
    with pytest.raises(ValueError, match="must exist"):
        request(
            GitRepository(root=tmp_path / "absent", git=repository.git),
            "absent",
            head,
        )
    regular_file = tmp_path / "regular-file"
    regular_file.write_text("not a repository\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a directory"):
        request(
            GitRepository(root=regular_file, git=repository.git),
            "regular-file",
            head,
        )
    link = tmp_path / "repository-link"
    os.symlink(repository.root, link)
    with pytest.raises(ValueError, match="must not traverse symbolic links"):
        request(GitRepository(root=link, git=repository.git), "linked", head)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_repository = GitRepository.create(real_parent / "repository")
    parent_repository.write_text("src/module.py", "VALUE = 1\n")
    parent_head = parent_repository.commit()
    linked_parent = tmp_path / "linked-parent"
    os.symlink(real_parent, linked_parent)
    with pytest.raises(ValueError, match="must not traverse symbolic links"):
        request(
            GitRepository(root=linked_parent / "repository", git=repository.git),
            "linked-parent",
            parent_head,
        )

    nested = repository.root / "src"
    nested_request = RepositoryCaptureRequest.build(
        repository_id="nested",
        repository_root=nested,
        requested_commit=head,
        policy_digest=POLICY_DIGEST,
        rule_pack_version="rigor-foundry/0.1.1",
        rule_pack_digest=RULE_PACK_DIGEST,
        adapter_lock_digest=ADAPTER_LOCK_DIGEST,
        toolchain_digest=TOOLCHAIN_DIGEST,
    )
    with pytest.raises(ValueError, match="exact Git worktree root"):
        capture_cross_repository_campaign(
            campaign_id="nested",
            frozen_at=FROZEN_AT,
            requests=(nested_request,),
        )

    valid = request(repository, "repo", head)
    with pytest.raises(ValueError, match="identifiers must be unique"):
        capture_cross_repository_campaign(
            campaign_id="duplicate-id",
            frozen_at=FROZEN_AT,
            requests=(valid, valid),
        )
    alias = request(repository, "alias", head)
    with pytest.raises(ValueError, match="roots must be unique"):
        capture_cross_repository_campaign(
            campaign_id="duplicate-root",
            frozen_at=FROZEN_AT,
            requests=(valid, alias),
        )


def test_capture_validates_request_and_operation_bounds(tmp_path: Path) -> None:
    """Malformed frozen inputs, object formats, empty work, and excess work fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/module.py", "VALUE = 1\n")
    head = repository.commit()
    arguments: dict[str, object] = {
        "repository_id": "repo",
        "repository_root": repository.root,
        "requested_commit": head,
        "policy_digest": POLICY_DIGEST,
        "rule_pack_version": "rigor-foundry/0.1.1",
        "rule_pack_digest": RULE_PACK_DIGEST,
        "adapter_lock_digest": ADAPTER_LOCK_DIGEST,
        "toolchain_digest": TOOLCHAIN_DIGEST,
    }
    for field, value, message in (
        ("repository_id", "bad id", "identifier"),
        ("requested_commit", "abc", "Git object"),
        ("policy_digest", "abc", "SHA-256"),
        ("rule_pack_digest", "abc", "SHA-256"),
        ("adapter_lock_digest", "abc", "SHA-256"),
        ("toolchain_digest", "abc", "SHA-256"),
        ("rule_pack_version", "0.1.1", "rigor-foundry-prefixed"),
        ("rule_pack_version", "rigor-foundry/01.1.1", "semantic version"),
    ):
        malformed = dict(arguments)
        malformed[field] = value
        with pytest.raises(ValueError, match=message):
            request_from_mapping(malformed)

    wrong_format = dict(arguments)
    wrong_format["requested_commit"] = "e" * 64
    sha256_request = request_from_mapping(wrong_format)
    with pytest.raises(ValueError, match="contradicts repository object format"):
        capture_cross_repository_campaign(
            campaign_id="wrong-format",
            frozen_at=FROZEN_AT,
            requests=(sha256_request,),
        )
    repository.git_command("tag", "-a", "v1", "-m", "annotated tag")
    tag_object = repository.git_command("rev-parse", "v1^{tag}").stdout.strip()
    tagged_request = request(repository, "tagged", tag_object)
    with pytest.raises(ValueError, match="not the exact commit object"):
        capture_cross_repository_campaign(
            campaign_id="tag-object",
            frozen_at=FROZEN_AT,
            requests=(tagged_request,),
        )
    with pytest.raises(ValueError, match="must not be empty"):
        capture_cross_repository_campaign(
            campaign_id="empty",
            frozen_at=FROZEN_AT,
            requests=(),
        )
    valid = request(repository, "repo", head)
    excess = tuple(
        RepositoryCaptureRequest(
            repository_id=f"repo-{index}",
            repository_root=repository.root / f"root-{index}",
            requested_commit=valid.requested_commit,
            policy_digest=valid.policy_digest,
            rule_pack_version=valid.rule_pack_version,
            rule_pack_digest=valid.rule_pack_digest,
            adapter_lock_digest=valid.adapter_lock_digest,
            toolchain_digest=valid.toolchain_digest,
            request_digest=f"{index:064x}",
        )
        for index in range(MAX_CAPTURE_REPOSITORIES + 1)
    )
    with pytest.raises(ValueError, match="at most"):
        capture_cross_repository_campaign(
            campaign_id="excess",
            frozen_at=FROZEN_AT,
            requests=excess,
        )


def test_capture_result_rejects_request_relation_errors(tmp_path: Path) -> None:
    """The public result binds one unique valid request digest per snapshot."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/module.py", "VALUE = 1\n")
    head = repository.commit()
    result = capture_cross_repository_campaign(
        campaign_id="binding",
        frozen_at=FROZEN_AT,
        requests=(request(repository, "repo", head),),
    )
    with pytest.raises(ValueError, match="count does not match"):
        CrossRepositoryCapture.build(
            campaign=result.campaign,
            request_digests=(),
            git_provenance=result.git_provenance,
        )
    with pytest.raises(ValueError, match="must be unique"):
        CrossRepositoryCapture.build(
            campaign=result.campaign,
            request_digests=("1" * 64, "1" * 64),
            git_provenance=result.git_provenance,
        )
    with pytest.raises(ValueError, match="SHA-256"):
        CrossRepositoryCapture.build(
            campaign=result.campaign,
            request_digests=("bad",),
            git_provenance=result.git_provenance,
        )


def test_capture_supports_real_sha256_repository_objects(tmp_path: Path) -> None:
    """A SHA-256 repository preserves its full commit and tree identities."""
    repository = GitRepository.create(tmp_path / "sha256-repository", object_format="sha256")
    repository.write_text("src/module.py", "VALUE = 1\n")
    head = repository.commit()
    tree = repository.git_command("rev-parse", "HEAD^{tree}").stdout.strip()

    result = capture_cross_repository_campaign(
        campaign_id="sha256-capture",
        frozen_at=FROZEN_AT,
        requests=(request(repository, "sha256-repo", head),),
    )

    assert len(head) == 64
    assert len(tree) == 64
    assert result.campaign.snapshots[0].head_commit == head
    assert result.campaign.snapshots[0].head_tree == tree


def test_capture_preserves_trailing_space_in_real_repository_root(tmp_path: Path) -> None:
    """Git's output terminator is removed without stripping valid path bytes."""
    repository = GitRepository.create(tmp_path / "repository ")
    repository.write_text("src/module.py", "VALUE = 1\n")
    head = repository.commit()

    result = capture_cross_repository_campaign(
        campaign_id="space-path",
        frozen_at=FROZEN_AT,
        requests=(request(repository, "space-repo", head),),
    )

    assert result.campaign.snapshots[0].head_commit == head


def test_capture_fault_boundaries_fail_closed_through_public_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Controlled Git faults and a real concurrent edit cannot yield a capture."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/module.py", "VALUE = 1\n")
    head = repository.commit()
    capture_request = request(repository, "repo", head)
    original_run = GitRunner.run

    def injected_output(payload: bytes, selected_argument: str):
        def run(
            runner: GitRunner,
            cwd: Path,
            *arguments: str,
            check: bool = True,
            timeout_seconds: int = 30,
        ) -> subprocess.CompletedProcess[bytes]:
            if selected_argument in arguments:
                return subprocess.CompletedProcess(arguments, 0, payload, b"")
            return original_run(
                runner,
                cwd,
                *arguments,
                check=check,
                timeout_seconds=timeout_seconds,
            )

        return run

    monkeypatch.setattr(GitRunner, "run", injected_output(b"\xff\n", "--show-toplevel"))
    with pytest.raises(RuntimeError, match="non-UTF-8 repository root"):
        capture_cross_repository_campaign(
            campaign_id="non-utf8",
            frozen_at=FROZEN_AT,
            requests=(capture_request,),
        )
    monkeypatch.setattr(GitRunner, "run", injected_output(b"\n", "--show-toplevel"))
    with pytest.raises(RuntimeError, match="empty repository root"):
        capture_cross_repository_campaign(
            campaign_id="empty-root",
            frozen_at=FROZEN_AT,
            requests=(capture_request,),
        )
    monkeypatch.setattr(GitRunner, "run", injected_output(b"sha512\n", "--show-object-format"))
    with pytest.raises(RuntimeError, match="unsupported object format"):
        capture_cross_repository_campaign(
            campaign_id="unsupported-format",
            frozen_at=FROZEN_AT,
            requests=(capture_request,),
        )

    def fail_object_verification(
        runner: GitRunner,
        cwd: Path,
        *arguments: str,
        check: bool = True,
        timeout_seconds: int = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        if "--quiet" in arguments:
            return subprocess.CompletedProcess(arguments, 2, b"", b"object database failure")
        return original_run(
            runner,
            cwd,
            *arguments,
            check=check,
            timeout_seconds=timeout_seconds,
        )

    monkeypatch.setattr(GitRunner, "run", fail_object_verification)
    with pytest.raises(RuntimeError, match="could not verify"):
        capture_cross_repository_campaign(
            campaign_id="object-failure",
            frozen_at=FROZEN_AT,
            requests=(capture_request,),
        )

    status_reads = 0

    def edit_between_state_reads(
        runner: GitRunner,
        cwd: Path,
        *arguments: str,
        check: bool = True,
        timeout_seconds: int = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal status_reads
        if "status" in arguments:
            status_reads += 1
            if status_reads == 2:
                repository.write_text("src/module.py", "VALUE = 2\n")
        return original_run(
            runner,
            cwd,
            *arguments,
            check=check,
            timeout_seconds=timeout_seconds,
        )

    monkeypatch.setattr(GitRunner, "run", edit_between_state_reads)
    with pytest.raises(RuntimeError, match="state changed"):
        capture_cross_repository_campaign(
            campaign_id="concurrent-change",
            frozen_at=FROZEN_AT,
            requests=(capture_request,),
        )
    assert status_reads == 2
