# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only cross-repository Git object capture
"""Capture exact commit and tree objects from explicitly named repositories."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .cross_repository_campaign import (
    CrossRepositoryCampaign,
    InterRepositoryEdge,
    RepositorySnapshot,
)
from .git_provenance import GitExecutableProvenance, GitRunner, GitTrustPolicy
from .model_primitives import (
    require_digest,
    require_git_object,
    require_identifier,
    require_semantic_version,
)
from .models import canonical_digest

MAX_CAPTURE_REPOSITORIES: Final = 128


@dataclass(frozen=True)
class RepositoryCaptureRequest:
    """One explicit local repository and frozen replay input.

    Parameters
    ----------
    repository_id:
        Stable identifier used by the cross-repository campaign.
    repository_root:
        Absolute, canonical, non-symlink Git worktree root.
    requested_commit:
        Full SHA-1 or SHA-256 commit object identifier to capture.
    policy_digest:
        Audit-policy digest selected for later replay.
    rule_pack_version:
        ``rigor-foundry/``-prefixed semantic rule-pack version.
    rule_pack_digest:
        Frozen rule-pack digest.
    adapter_lock_digest:
        Frozen adapter-lock digest.
    toolchain_digest:
        Frozen toolchain digest.
    request_digest:
        Content identity of the explicit capture request, including its root.
    """

    repository_id: str
    repository_root: Path
    requested_commit: str
    policy_digest: str
    rule_pack_version: str
    rule_pack_digest: str
    adapter_lock_digest: str
    toolchain_digest: str
    request_digest: str

    @classmethod
    def build(
        cls,
        *,
        repository_id: str,
        repository_root: Path,
        requested_commit: str,
        policy_digest: str,
        rule_pack_version: str,
        rule_pack_digest: str,
        adapter_lock_digest: str,
        toolchain_digest: str,
    ) -> RepositoryCaptureRequest:
        """Validate and content-address one explicit capture request."""
        root = _canonical_repository_root(repository_root)
        if not rule_pack_version.startswith("rigor-foundry/"):
            raise ValueError("capture rule_pack_version must be rigor-foundry-prefixed")
        require_semantic_version(
            rule_pack_version.removeprefix("rigor-foundry/"),
            "capture rule_pack_version",
        )
        fields: dict[str, str] = {
            "repository_id": require_identifier(repository_id, "capture.repository_id"),
            "repository_root": str(root),
            "requested_commit": require_git_object(
                requested_commit,
                "capture.requested_commit",
            ),
            "policy_digest": require_digest(policy_digest, "capture.policy_digest"),
            "rule_pack_version": rule_pack_version,
            "rule_pack_digest": require_digest(
                rule_pack_digest,
                "capture.rule_pack_digest",
            ),
            "adapter_lock_digest": require_digest(
                adapter_lock_digest,
                "capture.adapter_lock_digest",
            ),
            "toolchain_digest": require_digest(
                toolchain_digest,
                "capture.toolchain_digest",
            ),
        }
        return cls(
            repository_id=fields["repository_id"],
            repository_root=root,
            requested_commit=fields["requested_commit"],
            policy_digest=fields["policy_digest"],
            rule_pack_version=fields["rule_pack_version"],
            rule_pack_digest=fields["rule_pack_digest"],
            adapter_lock_digest=fields["adapter_lock_digest"],
            toolchain_digest=fields["toolchain_digest"],
            request_digest=canonical_digest(fields),
        )


@dataclass(frozen=True)
class CrossRepositoryCapture:
    """One campaign produced by read-only Git plumbing over explicit roots.

    Parameters
    ----------
    campaign:
        Frozen campaign containing available or unavailable snapshots.
    request_digests:
        Ordered identities of the explicit repository requests.
    git_provenance:
        Exact trusted Git executable used for every repository read.
    capture_digest:
        Content identity of the campaign, requests, and Git provenance.
    """

    campaign: CrossRepositoryCampaign
    request_digests: tuple[str, ...]
    git_provenance: GitExecutableProvenance
    capture_digest: str

    @classmethod
    def build(
        cls,
        *,
        campaign: CrossRepositoryCampaign,
        request_digests: tuple[str, ...],
        git_provenance: GitExecutableProvenance,
    ) -> CrossRepositoryCapture:
        """Bind one campaign to its explicit requests and Git executable."""
        if len(request_digests) != len(set(request_digests)):
            raise ValueError("capture request digests must be unique")
        if len(request_digests) != len(campaign.snapshots):
            raise ValueError("capture request count does not match campaign snapshots")
        for index, digest in enumerate(request_digests):
            require_digest(digest, f"capture.request_digests[{index}]")
        body: dict[str, object] = {
            "campaign_digest": campaign.campaign_digest,
            "request_digests": list(request_digests),
            "git_provenance_identity": git_provenance.identity_digest,
        }
        return cls(
            campaign=campaign,
            request_digests=request_digests,
            git_provenance=git_provenance,
            capture_digest=canonical_digest(body),
        )


@dataclass(frozen=True)
class _RepositoryState:
    head: bytes
    head_tree: bytes
    status: bytes
    root_identity: tuple[int, int, int, int, int]


def _canonical_repository_root(path: Path) -> Path:
    """Return one existing absolute directory that traverses no symlink."""
    if not path.is_absolute():
        raise ValueError("capture repository root must be absolute")
    lexical = Path(os.path.abspath(path))
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise ValueError("capture repository root must exist") from exc
    if lexical.is_symlink():
        raise ValueError("capture repository root must not traverse symbolic links")
    if resolved != lexical:
        raise ValueError("capture repository root must not traverse symbolic links")
    if not resolved.is_dir():
        raise ValueError("capture repository root must be a directory")
    return resolved


def _run_git(runner: GitRunner, root: Path, *arguments: str, check: bool = True) -> bytes:
    """Run fixed read-only Git arguments for one explicitly safe worktree."""
    completed = runner.run(
        root,
        "-c",
        f"safe.directory={root}",
        *arguments,
        check=check,
    )
    return completed.stdout


def _decode_field(value: bytes, field: str) -> str:
    """Decode one non-empty Git-controlled UTF-8 field."""
    try:
        decoded = value.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"Git returned non-UTF-8 {field}") from exc
    if not decoded:
        raise RuntimeError(f"Git returned empty {field}")
    return decoded


def _root_identity(root: Path) -> tuple[int, int, int, int, int]:
    """Return path metadata that detects replacement during a capture."""
    metadata = root.stat(follow_symlinks=False)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _repository_state(root: Path, runner: GitRunner) -> _RepositoryState:
    """Read enough source state to prove the operator checkout stayed unchanged."""
    return _RepositoryState(
        head=_run_git(runner, root, "rev-parse", "--verify", "HEAD"),
        head_tree=_run_git(runner, root, "rev-parse", "--verify", "HEAD^{tree}"),
        status=_run_git(
            runner,
            root,
            "status",
            "--porcelain=v2",
            "--branch",
            "-z",
            "--untracked-files=all",
        ),
        root_identity=_root_identity(root),
    )


def _assert_repository_root(root: Path, runner: GitRunner) -> str:
    """Verify an explicit root is the exact Git top level and return object format."""
    top_level = _decode_field(
        _run_git(runner, root, "rev-parse", "--show-toplevel"),
        "repository root",
    )
    if Path(top_level).resolve(strict=True) != root:
        raise ValueError("capture repository root must be the exact Git worktree root")
    object_format = _decode_field(
        _run_git(runner, root, "rev-parse", "--show-object-format"),
        "object format",
    )
    if object_format not in {"sha1", "sha256"}:
        raise RuntimeError(f"Git repository uses unsupported object format: {object_format}")
    return object_format


def _capture_snapshot(
    request: RepositoryCaptureRequest,
    runner: GitRunner,
) -> RepositorySnapshot:
    """Resolve one exact commit and tree without changing the source checkout."""
    root = _canonical_repository_root(request.repository_root)
    object_format = _assert_repository_root(root, runner)
    expected_length = 40 if object_format == "sha1" else 64
    if len(request.requested_commit) != expected_length:
        raise ValueError("requested commit contradicts repository object format")
    before = _repository_state(root, runner)
    verified = runner.run(
        root,
        "-c",
        f"safe.directory={root}",
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        f"{request.requested_commit}^{{commit}}",
        check=False,
    )
    if verified.returncode == 1:
        snapshot = RepositorySnapshot.build(
            repository_id=request.repository_id,
            availability="unavailable",
            unavailable_reason="requested commit object is unavailable",
        )
    elif verified.returncode != 0:
        raise RuntimeError("Git could not verify the requested commit object")
    else:
        commit = _decode_field(verified.stdout, "requested commit")
        if commit != request.requested_commit:
            raise ValueError("requested object is not the exact commit object")
        tree = _decode_field(
            _run_git(
                runner,
                root,
                "rev-parse",
                "--verify",
                "--end-of-options",
                f"{commit}^{{tree}}",
            ),
            "requested commit tree",
        )
        snapshot = RepositorySnapshot.build(
            repository_id=request.repository_id,
            availability="available",
            head_commit=commit,
            head_tree=tree,
            policy_digest=request.policy_digest,
            rule_pack_version=request.rule_pack_version,
            rule_pack_digest=request.rule_pack_digest,
            adapter_lock_digest=request.adapter_lock_digest,
            toolchain_digest=request.toolchain_digest,
        )
    if _repository_state(root, runner) != before:
        raise RuntimeError("repository state changed during cross-repository capture")
    return snapshot


def capture_cross_repository_campaign(
    *,
    campaign_id: str,
    frozen_at: str,
    requests: tuple[RepositoryCaptureRequest, ...],
    edges: tuple[InterRepositoryEdge, ...] = (),
    git_trust_policy: GitTrustPolicy | None = None,
) -> CrossRepositoryCapture:
    """Capture a bounded campaign from exact local Git commit objects.

    The function runs only read-only Git plumbing against roots explicitly named
    in ``requests``. It does not discover repositories, create worktrees, run an
    adapter, grant remediation authority, or write campaign data.
    """
    if not requests:
        raise ValueError("cross-repository capture requests must not be empty")
    if len(requests) > MAX_CAPTURE_REPOSITORIES:
        raise ValueError(
            f"cross-repository capture supports at most {MAX_CAPTURE_REPOSITORIES} repositories"
        )
    repository_ids = tuple(request.repository_id for request in requests)
    if len(repository_ids) != len(set(repository_ids)):
        raise ValueError("capture repository identifiers must be unique")
    roots = tuple(request.repository_root for request in requests)
    if len(roots) != len(set(roots)):
        raise ValueError("capture repository roots must be unique")
    runner = GitRunner(git_trust_policy)
    snapshots = tuple(_capture_snapshot(request, runner) for request in requests)
    campaign = CrossRepositoryCampaign.build(
        campaign_id=campaign_id,
        frozen_at=frozen_at,
        snapshots=snapshots,
        edges=edges,
    )
    return CrossRepositoryCapture.build(
        campaign=campaign,
        request_digests=tuple(request.request_digest for request in requests),
        git_provenance=runner.provenance,
    )
