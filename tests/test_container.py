# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — container-hardening scanner tests
"""Verify bounded, precise container-hardening candidates over tracked Dockerfiles."""

from __future__ import annotations

import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.container import (
    _instructions,
    _is_dockerfile,
    _line_evidence,
    _parse_from,
    _runtime_user,
    scan_container,
)
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64

# Unpinned base and no runtime USER: both defects, with a comment and a continuation.
_UNPINNED_ROOT = (
    "# base build\nFROM python:3.12-slim\nRUN echo one && \\\n    echo two\nCOPY . /app\n"
)

# Multi-stage, digest-pinned, non-root: a platform flag, AS stages, USER with a group.
_SAFE = (
    f"FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:{_A} AS builder\n"
    "RUN make\n"
    f"FROM python:3.12-slim@sha256:{_B} AS runtime\n"
    "COPY --from=builder /app /app\n"
    "USER app:app\n"
)

# Digest-pinned base but an explicit root runtime user.
_PINNED_ROOT = f"FROM alpine@sha256:{_C}\nUSER root\n"

# scratch base and a build-stage reference are never unpinned findings; no USER here.
_STAGE_REFS = "FROM scratch AS base\nFROM base\n"


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_container(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_scanner_flags_unpinned_and_root_and_ignores_hardened(tmp_path: Path) -> None:
    """Every declared container defect is a candidate; hardened recipes are not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("Dockerfile", _UNPINNED_ROOT)
    repository.write_text("docker/safe.dockerfile", _SAFE)
    repository.write_text("Containerfile", _PINNED_ROOT)
    repository.write_text("deploy/Dockerfile.edge", _STAGE_REFS)
    repository.write_text("docs/notes.txt", "FROM python:3.12\n")
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    by_rule = collections.Counter(item.rule_id for item in candidates)
    assert by_rule == {
        "DK001-unpinned-base-image": 1,
        "DK002-root-runtime-user": 3,
    }
    # The hardened multi-stage recipe and the non-Dockerfile text produce nothing.
    assert not [
        item
        for item in candidates
        if item.anchor.path in {"docker/safe.dockerfile", "docs/notes.txt"}
    ]

    unpinned = next(item for item in candidates if item.rule_id == "DK001-unpinned-base-image")
    assert unpinned.category == "container"
    assert unpinned.confidence == "high"
    assert unpinned.symbol == "base-image"
    assert isinstance(unpinned.anchor, TrackedBlobAnchor)
    assert unpinned.anchor.path == "Dockerfile"
    assert unpinned.anchor.line_start == 2
    assert unpinned.evidence.startswith("file_sha256=")

    root = next(item for item in candidates if item.rule_id == "DK002-root-runtime-user")
    assert root.category == "container"
    assert root.symbol == "runtime-user"


def test_scanner_orders_findings_by_line_then_rule(tmp_path: Path) -> None:
    """Candidates from one Dockerfile are ordered by line then rule identifier."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("Dockerfile", _UNPINNED_ROOT)
    policy_path = repository.write_policy()
    repository.commit()

    ordered = [
        (item.anchor.line_start, item.rule_id)
        for item in _scan(repository, policy_path)
        if isinstance(item.anchor, TrackedBlobAnchor)
    ]
    assert ordered == sorted(ordered)


def test_scanner_skips_non_dockerfile_and_binary(tmp_path: Path) -> None:
    """Python source, binary blobs, and non-recipe text yield no candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "IMAGE = 'python:3.12'\n")
    repository.write_bytes("Dockerfile.bin", b"\xff\xfe FROM python:3.12\x00")
    # A recipe fragment with no FROM stage has nothing to pin or run.
    repository.write_text("Dockerfile.partial", "RUN echo hi\nLABEL role=fragment\n")
    policy_path = repository.write_policy()
    repository.commit()

    assert _scan(repository, policy_path) == ()


def test_is_dockerfile_classifies_paths() -> None:
    """Only Docker and OCI build recipes are in scope."""
    assert _is_dockerfile("Dockerfile") is True
    assert _is_dockerfile("Containerfile") is True
    assert _is_dockerfile("Dockerfile.runtime") is True
    assert _is_dockerfile("deploy/api.dockerfile") is True
    assert _is_dockerfile("service.containerfile") is True
    assert _is_dockerfile("src/pkg/dockerfile_helper.py") is False
    assert _is_dockerfile("docs/notes.txt") is False


def test_instruction_and_operand_helpers() -> None:
    """The instruction joiner and operand parsers hold on exotic shapes."""
    # A trailing continuation still emits its buffered instruction.
    assert _instructions("FROM python:3.12 \\\n") == [(1, "FROM python:3.12")]
    # A comment-only and blank-only file yields no instructions.
    assert _instructions("# only a comment\n\n") == []
    # A FROM with no operand (malformed) parses to an empty image and no stage.
    assert _parse_from("FROM") == ("", None)
    assert _parse_from("FROM --platform=linux/amd64 img AS base") == ("img", "base")
    # A USER directive with no account resolves to an empty account.
    assert _runtime_user("USER") == ""
    assert _runtime_user("USER app:app") == "app"


def test_line_evidence_is_bounded_beyond_the_file(tmp_path: Path) -> None:
    """Evidence for a line past the end of the file stays content-addressed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("Dockerfile", "FROM python:3.12\n")
    repository.commit()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    assert _line_evidence(item, 9999).startswith("file_sha256=")
