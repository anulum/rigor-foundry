# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — candidate anchor contract tests
"""Verify exact Git-object anchors through real repository surfaces."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import (
    MAX_CANDIDATE_EXCERPT_BYTES,
    Candidate,
    RepositoryTreeAnchor,
    TrackedBlobAnchor,
    bounded_candidate_evidence,
    candidate_anchor_errors,
    candidate_anchor_from_dict,
    candidate_object_format_errors,
)
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.scanner import scan_repository


def _candidate_for(repository: GitRepository, rule_id: str) -> Candidate:
    """Return one named candidate from a real repository scan."""
    report = scan_repository(
        repository.root,
        Path("rigor-foundry-policy.json"),
    )
    return next(item for item in report.candidates if item.rule_id == rule_id)


def test_blob_anchor_follows_exact_dirty_worktree_bytes(tmp_path: Path) -> None:
    """Unstaged and staged-plus-unstaged scans never attest stale index bytes."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    test_path = repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE  # noqa: F401\n",
    )
    repository.write_policy()
    repository.commit()

    clean = _candidate_for(repository, "TA005-lint-suppression")
    assert isinstance(clean.anchor, TrackedBlobAnchor)
    index_oid = repository.git_command("rev-parse", ":tests/test_core.py").stdout.strip()
    assert clean.anchor.blob_oid == index_oid

    test_path.write_text(
        "from pkg.core import VALUE  # noqa: F401\nVALUE_COPY = VALUE\n",
        encoding="utf-8",
    )
    dirty = _candidate_for(repository, "TA005-lint-suppression")
    assert isinstance(dirty.anchor, TrackedBlobAnchor)
    worktree_oid = repository.git_command("hash-object", "tests/test_core.py").stdout.strip()
    assert dirty.anchor.blob_oid == worktree_oid
    assert dirty.anchor.blob_oid != index_oid
    assert dirty.anchor.content_sha256 == hashlib.sha256(test_path.read_bytes()).hexdigest()

    repository.git_command("add", "tests/test_core.py")
    staged_oid = repository.git_command("rev-parse", ":tests/test_core.py").stdout.strip()
    test_path.write_text(
        "from pkg.core import VALUE  # noqa: F401\nVALUE_COPY = VALUE\nSECOND = VALUE\n",
        encoding="utf-8",
    )
    mixed = _candidate_for(repository, "TA005-lint-suppression")
    assert isinstance(mixed.anchor, TrackedBlobAnchor)
    assert (
        mixed.anchor.blob_oid
        == repository.git_command(
            "hash-object",
            "tests/test_core.py",
        ).stdout.strip()
    )
    assert mixed.anchor.blob_oid != staged_oid


def test_inventory_hashes_every_scanned_blob_kind_without_writes(tmp_path: Path) -> None:
    """Text, binary, non-UTF-8, symlink, and oversize bytes receive exact blob IDs."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/text.py", "VALUE = 1\n")
    repository.write_bytes("src/pkg/binary.py", b"\x00\x01\x02")
    repository.write_bytes("native/kernel.rs", b"\xff\xfe\xfd")
    repository.symlink("studio/link.ts", "../src/pkg/text.py")
    repository.write_bytes("native/large.rs", b"x" * (8 * 1024 * 1024 + 1))
    repository.commit()

    inventory = load_git_inventory(repository.root)
    by_path = {item.path: item for item in inventory.files}
    for path in (
        "src/pkg/text.py",
        "src/pkg/binary.py",
        "native/kernel.rs",
        "studio/link.ts",
        "native/large.rs",
    ):
        item = by_path[path]
        assert item.scanned_blob_id == item.object_id
        assert TrackedBlobAnchor.build(item, line_start=1).errors(inventory) == ()

    (repository.root / "src/pkg/binary.py").unlink()
    missing_inventory = load_git_inventory(repository.root)
    missing = next(item for item in missing_inventory.files if item.path == "src/pkg/binary.py")
    assert missing.scanned_blob_id is None
    with pytest.raises(ValueError, match="no scanned blob"):
        TrackedBlobAnchor.build(missing, line_start=1)
    state = RepositoryTreeAnchor.build(missing_inventory, path=missing.path)
    assert state.errors(missing_inventory) == ()


def test_sha256_repository_binds_declared_object_format(tmp_path: Path) -> None:
    """SHA-256 Git repositories emit 64-character blob and tree identities."""
    repository = GitRepository.create(tmp_path / "repository", object_format="sha256")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE  # noqa: F401\n",
    )
    policy = repository.write_policy()
    repository.commit()

    report = scan_repository(repository.root, policy.relative_to(repository.root))
    candidate = next(
        item for item in report.candidates if item.rule_id == "TA005-lint-suppression"
    )
    assert report.git_object_format == "sha256"
    assert len(report.head_tree) == 64
    assert isinstance(candidate.anchor, TrackedBlobAnchor)
    assert len(candidate.anchor.blob_oid) == 64
    assert type(report).from_dict(report.to_dict()) == report


def test_anchor_parser_rejects_field_and_span_tampering(tmp_path: Path) -> None:
    """Kind, path, span, object identity, and content digest all fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "first = 1\nsecond = 2\nthird = 3\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    item = next(entry for entry in inventory.files if entry.path == "src/pkg/core.py")
    anchor = TrackedBlobAnchor.build(item, line_start=2, line_end=3)
    encoded = anchor.to_dict()
    assert candidate_anchor_from_dict(encoded) == anchor

    changes: tuple[tuple[str, object], ...] = (
        ("path", "../escape.py"),
        ("line_start", 0),
        ("line_end", 1),
        ("kind", "repository-tree"),
    )
    for field, value in changes:
        changed = {**encoded, field: value}
        with pytest.raises(ValueError):
            candidate_anchor_from_dict(changed)
    for field, value in (
        ("blob_oid", "0" * 40),
        ("content_sha256", "0" * 64),
    ):
        changed_anchor = candidate_anchor_from_dict({**encoded, field: value})
        assert changed_anchor.errors(inventory)
    mixed = {**encoded, "tree_oid": inventory.head_tree}
    with pytest.raises(ValueError, match="fields"):
        candidate_anchor_from_dict(mixed)
    with pytest.raises(ValueError, match="exceeds"):
        TrackedBlobAnchor.build(item, line_start=2, line_end=4)


def test_actual_alternate_policy_path_anchors_domain_candidates(tmp_path: Path) -> None:
    """Domain findings bind the discovered policy blob, not a hardcoded path."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    policy = repository.write_policy(required_domains=frozenset({"application-security"}))
    alternate = repository.root / "config/rigor-foundry/policy.json"
    alternate.parent.mkdir(parents=True)
    policy.rename(alternate)
    repository.commit()

    report = scan_repository(repository.root)
    candidate = next(
        item for item in report.candidates if item.rule_id == "GV004-uncontrolled-required-domain"
    )
    assert isinstance(candidate.anchor, TrackedBlobAnchor)
    assert candidate.anchor.path == "config/rigor-foundry/policy.json"
    assert (
        candidate.anchor.blob_oid
        == repository.git_command(
            "rev-parse",
            ":config/rigor-foundry/policy.json",
        ).stdout.strip()
    )
    assert candidate_anchor_errors(load_git_inventory(repository.root), report.candidates) == ()


def test_missing_state_and_gitlink_candidates_never_claim_blobs(tmp_path: Path) -> None:
    """Absent policy and gitlink findings use exact repository-tree anchors."""
    child = GitRepository.create(tmp_path / "child")
    child.write_text("README.md", "child\n")
    child_head = child.commit()
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.git_command("add", ".gitignore", "src/pkg/core.py")
    repository.git_command("update-index", "--add", "--cacheinfo", "160000", child_head, "vendor")
    repository.git_command("commit", "-m", "test: add repository state")

    report = scan_repository(repository.root)
    missing_policy = next(
        item
        for item in report.candidates
        if item.rule_id == "GV001-missing-repository-audit-policy"
    )
    gitlink = next(item for item in report.candidates if item.path == "vendor")
    assert isinstance(missing_policy.anchor, RepositoryTreeAnchor)
    assert isinstance(gitlink.anchor, RepositoryTreeAnchor)
    assert "blob_oid" not in missing_policy.anchor.to_dict()
    assert "blob_oid" not in gitlink.anchor.to_dict()
    assert missing_policy.anchor.tree_oid == report.head_tree
    assert gitlink.anchor.tree_oid == report.head_tree


def test_candidate_evidence_is_bounded_and_anchor_bound(tmp_path: Path) -> None:
    """Candidate IDs bind anchors and evidence cannot become an unbounded payload."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    item = next(entry for entry in inventory.files if entry.path == "src/pkg/core.py")
    anchor = TrackedBlobAnchor.build(item, line_start=1)
    candidate = Candidate.build(
        category="architecture",
        rule_id="AR002-wildcard-import-boundary",
        anchor=anchor,
        symbol="pkg.core",
        evidence="explicit export boundary",
        confidence="medium",
        rationale="exports require review",
        verification="import the public names",
    )
    changed = Candidate.build(
        category=candidate.category,
        rule_id=candidate.rule_id,
        anchor=RepositoryTreeAnchor.build(inventory, path=item.path),
        symbol=candidate.symbol,
        evidence=candidate.evidence,
        confidence=candidate.confidence,
        rationale=candidate.rationale,
        verification=candidate.verification,
    )
    assert changed.candidate_id != candidate.candidate_id
    with pytest.raises(ValueError, match="512 UTF-8 bytes"):
        Candidate.build(
            category=candidate.category,
            rule_id=candidate.rule_id,
            anchor=anchor,
            symbol=candidate.symbol,
            evidence="é" * 257,
            confidence=candidate.confidence,
            rationale=candidate.rationale,
            verification=candidate.verification,
        )


def test_bounded_evidence_preserves_count_identity_and_utf8_limit() -> None:
    """Large deterministic sequences retain identity without aborting a scan."""
    values = tuple(f"src/pkg/long_component_{index:04d}_é.py" for index in range(200))
    evidence = bounded_candidate_evidence("cycle members", values)
    changed = bounded_candidate_evidence("cycle members", (*values[:-1], "src/pkg/other.py"))

    assert len(evidence.encode("utf-8")) == MAX_CANDIDATE_EXCERPT_BYTES
    assert "count=200" in evidence
    assert "truncated=true" in evidence
    assert evidence != changed
    assert bounded_candidate_evidence("members", ("a", "b")).endswith("values=a, b")
    with pytest.raises(ValueError, match="no room"):
        bounded_candidate_evidence("x" * 600, ("value",))
    with pytest.raises(ValueError, match="non-empty string"):
        bounded_candidate_evidence(" ", ("value",))
    with pytest.raises(ValueError, match="non-empty string"):
        bounded_candidate_evidence("members", (" ",))


def test_anchor_records_fail_closed_on_malformed_protocol_fields(tmp_path: Path) -> None:
    """Schema, kind, path, digest, span, and candidate tampering are rejected."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.commit()
    inventory = load_git_inventory(repository.root)
    item = next(entry for entry in inventory.files if entry.path == "src/pkg/core.py")
    blob = TrackedBlobAnchor.build(item, line_start=1)
    tree = RepositoryTreeAnchor.build(inventory, path=".")

    for changed in (
        {**blob.to_dict(), "schema_version": "0"},
        {**blob.to_dict(), "path": "."},
        {**blob.to_dict(), "blob_oid": "g" * 40},
        {**blob.to_dict(), "content_sha256": "g" * 64},
        {**tree.to_dict(), "line_end": 2},
        {**tree.to_dict(), "kind": "unsupported"},
    ):
        with pytest.raises(ValueError):
            candidate_anchor_from_dict(changed)
    assert candidate_anchor_from_dict(tree.to_dict()) == tree

    candidate = Candidate.build(
        category="architecture",
        rule_id="AR002-wildcard-import-boundary",
        anchor=blob,
        symbol="pkg.core",
        evidence="public export boundary",
        confidence="medium",
        rationale="exports require review",
        verification="import the public names",
    )
    assert candidate.line == 1
    encoded = candidate.to_dict()
    for changed in (
        {**encoded, "extra": True},
        {**encoded, "category": "unsupported"},
        {**encoded, "confidence": "unsupported"},
        {**encoded, "candidate_id": "0" * 64},
    ):
        with pytest.raises(ValueError):
            Candidate.from_dict(changed)
    with pytest.raises(ValueError, match="unregistered"):
        Candidate.build(
            category="architecture",
            rule_id="AR999-unknown",
            anchor=blob,
            symbol="pkg.core",
            evidence="unknown rule",
            confidence="medium",
            rationale="rule must exist",
            verification="register the rule",
        )
    with pytest.raises(ValueError, match="non-empty string"):
        Candidate.build(
            category="architecture",
            rule_id="AR002-wildcard-import-boundary",
            anchor=blob,
            symbol="pkg.core",
            evidence=" ",
            confidence="medium",
            rationale="evidence must be present",
            verification="record evidence",
        )
    with pytest.raises(ValueError, match="does not belong"):
        Candidate.build(
            category="governance",
            rule_id="AR002-wildcard-import-boundary",
            anchor=blob,
            symbol="pkg.core",
            evidence="wrong category",
            confidence="medium",
            rationale="category must match",
            verification="use the registered category",
        )


def test_anchor_verification_reports_real_repository_drift(tmp_path: Path) -> None:
    """Anchors report missing bytes, changed trees, invalid spans, and hash formats."""
    first = GitRepository.create(tmp_path / "first")
    path = first.write_text("src/pkg/core.py", "VALUE = 1\n")
    first.commit()
    clean_inventory = load_git_inventory(first.root)
    clean_item = next(item for item in clean_inventory.files if item.path == "src/pkg/core.py")
    clean_blob = TrackedBlobAnchor.build(clean_item, line_start=1)
    clean_tree = RepositoryTreeAnchor.build(clean_inventory, path=clean_item.path)

    path.unlink()
    missing_inventory = load_git_inventory(first.root)
    missing_errors = clean_blob.errors(missing_inventory)
    assert "tracked path has no scanned blob" in missing_errors
    assert "blob content digest does not match the scanned bytes" in missing_errors
    oversized = TrackedBlobAnchor(
        path=clean_blob.path,
        line_start=1,
        line_end=2,
        blob_oid=clean_blob.blob_oid,
        content_sha256=clean_blob.content_sha256,
    )
    assert "blob line span exceeds the scanned object" in oversized.errors(missing_inventory)
    absent_path = TrackedBlobAnchor(
        path="src/pkg/absent.py",
        line_start=1,
        line_end=1,
        blob_oid=clean_blob.blob_oid,
        content_sha256=clean_blob.content_sha256,
    )
    assert absent_path.errors(missing_inventory) == (
        "tracked blob path must occur exactly once in the inventory",
    )

    second = GitRepository.create(tmp_path / "second", object_format="sha256")
    second.write_text("src/pkg/core.py", "VALUE = 2\n")
    second.commit()
    second_inventory = load_git_inventory(second.root)
    tree_errors = clean_tree.errors(second_inventory)
    assert "repository tree object does not match the inventory" in tree_errors
    assert "repository content digest does not match the inventory" in tree_errors
    assert "tree object id does not match the repository object format" in tree_errors
    assert "blob object id does not match the repository object format" in clean_blob.errors(
        second_inventory
    )
    assert candidate_object_format_errors("unknown", ()) == (
        "report object format is unsupported",
    )
    assert candidate_object_format_errors(
        "sha256",
        (
            Candidate.build(
                category="architecture",
                rule_id="AR002-wildcard-import-boundary",
                anchor=clean_blob,
                symbol="pkg.core",
                evidence="format mismatch",
                confidence="medium",
                rationale="object formats differ",
                verification="scan the declared repository",
            ),
        ),
    ) == ("candidates[0]: anchor object id length contradicts object format",)
