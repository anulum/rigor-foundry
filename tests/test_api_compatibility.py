# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared Python API manifest tests
"""Verify AA001 through real Git repositories and the public scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from rigor_foundry.models import AuditReport, Candidate
from rigor_foundry.scanner import scan_repository


def _manifest(*surfaces: tuple[str, list[str]]) -> str:
    """Return one canonical public-API manifest fixture."""
    return (
        json.dumps(
            {
                "schema_version": "1.0",
                "surfaces": [{"path": path, "exports": exports} for path, exports in surfaces],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _repository(
    tmp_path: Path,
    declaration: str | None = '__all__ = ["alpha", "beta"]\n',
) -> GitRepository:
    """Create one policy-bound real Git repository."""
    repository = GitRepository.create(tmp_path / "repository")
    if declaration is not None:
        repository.write_text("src/pkg/__init__.py", declaration)
    repository.write_policy()
    return repository


def _candidates(repository: GitRepository) -> tuple[Candidate, ...]:
    """Return only AA001 candidates from the public repository scan."""
    report = scan_repository(repository.root, Path("rigor-foundry-policy.json"))
    return tuple(
        candidate
        for candidate in report.candidates
        if candidate.rule_id == "AA001-unbound-api-manifest"
    )


def test_matching_manifest_is_quiet_and_dirty_drift_is_digest_only(tmp_path: Path) -> None:
    """Exact declarations stay quiet while dirty drift is blob-bound without name leakage."""
    repository = _repository(tmp_path)
    repository.write_text(
        "rigor-public-api.json",
        _manifest(("src/pkg/__init__.py", ["alpha", "beta"])),
    )
    repository.commit()
    assert _candidates(repository) == ()

    repository.write_text("src/pkg/__init__.py", '__all__ = ["alpha", "beta", "secret"]\n')
    candidates = _candidates(repository)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.category == "api-compatibility"
    assert candidate.symbol == "src/pkg/__init__.py"
    assert "manifest_state=mismatch" in candidate.evidence
    assert "declared_count=3" in candidate.evidence
    assert "manifest_count=2" in candidate.evidence
    assert "secret" not in candidate.evidence
    assert isinstance(candidate.anchor, TrackedBlobAnchor)
    assert (
        candidate.anchor.blob_oid
        == repository.git_command("hash-object", "src/pkg/__init__.py").stdout.strip()
    )

    report = scan_repository(repository.root, Path("rigor-foundry-policy.json"))
    assert AuditReport.from_dict(report.to_dict()) == report


def test_missing_manifest_and_unrecorded_surface_are_distinct(tmp_path: Path) -> None:
    """A missing manifest differs from a present manifest lacking one declaration."""
    repository = _repository(tmp_path)
    repository.commit()
    missing = _candidates(repository)
    assert len(missing) == 1
    assert "manifest_state=missing" in missing[0].evidence
    assert "manifest_sha256=absent" in missing[0].evidence

    repository.write_text("rigor-public-api.json", _manifest())
    repository.git_command("add", "rigor-public-api.json")
    unrecorded = _candidates(repository)
    assert len(unrecorded) == 1
    assert "manifest_state=unrecorded" in unrecorded[0].evidence


def test_dynamic_and_stale_surfaces_are_reported_independently(tmp_path: Path) -> None:
    """Dynamic declarations and stale manifest rows retain their own exact anchors."""
    repository = _repository(
        tmp_path,
        '__all__: list[str] = ["alpha"]\n__all__.append("beta")\n',
    )
    repository.write_text(
        "rigor-public-api.json",
        _manifest(
            ("src/gone.py", ["gone"]),
            ("src/pkg/__init__.py", ["alpha", "beta"]),
        ),
    )
    repository.commit()

    candidates = _candidates(repository)
    assert len(candidates) == 2
    dynamic = next(item for item in candidates if "manifest_state=dynamic" in item.evidence)
    stale = next(item for item in candidates if "manifest_state=stale" in item.evidence)
    assert isinstance(dynamic.anchor, TrackedBlobAnchor)
    assert dynamic.anchor.line_start == 1
    assert dynamic.anchor.line_end == 2
    assert isinstance(stale.anchor, TrackedBlobAnchor)
    assert stale.anchor.path == "rigor-public-api.json"
    assert stale.symbol == "src/gone.py"


@pytest.mark.parametrize(
    "declaration",
    [
        "__all__ = exported_names\n",
        '__all__ = ["alpha", 1]\n',
        '__all__ = ["alpha", "alpha"]\n',
        '__all__, other = (["alpha"], 1)\n',
    ],
)
def test_non_literal_or_ambiguous_declaration_is_dynamic(
    tmp_path: Path,
    declaration: str,
) -> None:
    """Non-literal, non-string, duplicate, and destructured declarations need review."""
    repository = _repository(tmp_path, declaration)
    repository.write_text("rigor-public-api.json", _manifest())
    repository.commit()
    candidates = _candidates(repository)
    assert len(candidates) == 1
    assert "manifest_state=dynamic" in candidates[0].evidence


def test_annotated_tuple_is_static_but_local_and_invalid_python_are_ignored(
    tmp_path: Path,
) -> None:
    """Only parseable module-level literal declarations inside source roots are surfaces."""
    repository = _repository(tmp_path, '__all__: tuple[str, ...] = ("alpha",)\n')
    repository.write_text("src/pkg/local.py", 'def f():\n    __all__ = ["local"]\n')
    repository.write_text("src/pkg/broken.py", "def broken(:\n")
    repository.write_text("tests/outside.py", '__all__ = ["outside"]\n')
    repository.write_text(
        "rigor-public-api.json",
        _manifest(("src/pkg/__init__.py", ["alpha"])),
    )
    repository.commit()
    assert _candidates(repository) == ()


@pytest.mark.parametrize(
    "manifest",
    [
        "not-json\n",
        "[]\n",
        json.dumps({"schema_version": "2.0", "surfaces": []}),
        json.dumps({"schema_version": "1.0", "surfaces": [], "extra": True}),
        json.dumps({"schema_version": "1.0", "surfaces": {}}),
        json.dumps({"schema_version": "1.0", "surfaces": ["bad"]}),
        json.dumps({"schema_version": "1.0", "surfaces": [{"path": "src/pkg/a.py"}]}),
        _manifest(("../escape.py", ["alpha"])),
        _manifest(("/absolute.py", ["alpha"])),
        _manifest(("src\\pkg\\a.py", ["alpha"])),
        _manifest(("src/pkg/a.txt", ["alpha"])),
        _manifest(("src/pkg/a.py", ["beta", "alpha"])),
        _manifest(("src/pkg/a.py", ["alpha", "alpha"])),
        _manifest(("src/pkg/a.py", ["not-valid"])),
        json.dumps(
            {
                "schema_version": "1.0",
                "surfaces": [{"path": "src/pkg/a.py", "exports": "alpha"}],
            }
        ),
        _manifest(("src/pkg/z.py", []), ("src/pkg/a.py", [])),
        _manifest(("src/pkg/a.py", []), ("src/pkg/a.py", [])),
    ],
)
def test_invalid_manifest_fails_closed_with_one_manifest_candidate(
    tmp_path: Path,
    manifest: str,
) -> None:
    """Every malformed schema variant fails closed at the tracked manifest."""
    repository = _repository(tmp_path)
    repository.write_text("rigor-public-api.json", manifest)
    repository.commit()
    candidates = _candidates(repository)
    assert len(candidates) == 1
    assert "manifest_state=invalid" in candidates[0].evidence
    assert isinstance(candidates[0].anchor, TrackedBlobAnchor)
    assert candidates[0].anchor.path == "rigor-public-api.json"


def test_non_text_manifest_and_missing_worktree_manifest_are_fail_closed(tmp_path: Path) -> None:
    """Binary bytes bind a blob while a removed tracked manifest binds repository state."""
    repository = _repository(tmp_path)
    manifest = repository.write_bytes("rigor-public-api.json", b"\x00\xff")
    repository.commit()
    non_text = _candidates(repository)
    assert len(non_text) == 1
    assert "manifest_state=non-text" in non_text[0].evidence
    assert isinstance(non_text[0].anchor, TrackedBlobAnchor)

    manifest.unlink()
    missing_worktree = _candidates(repository)
    assert len(missing_worktree) == 1
    assert "manifest_state=non-text" in missing_worktree[0].evidence
    assert isinstance(missing_worktree[0].anchor, RepositoryTreeAnchor)


def test_repository_without_declarations_or_manifest_is_quiet(tmp_path: Path) -> None:
    """AA001 does not claim relevance when the repository declares no Python surface."""
    repository = _repository(tmp_path, declaration=None)
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.commit()
    assert _candidates(repository) == ()
