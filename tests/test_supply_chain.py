# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — supply-chain scanner tests
"""Verify bounded, precise supply-chain candidates over tracked requirement files."""

from __future__ import annotations

import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.supply_chain import (
    _is_requirements_file,
    _line_evidence,
    _logical_lines,
    scan_supply_chain,
)

# A hash-mode lock: two requirements carry hashes, one pinned entry is missing its hash.
_HASHED_LOCK = (
    "requests==2.31.0 \\\n"
    "    --hash=sha256:aaaa\n"
    "click==8.1.7\n"
    "lonely==1.0.0 \\\n"
    "    --hash=sha256:bbbb\n"
)

# A source input installing dependencies from VCS checkouts and a direct URL.
_VCS_INPUT = (
    "git+https://github.com/psf/requests.git@v2.31.0#egg=requests\n"
    "internal @ https://example.com/internal-1.0-py3-none-any.whl\n"
    "-e git+ssh://git@github.com/acme/lib.git#egg=lib\n"
    "--index-url https://pypi.org/simple\n"
    "numpy==1.26.0\n"
    "# a comment @ https://not-flagged.example\n"
)

# A fully hashed lock with no unverified or direct dependency.
_SAFE_LOCK = "requests==2.31.0 \\\n    --hash=sha256:cccc\n"


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_supply_chain(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_scanner_flags_unhashed_and_vcs_and_ignores_safe(tmp_path: Path) -> None:
    """Every declared supply-chain defect is a candidate; hardened equivalents are not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("requirements/app.txt", _HASHED_LOCK)
    repository.write_text("requirements/vcs.in", _VCS_INPUT)
    repository.write_text("requirements/safe.txt", _SAFE_LOCK)
    repository.write_text("src/pkg/config.txt", "git+https://evil.example/x.git#egg=x\n")
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    assert collections.Counter(item.rule_id for item in candidates) == {
        "SC001-unhashed-pinned-requirement": 1,
        "SC002-vcs-url-requirement": 3,
    }
    # The safe lock and the non-requirements file are ignored despite similar text.
    assert not [
        item
        for item in candidates
        if item.anchor.path in {"requirements/safe.txt", "src/pkg/config.txt"}
    ]

    unhashed = next(
        item for item in candidates if item.rule_id == "SC001-unhashed-pinned-requirement"
    )
    assert unhashed.category == "supply-chain"
    assert unhashed.confidence == "high"
    assert unhashed.symbol == "pinned-requirement"
    assert isinstance(unhashed.anchor, TrackedBlobAnchor)
    assert unhashed.anchor.path == "requirements/app.txt"
    assert unhashed.anchor.line_start == 3
    assert unhashed.evidence.startswith("file_sha256=")

    vcs = next(item for item in candidates if item.rule_id == "SC002-vcs-url-requirement")
    assert vcs.category == "supply-chain"
    assert vcs.symbol == "vcs-url-requirement"


def test_scanner_orders_findings_by_line_then_rule(tmp_path: Path) -> None:
    """Candidates from one file are deterministically ordered by line then rule."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("requirements/vcs.in", _VCS_INPUT)
    policy_path = repository.write_policy()
    repository.commit()

    lines = [
        item.anchor.line_start
        for item in _scan(repository, policy_path)
        if isinstance(item.anchor, TrackedBlobAnchor)
    ]
    assert lines == sorted(lines)


def test_scanner_skips_non_requirement_python_and_binary(tmp_path: Path) -> None:
    """Python source, binary blobs, and non-requirements text yield no candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "url = 'git+https://x.example/y.git'\n")
    repository.write_text("docs/requirements.rst", "install from git+https://x.example\n")
    repository.write_bytes("requirements/binary.txt", b"\xff\xfe git+https://x\x00")
    policy_path = repository.write_policy()
    repository.commit()

    assert _scan(repository, policy_path) == ()


def test_is_requirements_file_classifies_paths() -> None:
    """Only requirement-named or requirements-directory .txt/.in paths are in scope."""
    assert _is_requirements_file("requirements.txt") is True
    assert _is_requirements_file("requirements-dev.in") is True
    assert _is_requirements_file("requirements/native.txt") is True
    assert _is_requirements_file("deps/requirements/base.in") is True
    # Right suffix but neither a requirements name nor a requirements directory.
    assert _is_requirements_file("src/pkg/notes.txt") is False
    # A requirements-named file with an out-of-scope suffix is ignored.
    assert _is_requirements_file("requirements.py") is False


def test_logical_lines_join_continuations_including_trailing_backslash() -> None:
    """Backslash-continued physical lines join into one logical line at its first line."""
    joined = _logical_lines("a==1 \\\n    --hash=x\nb==2\n")
    assert [start for start, _ in joined] == [1, 3]
    assert joined[0][1].startswith("a==1")
    assert "--hash=x" in joined[0][1]
    assert joined[1][1] == "b==2"
    # A file whose final line ends with a continuation still emits the trailing block.
    assert _logical_lines("a==1 \\\n") == [(1, "a==1 ")]


def test_line_evidence_is_bounded_beyond_the_file(tmp_path: Path) -> None:
    """Evidence for a line past the end of the file stays content-addressed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("requirements/app.txt", "requests==2.31.0\n")
    repository.commit()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    assert _line_evidence(item, 9999).startswith("file_sha256=")
