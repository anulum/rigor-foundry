# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reliability scanner tests
"""Verify bounded, precise reliability candidates over tracked Python."""

from __future__ import annotations

import ast
import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.reliability import (
    _is_mutable_default,
    _line_evidence,
    scan_reliability,
)

_VULNERABLE = (
    "def sync_bad(a, items=[], mapping={}, uniq=set(), made=list()):\n"
    "    try:\n"
    "        risky()\n"
    "    except:\n"
    "        pass\n"
    "\n"
    "\n"
    "async def async_bad(*, needed, cfg={}):\n"
    "    try:\n"
    "        step()\n"
    "    except:\n"
    "        return None\n"
)

_SAFE = (
    "def sync_ok(\n"
    "    a,\n"
    "    items=None,\n"
    "    pair=(1, 2),\n"
    "    made=list([0]),\n"
    "    other=make(),\n"
    "    kw=dict(a=1),\n"
    "    built=ns.factory(),\n"
    "):\n"
    "    try:\n"
    "        run()\n"
    "    except ValueError:\n"
    "        recover()\n"
)


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_reliability(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_scanner_flags_each_unreliable_pattern_and_ignores_safe(tmp_path: Path) -> None:
    """Every declared reliability defect is a candidate; hardened equivalents are not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/vuln.py", _VULNERABLE)
    repository.write_text("src/pkg/safe.py", _SAFE)
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    by_file = collections.Counter(
        item.rule_id for item in candidates if item.anchor.path == "src/pkg/vuln.py"
    )
    assert by_file == {
        "RL001-bare-except": 2,
        "RL002-mutable-default-argument": 5,
    }
    assert not [item for item in candidates if item.anchor.path == "src/pkg/safe.py"]

    bare = next(item for item in candidates if item.rule_id == "RL001-bare-except")
    assert bare.category == "reliability"
    assert bare.confidence == "high"
    assert bare.symbol == "except"
    assert isinstance(bare.anchor, TrackedBlobAnchor)
    assert bare.evidence.startswith("file_sha256=")

    mutable = next(item for item in candidates if item.rule_id == "RL002-mutable-default-argument")
    assert mutable.category == "reliability"
    assert mutable.symbol == "default"


def test_scanner_orders_findings_by_line_then_symbol(tmp_path: Path) -> None:
    """Candidates from one file are deterministically ordered by line then symbol."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/vuln.py", _VULNERABLE)
    policy_path = repository.write_policy()
    repository.commit()

    lines = [
        item.anchor.line_start
        for item in _scan(repository, policy_path)
        if isinstance(item.anchor, TrackedBlobAnchor)
    ]
    assert lines == sorted(lines)


def test_scanner_skips_non_python_unparseable_and_binary(tmp_path: Path) -> None:
    """Non-Python, syntactically broken, and undecodable files yield no candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("docs/notes.txt", "def f(x=[]):\n    pass\n")
    repository.write_text("src/pkg/broken.py", "def f(:\n")
    repository.write_bytes("src/pkg/binary.py", b"\xff\xfe def f(x=[]):\x00")
    policy_path = repository.write_policy()
    repository.commit()

    assert _scan(repository, policy_path) == ()


def _default(source: str) -> ast.expr:
    """Return the single positional default expression parsed from ``source``."""
    function = ast.parse(source).body[0]
    assert isinstance(function, ast.FunctionDef)
    return function.args.defaults[0]


def test_is_mutable_default_classifies_container_shapes() -> None:
    """The mutable-default helper accepts fresh containers and rejects everything else."""
    assert _is_mutable_default(_default("def f(x=[]):\n    pass\n")) is True
    assert _is_mutable_default(_default("def f(x={}):\n    pass\n")) is True
    assert _is_mutable_default(_default("def f(x={1}):\n    pass\n")) is True
    assert _is_mutable_default(_default("def f(x=set()):\n    pass\n")) is True
    # A tuple literal is immutable and must not be flagged.
    assert _is_mutable_default(_default("def f(x=(1, 2)):\n    pass\n")) is False
    # A constructor call with arguments builds specific state, not a shared blank.
    assert _is_mutable_default(_default("def f(x=list([0])):\n    pass\n")) is False
    assert _is_mutable_default(_default("def f(x=dict(a=1)):\n    pass\n")) is False
    # A non-builtin call and an attribute call are out of scope.
    assert _is_mutable_default(_default("def f(x=make()):\n    pass\n")) is False
    assert _is_mutable_default(_default("def f(x=ns.factory()):\n    pass\n")) is False


def test_line_evidence_is_bounded_beyond_the_file(tmp_path: Path) -> None:
    """Evidence for a line past the end of the file stays content-addressed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    assert _line_evidence(item, 9999).startswith("file_sha256=")
