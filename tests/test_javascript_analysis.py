# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native JavaScript/TypeScript analysis tests
"""Verify tree-sitter JavaScript/TypeScript candidates and graceful degradation."""

from __future__ import annotations

from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

pytest.importorskip("tree_sitter")

import tree_sitter
import tree_sitter_javascript

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.javascript_analysis import (
    _dynamic_execution_findings,
    _import_grammars,
    _line_evidence,
    _load_parsers,
    scan_javascript,
)
from rigor_foundry.models import AuditPolicy, Candidate

_JS = (
    "function handle(a, b) {\n"
    "  eval(a);\n"
    "  const g = new Function(b);\n"
    "  obj.eval(a);\n"
    "  safe(b);\n"
    "  new Widget(a);\n"
    "}\n"
)
_TS = "const x: number = eval(y);\nconst h = new Function(z);\n"
_SAFE = "function handle(a) {\n  JSON.parse(a);\n  const g = () => a;\n}\n"


class _FakeNode:
    """A minimal AST node that exposes an empty call field for the guard path."""

    def __init__(self, node_type: str, children: tuple[_FakeNode, ...] = ()) -> None:
        self.type = node_type
        self.children = children
        self.start_point = (0, 0)

    def child_by_field_name(self, _name: str) -> None:
        return None


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_javascript(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_flags_js_and_ts_dynamic_execution_and_ignores_safe(tmp_path: Path) -> None:
    """eval and Function are flagged natively in JS and TS; safe code is not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/app.js", _JS)
    repository.write_text("src/app.ts", _TS)
    repository.write_text("src/safe.js", _SAFE)
    repository.write_text("src/module.py", "eval('x')\n")
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    located = {(item.anchor.path, item.symbol) for item in candidates}
    assert ("src/app.js", "eval") in located
    assert ("src/app.js", "new Function") in located
    assert ("src/app.ts", "eval") in located
    assert ("src/app.ts", "new Function") in located
    assert all(item.rule_id == "AS006-js-dynamic-code-execution" for item in candidates)
    assert all(item.category == "application-security" for item in candidates)
    assert all(item.confidence == "high" for item in candidates)
    # obj.eval (member access), safe(), new Widget, and the Python file are ignored.
    assert not [item for item in candidates if item.anchor.path == "src/safe.js"]
    assert not [item for item in candidates if item.anchor.path == "src/module.py"]
    sample = next(
        item for item in candidates if item.anchor.path == "src/app.js" and item.symbol == "eval"
    )
    assert isinstance(sample.anchor, TrackedBlobAnchor)
    assert sample.evidence.startswith("file_sha256=")


def test_degrades_gracefully_without_the_optional_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing tree-sitter extra yields no candidates rather than an error."""

    def _raise() -> tuple[object, object, object]:
        raise ImportError("tree-sitter is not installed")

    monkeypatch.setattr("rigor_foundry.javascript_analysis._import_grammars", _raise)
    assert _load_parsers() is None
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/app.js", _JS)
    policy_path = repository.write_policy()
    repository.commit()
    assert _scan(repository, policy_path) == ()


def test_grammar_import_findings_and_evidence_edges(tmp_path: Path) -> None:
    """The grammar import, finding walk, and evidence bounds behave correctly."""
    assert len(_import_grammars()) == 3
    parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_javascript.language()))
    tree = parser.parse(b"eval(a); obj.eval(b); new Widget(); new Function(c);")
    assert sorted(_dynamic_execution_findings(tree.root_node)) == [
        (1, "eval"),
        (1, "new Function"),
    ]
    # A call node whose target field is absent exercises the defensive guard.
    root = _FakeNode("program", (_FakeNode("call_expression"), _FakeNode("new_expression")))
    assert _dynamic_execution_findings(root) == []

    repository = GitRepository.create(tmp_path / "repository")
    repository.write_bytes("src/binary.js", b"\xff\xfe eval(x)")
    repository.write_text("src/plain.ts", "const value = 1;\n")
    policy_path = repository.write_policy()
    repository.commit()
    assert _scan(repository, policy_path) == ()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    assert _line_evidence(item, 9999).startswith("file_sha256=")
