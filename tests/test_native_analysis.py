# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native tree-sitter analysis tests
"""Verify native JS/TS/Go/Rust candidates, safe-equivalent rejection, and degradation."""

from __future__ import annotations

from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

pytest.importorskip("tree_sitter")

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.native_analysis import (
    _import_grammars,
    _line_evidence,
    _load_routes,
    _match_c,
    _match_go,
    _match_javascript,
    _match_julia,
    _match_rust,
    _match_shell,
    scan_native,
)

_JS = (
    "function h(a, b) {\n  eval(a);\n  const g = new Function(b);\n  obj.eval(a);\n  safe(b);\n}\n"
)
_TS = "const x: number = eval(y);\nconst z = new Function(a);\n"
_GO = (
    "package main\n\n"
    "func run(a string) {\n"
    "  exec.Command(a)\n"
    "  exec.CommandContext(ctx, a)\n"
    "  other.Command(a)\n"
    "  exec.LookPath(a)\n"
    "}\n"
)
_RS = 'fn run() {\n    unsafe { do_it(); }\n    let label = "unsafe";\n    safe_call(label);\n}\n'
_C = "int main(void) {\n  gets(buffer);\n  strcpy(dst, src);\n  system(command);\n  snprintf(out, n, fmt);\n}\n"
_CPP = "int run() {\n  popen(cmd, mode);\n  std::strcpy(dst, src);\n  return 0;\n}\n"
_JL = "function run(p)\n    unsafe_load(p)\n    unsafe_store!(p, v)\n    ccall(:f, Cvoid, ())\n    safe(p)\nend\n"
_SH = 'run() {\n  eval "$cmd"\n  echo done\n}\n'


class _FakeNode:
    """A configurable AST node for exercising the defensive missing-field guards."""

    def __init__(
        self,
        node_type: str,
        fields: dict[str, _FakeNode] | None = None,
        text: bytes = b"",
        children: tuple[_FakeNode, ...] = (),
    ) -> None:
        self.type = node_type
        self._fields = fields or {}
        self.children = children
        self.start_point = (0, 0)
        self.text = text

    def child_by_field_name(self, name: str) -> _FakeNode | None:
        return self._fields.get(name)


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_native(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_flags_each_native_language_and_ignores_safe(tmp_path: Path) -> None:
    """JS/TS eval-Function, Go os/exec, and Rust unsafe are flagged; safe code is not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/app.js", _JS)
    repository.write_text("src/app.ts", _TS)
    repository.write_text("src/run.go", _GO)
    repository.write_text("src/lib.rs", _RS)
    repository.write_text("src/raw.c", _C)
    repository.write_text("src/raw.cpp", _CPP)
    repository.write_text("src/calc.jl", _JL)
    repository.write_text("src/deploy.sh", _SH)
    repository.write_text("src/module.py", "eval('x')\n")
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    by_rule = {(item.anchor.path, item.rule_id, item.symbol) for item in candidates}
    assert ("src/app.js", "AS006-js-dynamic-code-execution", "eval") in by_rule
    assert ("src/app.js", "AS006-js-dynamic-code-execution", "new Function") in by_rule
    assert ("src/app.ts", "AS006-js-dynamic-code-execution", "eval") in by_rule
    assert ("src/run.go", "AS007-go-command-execution", "exec.Command") in by_rule
    assert ("src/run.go", "AS007-go-command-execution", "exec.CommandContext") in by_rule
    assert ("src/lib.rs", "AS008-rust-unsafe-block", "unsafe") in by_rule
    assert ("src/raw.c", "AS009-c-unsafe-libc", "gets") in by_rule
    assert ("src/raw.c", "AS009-c-unsafe-libc", "system") in by_rule
    assert ("src/raw.cpp", "AS009-c-unsafe-libc", "popen") in by_rule
    assert ("src/calc.jl", "AS010-julia-unsafe-memory", "unsafe_load") in by_rule
    assert ("src/calc.jl", "AS010-julia-unsafe-memory", "unsafe_store!") in by_rule
    assert ("src/deploy.sh", "AS011-shell-eval-execution", "eval") in by_rule
    # Go other.Command / exec.LookPath, the Rust "unsafe" string literal, JS member
    # access, C snprintf, C++ std::strcpy, Julia ccall/safe, shell echo, and the
    # Python file produce no candidate.
    go_candidates = [item for item in candidates if item.anchor.path == "src/run.go"]
    assert len(go_candidates) == 2
    assert len([item for item in candidates if item.anchor.path == "src/lib.rs"]) == 1
    # C: gets + strcpy + system (snprintf ignored); C++: popen (std::strcpy ignored).
    assert len([item for item in candidates if item.anchor.path == "src/raw.c"]) == 3
    assert len([item for item in candidates if item.anchor.path == "src/raw.cpp"]) == 1
    # Julia: unsafe_load + unsafe_store! (ccall/safe ignored); shell: one eval.
    assert len([item for item in candidates if item.anchor.path == "src/calc.jl"]) == 2
    assert len([item for item in candidates if item.anchor.path == "src/deploy.sh"]) == 1
    assert not [item for item in candidates if item.anchor.path == "src/module.py"]
    assert all(item.category == "application-security" for item in candidates)
    rust = next(item for item in candidates if item.rule_id == "AS008-rust-unsafe-block")
    assert rust.confidence == "medium"
    assert isinstance(rust.anchor, TrackedBlobAnchor)
    assert rust.evidence.startswith("file_sha256=")


def test_degrades_gracefully_without_the_optional_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing native extra yields no candidates rather than an error."""

    def _raise() -> tuple[object, ...]:
        raise ImportError("tree-sitter is not installed")

    monkeypatch.setattr("rigor_foundry.native_analysis._import_grammars", _raise)
    assert _load_routes() is None
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/app.js", _JS)
    policy_path = repository.write_policy()
    repository.commit()
    assert _scan(repository, policy_path) == ()


def test_matchers_defensive_guards_and_evidence_edges(tmp_path: Path) -> None:
    """The grammar import, matcher guard paths, binary skip, and evidence bounds hold."""
    assert len(_import_grammars()) == 9
    # Defensive guards: a call without a function field, a non-selector callee, and
    # a selector with a missing operand all resolve to no match.
    assert _match_javascript(_FakeNode("call_expression")) is None
    assert _match_javascript(_FakeNode("new_expression")) is None
    assert _match_go(_FakeNode("identifier")) is None
    assert _match_go(_FakeNode("call_expression")) is None
    assert _match_go(_FakeNode("call_expression", {"function": _FakeNode("identifier")})) is None
    selector = _FakeNode("selector_expression", {"field": _FakeNode("field_identifier")})
    assert _match_go(_FakeNode("call_expression", {"function": selector})) is None
    assert _match_rust(_FakeNode("block")) is None
    assert _match_c(_FakeNode("identifier")) is None
    assert _match_c(_FakeNode("call_expression")) is None
    assert (
        _match_c(_FakeNode("call_expression", {"function": _FakeNode("field_expression")})) is None
    )
    assert _match_julia(_FakeNode("identifier")) is None
    assert _match_julia(_FakeNode("call_expression")) is None
    assert (
        _match_julia(_FakeNode("call_expression", children=(_FakeNode("call_expression"),)))
        is None
    )
    assert _match_shell(_FakeNode("identifier")) is None
    assert _match_shell(_FakeNode("command")) is None

    repository = GitRepository.create(tmp_path / "repository")
    repository.write_bytes("src/binary.go", b"\xff\xfe exec.Command(x)")
    repository.write_text("src/plain.rs", "fn main() { let x = 1; }\n")
    policy_path = repository.write_policy()
    repository.commit()
    assert _scan(repository, policy_path) == ()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    assert _line_evidence(item, 9999).startswith("file_sha256=")
