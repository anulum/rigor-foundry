# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent repository state tests
"""Exercise source identities against real Git objects and bounded JSON input."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository
from test_task_definition import budget

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.repository_state import RepositoryState1


def state(*, head: str = "a" * 40, tree: str = "b" * 40) -> RepositoryState1:
    """Bind explicit fixture observations without claiming authenticated ownership."""
    return RepositoryState1.build(
        project_id="application",
        root_id="code",
        registry_generation_id="generation-1",
        registry_sha256="a" * 64,
        baseline_head=head,
        head=head,
        head_tree=tree,
        baseline_inventory_digest="b" * 64,
        index_state_digest="c" * 64,
        worktree_state_digest="d" * 64,
        untracked_state_digest="e" * 64,
        generated_state_digest="f" * 64,
        configured_roots_digest="0" * 64,
    )


def test_real_git_state_round_trip_and_reference(tmp_path: Path) -> None:
    """Real commits/trees enter an independent exact source identity through JSON."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/main.py", "VALUE = 1\n")
    head = repository.commit()
    tree = repository.git_command("rev-parse", "HEAD^{tree}").stdout.strip()
    declared = state(head=head, tree=tree)
    path = tmp_path / "state.json"
    path.write_text(json.dumps(declared.to_dict()), encoding="utf-8")
    actual = RepositoryState1.from_dict(read_policy_document(path, budget=budget()))
    assert actual == declared
    reference = actual.reference()
    assert reference.pop("ref_digest") == canonical_digest(reference)
    assert reference["object_id"] == "code"
    assert reference["object_digest"] == actual.repository_state_digest
    body = actual.to_dict()
    assert body.pop("repository_state_digest") == canonical_digest(body)
    assert not {"proof", "inventory_digest", "context_digest", "source_path"}.intersection(body)
    repository.write_text("src/main.py", "VALUE = 2\n")
    changed_head = repository.commit()
    changed = state(
        head=changed_head, tree=repository.git_command("rev-parse", "HEAD^{tree}").stdout.strip()
    )
    assert changed.repository_state_digest != actual.repository_state_digest


def test_sha256_git_objects_remain_full_width() -> None:
    """The schema retains either complete Git object format without truncation."""
    declared = state(head="a" * 64, tree="b" * 64)
    assert RepositoryState1.from_dict(declared.to_dict()) == declared


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("project_id", "bad project"),
        ("root_id", ""),
        ("registry_generation_id", False),
        ("baseline_head", "a" * 39),
        ("head", "A" * 40),
        ("head_tree", "b" * 64),
        ("registry_sha256", "a" * 40),
        ("baseline_inventory_digest", None),
        ("index_state_digest", 1),
        ("worktree_state_digest", "0" * 63),
        ("untracked_state_digest", "G" * 64),
        ("generated_state_digest", ""),
        ("configured_roots_digest", {}),
    ],
)
def test_invalid_state_refuses_even_after_rehashing(field: str, invalid: object) -> None:
    """A fresh self-digest cannot legitimize invalid IDs, Git formats or inputs."""
    body = state().to_dict()
    body.pop("repository_state_digest")
    body[field] = invalid
    with pytest.raises(ValueError):
        RepositoryState1.from_dict({**body, "repository_state_digest": canonical_digest(body)})


@pytest.mark.parametrize("field", ["schema_version", "object_kind"])
def test_state_headers_are_exact(field: str) -> None:
    """Wrong or legacy headers cannot fall back to another parser."""
    data = state().to_dict()
    data[field] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        RepositoryState1.from_dict(data)


def test_closed_state_and_direct_forgery_refuse() -> None:
    """Consumers revalidate directly constructed or subsequently altered objects."""
    declared = state()
    data = declared.to_dict()
    for invalid in [
        None,
        {**data, "locator": "/caller"},
        {k: v for k, v in data.items() if k != "head"},
    ]:
        with pytest.raises(ValueError):
            RepositoryState1.from_dict(invalid)
    with pytest.raises(ValueError, match="differs"):
        replace(declared, head="c" * 40)
    object.__setattr__(declared, "repository_state_digest", "0" * 64)
    with pytest.raises(ValueError, match="differs"):
        declared.to_dict()
    with pytest.raises(ValueError, match="differs"):
        declared.reference()
