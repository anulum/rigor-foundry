# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — general task definition tests
"""Exercise declared task identity through actual JSON and public model APIs."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.task_definition import TaskDefinition1


def budget(**changes: int) -> PolicyReadBudget1:
    """Specify all allocation ceilings for declared task parsing."""
    limits = {
        "max_document_bytes": 65536,
        "max_source_bytes": 65536,
        "max_total_source_bytes": 131072,
        "max_sources": 2,
        "max_rules": 8,
        "max_references": 12,
        "max_depth": 8,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def definition(
    *, statement: str = "Verify the maintained application sources."
) -> TaskDefinition1:
    """Declare general work without creating any audit or review record."""
    return TaskDefinition1.build(
        task_id="application-verification",
        revision="declared-1",
        actor_ids=("actor-a", "actor-b"),
        project_id="application",
        group_id="engineering",
        root_ids=("application-code", "application-tests"),
        statement=statement,
        lifecycle="active",
        budget=budget(),
    )


def test_real_json_to_definition_and_independent_identity(tmp_path: Path) -> None:
    """The existing bounded document reader feeds a complete general-task identity."""
    declared = definition(statement="Overiť zdroje živej aplikácie.\r\n")
    path = tmp_path / "task.json"
    path.write_text(json.dumps(declared.to_dict(), ensure_ascii=False), encoding="utf-8")
    actual = TaskDefinition1.from_dict(
        read_policy_document(path, budget=budget()), budget=budget()
    )
    assert actual == declared
    assert actual.statement.endswith("\r\n")
    reference = actual.reference()
    digest = reference.pop("ref_digest")
    assert digest == canonical_digest(reference)
    reference["ref_digest"] = digest
    assert reference["kind"] == "task-definition"
    assert reference["object_digest"] == declared.definition_digest
    identity = actual.identity_digest(
        actor_id="actor-a", root_id="application-code", budget=budget()
    )
    assert identity == canonical_digest(
        {
            "schema_version": "1.0",
            "object_kind": "task-identity",
            "task_id": declared.task_id,
            "task_definition": reference,
            "actor_id": "actor-a",
            "project_id": "application",
            "group_id": "engineering",
            "root_id": "application-code",
        }
    )
    assert "proof" not in actual.to_dict()
    assert "context_digest" not in actual.to_dict()
    assert "event" not in actual.to_dict()


def test_identity_changes_with_actor_root_and_exact_definition() -> None:
    """Every independent identity input affects the subject without an enclosing proof."""
    first = definition()
    identities = {
        first.identity_digest(actor_id=actor, root_id=root, budget=budget())
        for actor in first.actor_ids
        for root in first.root_ids
    }
    assert len(identities) == 4
    changed = definition(statement=first.statement + " ")
    assert changed.definition_digest != first.definition_digest
    assert (
        changed.identity_digest(actor_id="actor-a", root_id="application-code", budget=budget())
        not in identities
    )


@pytest.mark.parametrize(
    ("actor", "root"),
    [
        ("foreign-actor", "application-code"),
        ("actor-a", "foreign-root"),
        ("bad actor", "application-code"),
    ],
)
def test_identity_refuses_outside_or_malformed_declared_membership(actor: str, root: str) -> None:
    """A valid self-digest does not expand the task's declared identity domain."""
    with pytest.raises(ValueError):
        definition().identity_digest(actor_id=actor, root_id=root, budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("actor_ids", []),
        ("root_ids", []),
        ("actor_ids", ["actor-b", "actor-a"]),
        ("root_ids", ["a", "a"]),
        ("actor_ids", ["bad actor"]),
        ("root_ids", ["bad root"]),
        ("actor_ids", None),
        ("root_ids", "application"),
        ("task_id", "bad id"),
        ("project_id", "bad id"),
        ("group_id", "bad id"),
        ("lifecycle", "bad id"),
        ("statement", ""),
        ("statement", " "),
        ("revision", ""),
        ("revision", 1),
    ],
)
def test_invalid_declared_fields_refuse_even_with_recomputed_digest(
    field: str,
    invalid: object,
) -> None:
    """All identities, explicit text and array order remain closed after rehashing."""
    data = definition().to_dict()
    data.pop("definition_digest")
    data[field] = invalid
    with pytest.raises(ValueError):
        TaskDefinition1.from_dict(
            {**data, "definition_digest": canonical_digest(data)}, budget=budget()
        )


@pytest.mark.parametrize("field", ["schema_version", "object_kind"])
def test_wrong_kind_or_version_refuses_before_identity(field: str) -> None:
    """General task data never falls back to a different or older record parser."""
    data = definition().to_dict()
    data[field] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        TaskDefinition1.from_dict(data, budget=budget())


def test_closed_fields_and_direct_forgery_refuse() -> None:
    """Extra, missing and altered fields cannot cross a later consumer boundary."""
    actual = definition()
    data = actual.to_dict()
    for invalid in [
        None,
        {**data, "owner": "caller"},
        {k: v for k, v in data.items() if k != "revision"},
    ]:
        with pytest.raises(ValueError):
            TaskDefinition1.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="digest"):
        replace(actual, definition_digest="0" * 64)
    with pytest.raises(ValueError, match="tuples"):
        replace(actual, actor_ids=cast(tuple[str, ...], ["actor-a"]))
    object.__setattr__(actual, "definition_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        actual.to_dict()
    with pytest.raises(ValueError, match="digest"):
        actual.reference()


def test_explicit_reference_budget_and_fixed_ceiling_refuse() -> None:
    """The record cannot use a self-digest to exceed explicit or hard reference bounds."""
    data = definition().to_dict()
    assert TaskDefinition1.from_dict(data, budget=budget(max_references=6))
    with pytest.raises(ValueError, match="reference budget"):
        TaskDefinition1.from_dict(data, budget=budget(max_references=5))
    with pytest.raises(ValueError, match="reference budget"):
        TaskDefinition1.build(
            task_id="task",
            revision="1",
            actor_ids=("actor",),
            project_id="project",
            group_id="group",
            root_ids=("root",),
            statement="Declared task.",
            lifecycle="active",
            budget=budget(max_references=3),
        )
    with pytest.raises(ValueError, match="implementation reference ceiling"):
        replace(
            definition(),
            actor_ids=tuple(f"actor-{i:05d}" for i in range(65534)),
            root_ids=("root",),
        )
    with pytest.raises(ValueError, match="bounded tuples"):
        replace(definition(), actor_ids=tuple("actor" for _ in range(65537)))


def test_invalid_budget_refuses_both_parser_and_builder() -> None:
    """A raw mapping cannot appoint a parser budget in Python calls."""
    invalid = cast(PolicyReadBudget1, {})
    with pytest.raises(ValueError, match="budget is required"):
        TaskDefinition1.from_dict(definition().to_dict(), budget=invalid)
    with pytest.raises(ValueError, match="budget is required"):
        TaskDefinition1.build(
            task_id="task",
            revision="1",
            actor_ids=("actor",),
            project_id="project",
            group_id="group",
            root_ids=("root",),
            statement="Declared task.",
            lifecycle="active",
            budget=invalid,
        )
