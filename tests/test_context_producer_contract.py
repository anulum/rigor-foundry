# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — context producer contract tests
"""Exercise fixed owner domains without treating metadata as an installed producer."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_producer_contract import (
    ContextOwnerClass,
    ContextProducerContract1,
    ContextRootBinding,
    SourceFormat,
)
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document


def budget(**changes: int) -> PolicyReadBudget1:
    """Supply explicit ceilings for one descriptive owner contract."""
    limits = {
        "max_document_bytes": 65536,
        "max_source_bytes": 65536,
        "max_total_source_bytes": 131072,
        "max_sources": 2,
        "max_rules": 8,
        "max_references": 64,
        "max_depth": 8,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def root(*, identity: str = "code", path: str = "projects/application/src") -> ContextRootBinding:
    """Declare an inline root mapping that still requires actual registry verification."""
    return ContextRootBinding(identity, "application", "engineering", path, "a" * 64)


def contract(
    owner_class: ContextOwnerClass = "task",
    *,
    bindings: tuple[ContextRootBinding, ...] | None = None,
    limits: PolicyReadBudget1 | None = None,
) -> ContextProducerContract1:
    """Construct each supported descriptive domain without installing any code."""
    registry: SourceFormat = ("project-registry", "gotm-project-registry.v1")
    task: SourceFormat = ("task-definition", "1.0")
    inventory: SourceFormat = ("repository-state", "1.0")
    domains: dict[str, tuple[str, tuple[SourceFormat, ...], tuple[str, ...], tuple[str, ...]]] = {
        "task": (
            "builtin.task-definition.v1",
            (registry, task),
            ("task-identity",),
            ("task.actor", "task.id"),
        ),
        "registry": (
            "builtin.project-registry.v1",
            (registry,),
            ("registry-generation",),
            ("project.id",),
        ),
        "inventory": (
            "builtin.maintained-inventory.v1",
            (registry, inventory),
            ("baseline-inventory", "repository-state"),
            ("inventory.languages",),
        ),
        "fact": (
            "builtin.context-facts.v1",
            (registry, inventory, task),
            ("registry-generation", "repository-state", "task-identity"),
            ("task.id",),
        ),
    }
    implementation, formats, subjects, facts = domains[owner_class]
    return ContextProducerContract1.build(
        contract_id="contract",
        owner_id="fixed-owner",
        owner_class=owner_class,
        implementation_id=implementation,
        implementation_digest="b" * 64,
        source_formats=formats,
        subject_kinds=subjects,
        fact_references=facts,
        root_bindings=(root(),) if bindings is None else bindings,
        budget=budget() if limits is None else limits,
    )


@pytest.mark.parametrize("owner_class", ["task", "registry", "inventory", "fact"])
def test_fixed_contract_round_trip_through_real_bounded_json(
    tmp_path: Path,
    owner_class: ContextOwnerClass,
) -> None:
    """Actual documents retain distinct fixed domains and parent-covered inline data."""
    declared = contract(owner_class)
    path = tmp_path / "owner.json"
    path.write_text(json.dumps(declared.to_dict()), encoding="utf-8")
    actual = ContextProducerContract1.from_dict(
        read_policy_document(path, budget=budget()),
        budget=budget(),
    )
    assert actual == declared
    assert "schema_version" not in actual.root_bindings[0].to_dict()
    formats = cast(list[dict[str, object]], actual.to_dict()["source_formats"])
    assert set(formats[0]) == {"kind", "format_version"}
    reference = actual.reference()
    assert reference.pop("ref_digest") == canonical_digest(reference)
    assert reference["kind"] == "context-producer-contract"
    assert reference["object_digest"] == actual.contract_digest
    assert "installed" not in actual.to_dict()
    assert "guard_admissible" not in actual.to_dict()


@pytest.mark.parametrize(
    "path",
    [
        ".",
        "projects/.GIT/config",
        "..",
        "/absolute",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        "a\\b",
        "a\0b",
        "C:root",
        "a/.git",
    ],
)
def test_inline_root_refuses_noncanonical_paths(path: str) -> None:
    """An inline lexical path cannot acquire traversal or alias interpretation."""
    with pytest.raises(ValueError):
        root(path=path)


def test_inline_root_exact_fields_and_direct_mutation() -> None:
    """Inline values have no standalone header and revalidate before serialization."""
    declared = root()
    data = declared.to_dict()
    assert ContextRootBinding.from_dict(data) == declared
    with pytest.raises(ValueError):
        ContextRootBinding.from_dict({**data, "schema_version": "1.0"})
    object.__setattr__(declared, "canonical_path", "../outside")
    with pytest.raises(ValueError):
        declared.to_dict()


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("implementation_id", "caller.module.callback"),
        ("owner_class", "inventory"),
        ("source_formats", [{"kind": "unknown", "format_version": "1.0"}]),
        ("source_formats", [{"kind": "task-definition", "format_version": "2.0"}]),
        (
            "source_formats",
            [{"kind": "task-definition", "format_version": "1.0", "loader": "caller"}],
        ),
        (
            "source_formats",
            [{"kind": "project-registry", "format_version": "gotm-project-registry.v1"}],
        ),
        ("source_formats", [{"kind": "task-definition", "format_version": "1.0"}]),
        ("source_formats", []),
        ("source_formats", None),
        ("subject_kinds", ["foreign-subject"]),
        ("subject_kinds", []),
        ("subject_kinds", None),
        ("fact_references", ["registry.generation"]),
        ("fact_references", ["bad..reference"]),
        ("fact_references", ["task.id", "task.actor"]),
        ("fact_references", ["task.id", "task.id"]),
        ("fact_references", None),
        ("root_bindings", []),
        ("root_bindings", None),
    ],
)
def test_rehashed_wrong_domains_and_extensions_refuse(field: str, invalid: object) -> None:
    """A supplied descriptor cannot add an implementation, source or observation domain."""
    data = contract().to_dict()
    data.pop("contract_digest")
    data[field] = invalid
    with pytest.raises(ValueError):
        ContextProducerContract1.from_dict(
            {**data, "contract_digest": canonical_digest(data)},
            budget=budget(),
        )


def test_source_format_order_and_owner_dependencies_refuse() -> None:
    """Every fixed owner keeps its actual source prerequisites and deterministic pair order."""
    data = contract().to_dict()
    data["source_formats"] = list(reversed(cast(list[object], data["source_formats"])))
    with pytest.raises(ValueError, match="sorted"):
        ContextProducerContract1.from_dict(data, budget=budget())
    owners: tuple[ContextOwnerClass, ...] = ("inventory", "fact")
    for owner in owners:
        original = contract(owner)
        data = original.to_dict()
        data["source_formats"] = [
            item
            for item in cast(list[dict[str, object]], data["source_formats"])
            if item["kind"] != "repository-state"
        ]
        with pytest.raises(ValueError, match="repository state"):
            ContextProducerContract1.from_dict(data, budget=budget())
    data = contract("fact").to_dict()
    data["fact_references"] = []
    with pytest.raises(ValueError, match="fixed owner domain"):
        ContextProducerContract1.from_dict(data, budget=budget())


def test_identity_only_task_contract_and_profiled_registry_are_explicit() -> None:
    """Empty task observation enrollment grants no fabricated missing fields."""
    declared = contract()
    body = declared.to_dict()
    body.pop("contract_digest")
    body["fact_references"] = []
    body["source_formats"] = [
        {"kind": "project-registry", "format_version": "project-registry.v2"},
        {"kind": "task-definition", "format_version": "1.0"},
    ]
    actual = ContextProducerContract1.from_dict(
        {**body, "contract_digest": canonical_digest(body)},
        budget=budget(),
    )
    assert actual.fact_references == ()


def test_duplicate_reordered_or_alias_root_domains_refuse() -> None:
    """Root identity order and exact path uniqueness cannot be rewritten by a self-digest."""
    declared = contract()
    for roots in [
        (root(), root()),
        (root(identity="z"), root(identity="a", path="projects/application/tests")),
        (root(identity="a"), root(identity="b")),
    ]:
        with pytest.raises(ValueError, match="ordered and unique"):
            replace(declared, root_bindings=roots)
    with pytest.raises(ValueError, match="immutable"):
        replace(declared, subject_kinds=cast(tuple[str, ...], []))
    with pytest.raises(ValueError, match="supported, sorted"):
        replace(declared, source_formats=(cast(SourceFormat, ("task-definition",)),))
    with pytest.raises(ValueError, match="ordered and unique"):
        replace(declared, root_bindings=(cast(ContextRootBinding, {}),))


def test_reference_budget_applies_before_construction_and_parser_conversion() -> None:
    """Explicit relation bounds apply independently of a valid descriptive digest."""
    declared = contract()
    assert ContextProducerContract1.from_dict(declared.to_dict(), budget=budget(max_references=8))
    with pytest.raises(ValueError, match="reference budget"):
        ContextProducerContract1.from_dict(declared.to_dict(), budget=budget(max_references=7))
    with pytest.raises(ValueError, match="reference budget"):
        ContextProducerContract1.build(
            contract_id="contract",
            owner_id="owner",
            owner_class="task",
            implementation_id=declared.implementation_id,
            implementation_digest="b" * 64,
            source_formats=declared.source_formats,
            subject_kinds=declared.subject_kinds,
            fact_references=declared.fact_references,
            root_bindings=declared.root_bindings,
            budget=budget(max_references=7),
        )
    with pytest.raises(ValueError, match="implementation reference ceiling"):
        replace(declared, fact_references=("task.id",) * 65536)


@pytest.mark.parametrize("field", ["schema_version", "object_kind"])
def test_wrong_header_refuses_before_domain_selection(field: str) -> None:
    """No fallback interprets another version or object kind."""
    data = contract().to_dict()
    data[field] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        ContextProducerContract1.from_dict(data, budget=budget())


def test_closed_contract_and_forged_records_refuse() -> None:
    """Missing/extra values and directly altered digests cannot become producer proof."""
    declared = contract()
    data = declared.to_dict()
    for invalid in [
        None,
        {**data, "installed": True},
        {k: v for k, v in data.items() if k != "owner_id"},
    ]:
        with pytest.raises(ValueError):
            ContextProducerContract1.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="digest"):
        replace(declared, contract_digest="0" * 64)
    object.__setattr__(declared, "contract_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        declared.to_dict()
    with pytest.raises(ValueError, match="digest"):
        declared.reference()


def test_invalid_budget_and_builder_runtime_types_refuse() -> None:
    """Runtime input cannot appoint a budget or substitute an arbitrary root object."""
    declared = contract()
    with pytest.raises(ValueError, match="budget is required"):
        ContextProducerContract1.from_dict(declared.to_dict(), budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="budget is required"):
        contract(limits=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="immutable"):
        contract(bindings=cast(tuple[ContextRootBinding, ...], []))
    with pytest.raises(ValueError, match="root binding record"):
        contract(bindings=(cast(ContextRootBinding, {}),))
