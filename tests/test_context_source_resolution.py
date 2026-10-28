# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual context source parser tests
"""Resolve real source documents through their fixed owning public parsers."""

from __future__ import annotations

import hashlib
from typing import cast

import pytest
from test_context_producer_contract import contract
from test_inventory_baseline import baseline
from test_inventory_domain import domain
from test_project_registry_models import profiled_registry, registry
from test_repository_state import state
from test_task_definition import budget, definition
from test_typed_object_reference import reference

from rigor_foundry.context_source_resolution import (
    ContextSourceTarget,
    parse_context_source_target,
)
from rigor_foundry.inventory_domain import InventoryDomain1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.project_registry_primitives import project_registry_canonical_json
from rigor_foundry.typed_object_reference import SUPPORTED_CONTEXT_SOURCE_FORMATS, TypedObjectRef1


def sources() -> tuple[tuple[TypedObjectRef1, ContextSourceTarget], ...]:
    """Return every actual owning target class and both original registry formats."""
    task, producer, repository = definition(), contract(), state()
    unclassified_domain = InventoryDomain1.build(
        domain_id="context-source-domain",
        project_id="PROJECT-A",
        roots=domain().roots,
        rules=(),
        budget=budget(),
    )
    values: list[tuple[TypedObjectRef1, ContextSourceTarget]] = [
        (TypedObjectRef1.from_dict(item.reference()), item)
        for item in (task, producer, repository, unclassified_domain, baseline())
    ]
    for registered in (registry(), profiled_registry()):
        version = cast(str, registered.to_dict()["schema_version"])
        values.append(
            (
                reference(
                    "project-registry",
                    version,
                    registered.generation_id,
                    registered.registry_sha256,
                ),
                registered,
            )
        )
    return tuple(values)


def test_every_source_uses_its_actual_owning_parser() -> None:
    """Original registry bytes/digests survive parsing without a replacement hash."""
    selected = sources()
    assert (
        frozenset((ref.kind, ref.format_version) for ref, _ in selected)
        == SUPPORTED_CONTEXT_SOURCE_FORMATS
    )
    for ref, target in selected:
        parsed = parse_context_source_target(
            ref, target.to_dict(), budget=budget(max_references=64)
        )
        assert type(parsed) is type(target) and parsed == target
        if isinstance(parsed, ProjectRegistry):
            assert isinstance(target, ProjectRegistry)
            assert parsed.to_bytes() == target.to_bytes()
            body = parsed.to_dict()
            body.pop("registry_sha256")
            assert (
                ref.object_digest
                == hashlib.sha256(project_registry_canonical_json(body)).hexdigest()
            )
        else:
            assert parsed.reference() == ref.to_dict()


@pytest.mark.parametrize(
    "change", ["identity", "digest", "version", "mixed-kind", "child-digest", "child-extra"]
)
def test_target_mismatch_or_forgery_refuses(change: str) -> None:
    """Matching-looking parent references never skip the actual owning child parser."""
    ref, target = sources()[0]
    data = target.to_dict()
    if change == "identity":
        ref = reference(identity="foreign")
    elif change == "digest":
        ref = reference(identity=ref.object_id, digest="b" * 64)
    elif change == "version":
        data["schema_version"] = "2.0"
    elif change == "mixed-kind":
        data = contract().to_dict()
    elif change == "child-digest":
        data["definition_digest"] = "b" * 64
    else:
        data["callback"] = "caller"
    with pytest.raises(ValueError):
        parse_context_source_target(ref, data, budget=budget(max_references=64))


def test_invalid_direct_reference_refuses_before_target_lookup() -> None:
    """Unsupported and non-record references cannot choose a fallback parser."""
    ref = reference()
    object.__setattr__(ref, "kind", "unknown")
    for invalid in (ref, cast(TypedObjectRef1, {})):
        with pytest.raises(ValueError):
            parse_context_source_target(invalid, None, budget=budget())
    with pytest.raises(ValueError, match="budget is required"):
        parse_context_source_target(reference(), None, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError):
        parse_context_source_target(reference(), None, budget=budget())


def test_registry_source_reference_limits_and_array_types() -> None:
    """Original registry parsing retains its own validation behind earlier input ceilings."""
    ref, target = sources()[-1]
    data = target.to_dict()
    with pytest.raises(ValueError, match="reference budget"):
        parse_context_source_target(ref, data, budget=budget(max_references=1))
    projects = cast(list[dict[str, object]], data["projects"])
    huge_relations = {**projects[0], "affiliations": ["group"] * 20}
    with pytest.raises(ValueError, match="reference budget"):
        parse_context_source_target(
            ref, {**data, "projects": [huge_relations]}, budget=budget(max_references=12)
        )
    for field in ("groups", "projects", "consumers"):
        with pytest.raises(ValueError, match="must be arrays"):
            parse_context_source_target(
                ref, {**data, field: None}, budget=budget(max_references=64)
            )
    for relation in ("affiliations", "aliases"):
        with pytest.raises(ValueError, match="must be arrays"):
            parse_context_source_target(
                ref,
                {**data, "projects": [{**projects[0], relation: None}]},
                budget=budget(max_references=64),
            )
    with pytest.raises(ValueError):
        parse_context_source_target(
            ref, {**data, "projects": [None]}, budget=budget(max_references=64)
        )
