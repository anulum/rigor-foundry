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
from pathlib import Path
from typing import cast

import pytest
from test_component_source_resolution import target_records
from test_context_producer_contract import contract
from test_inventory_baseline import baseline
from test_inventory_domain import domain
from test_policy_source_records import records
from test_project_registry_models import profiled_registry, registry
from test_repository_state import state
from test_rule_corpus_acceptance import signed_corpus_acceptance
from test_rule_corpus_native import corpus_budget, corpus_native_selection
from test_rule_source_document import source_document
from test_task_definition import budget, definition
from test_typed_object_reference import reference
from test_work_context_sources import sources as work_sources

from rigor_foundry.component_source_resolution import (
    SUPPORTED_POLICY_TARGET_FORMATS,
    parse_policy_component_target,
)
from rigor_foundry.context_source_resolution import (
    SUPPORTED_CONTEXT_TARGET_FORMATS,
    ContextSourceTarget,
    parse_context_source_target,
)
from rigor_foundry.inventory_domain import InventoryDomain1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.project_registry_primitives import project_registry_canonical_json
from rigor_foundry.rule_corpus_acceptance import RuleCorpusAcceptance1
from rigor_foundry.rule_corpus_ratification import RuleCorpusRatification1
from rigor_foundry.task_definition import TaskDefinition1
from rigor_foundry.typed_object_reference import SUPPORTED_CONTEXT_SOURCE_FORMATS, TypedObjectRef1
from rigor_foundry.work_closure import WorkClosure
from rigor_foundry.work_context_sources import (
    WorkRecordSource1,
    work_context_source_reference,
)
from rigor_foundry.work_models import WorkRecord, WorkTask


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
    values.extend(
        (
            work_context_source_reference(item, budget=budget(max_references=2048)),
            WorkRecordSource1(item, budget(max_references=2048))
            if isinstance(item, WorkRecord)
            else item,
        )
        for item in work_sources()
    )
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


def test_every_source_uses_its_actual_owning_parser(tmp_path: Path) -> None:
    """Original registry bytes/digests survive parsing without a replacement hash."""
    selected = (
        *sources(),
        *((TypedObjectRef1.from_dict(item.reference()), item) for item in records(tmp_path)),
    )
    assert (
        frozenset((ref.kind, ref.format_version) for ref, _ in selected)
        == SUPPORTED_CONTEXT_TARGET_FORMATS
    )
    for ref, target in selected:
        data = target.to_dict()
        parsed = parse_context_source_target(
            ref, data, budget=budget(max_references=2048, max_sources=3)
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
        elif isinstance(parsed, (WorkTask, WorkClosure)):
            assert work_context_source_reference(parsed, budget=budget(max_references=2048)) == ref
        else:
            assert parsed.reference() == ref.to_dict()


def test_reference_inventory_preserves_each_actual_parser_domain(tmp_path: Path) -> None:
    """All declared formats have real owners; component/corpus identities cannot select context."""
    limits = corpus_budget()
    components = target_records()
    component_pairs = frozenset((ref.kind, ref.format_version) for ref, _, _ in components)
    assert component_pairs == SUPPORTED_POLICY_TARGET_FORMATS
    noncontext: list[TypedObjectRef1] = []
    for ref, wire, target in components:
        parsed = parse_policy_component_target(ref, wire, budget=limits)
        assert type(parsed) is type(target) and parsed == target
        noncontext.append(ref)

    document = source_document()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        ratification = selected.ratification
        acceptance = signed_corpus_acceptance(document, ratification, budget=limits)
        assert (
            RuleCorpusRatification1.from_dict(ratification.to_dict(budget=limits), budget=limits)
            == ratification
        )
        assert (
            RuleCorpusAcceptance1.from_dict(acceptance.to_dict(budget=limits), budget=limits)
            == acceptance
        )
        corpus_refs = (
            ratification.reference(budget=limits),
            acceptance.reference(budget=limits),
        )
        corpus_pairs = frozenset((ref.kind, ref.format_version) for ref in corpus_refs)
        assert corpus_pairs == frozenset(
            {("rule-corpus-ratification", "1.0"), ("rule-corpus-acceptance", "1.0")}
        )
        noncontext.extend(corpus_refs)

    assert len(SUPPORTED_CONTEXT_TARGET_FORMATS) == 13 and len(component_pairs) == 14
    assert not SUPPORTED_CONTEXT_TARGET_FORMATS.intersection(component_pairs | corpus_pairs)
    assert not component_pairs.intersection(corpus_pairs)
    assert (
        SUPPORTED_CONTEXT_TARGET_FORMATS | component_pairs | corpus_pairs
        == SUPPORTED_CONTEXT_SOURCE_FORMATS
    )
    for ref in noncontext:
        assert TypedObjectRef1.from_dict(ref.to_dict()) == ref
        with pytest.raises(ValueError, match="unsupported context target"):
            parse_context_source_target(ref, None, budget=limits)


@pytest.mark.parametrize(
    "change", ["identity", "digest", "version", "mixed-kind", "child-digest", "child-extra"]
)
def test_target_mismatch_or_forgery_refuses(change: str) -> None:
    """Matching-looking parent references never skip the actual owning child parser."""
    ref, target = sources()[0]
    assert isinstance(target, TaskDefinition1)
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
    assert isinstance(target, ProjectRegistry)
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
