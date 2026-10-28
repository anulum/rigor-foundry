# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete actual source universe tests
"""Observe complete actual retained cohorts and consume their original byte partitions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_context_producer_contract import contract
from test_policy_source_selection import SelectedPolicy, selection
from test_project_registry_models import registry
from test_task_definition import definition

import rigor_foundry.source_universe_owner as owner_module
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_implementation import (
    OwnerImplementationSnapshot,
    observe_owner_implementation,
)
from rigor_foundry.context_producer_contract import ContextProducerContract1, ContextRootBinding
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_regions import SourceRegion1
from rigor_foundry.policy_source_selection import PolicySourceSelection
from rigor_foundry.policy_source_spans import SourceSpan1
from rigor_foundry.retained_policy_source import RetainedPolicySource
from rigor_foundry.source_universe import SourceReadState, SourceUniverseEntry1
from rigor_foundry.source_universe_owner import SourceUniverseOwner
from rigor_foundry.typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class UniverseSelection:
    """Actual borrowed owner inputs and original paths retained for public tests."""

    arguments: dict[str, object]
    sources: tuple[PolicySourceSelection, ...]
    actual: SelectedPolicy
    budget: PolicyReadBudget1


class OwnerArguments(TypedDict):
    """Explicit actual constructor inputs, including deliberately malformed public test cases."""

    sources: tuple[PolicySourceSelection, ...]
    registry_source: RetainedContextSource
    contract_source: RetainedContextSource
    implementation: OwnerImplementationSnapshot
    budget: PolicyReadBudget1


@contextmanager
def universe_selection(
    root: Path,
    kind: str = "capture",
    *,
    state: SourceReadState = "verified",
    fault: str = "",
    source_bytes: int = 0,
) -> Iterator[UniverseSelection]:
    """Prepare a complete real registry/contract/source cohort before observing code."""
    root.mkdir()
    budget = implementation_budget()
    with ExitStack() as stack:
        actual = stack.enter_context(
            selection(
                root / "policy",
                kind,
                state=state,
                fault="wrong-kind" if fault == "metadata-kind" else "",
                capture_payload=b"x" * source_bytes
                if source_bytes
                else b"original\r\npolicy\x00\xff",
            )
        )
        sources = [actual.source]
        if source_bytes:
            other = stack.enter_context(
                selection(root / "other-policy", capture_payload=b"y" * source_bytes)
            )
            sources = [
                replace(actual.source, source_id="policy0"),
                replace(other.source, source_id="policy1"),
            ]
        if kind == "discovery":
            for index in (1, 2):
                payload = None
                held = state != "verified" or (index == 2 and fault == "mixed-held")
                if not held:
                    path = actual.root / f"source{index}.txt"
                    raw = path.read_bytes()
                    payload = stack.enter_context(
                        RetainedPolicySource(
                            path,
                            byte_digest=hashlib.sha256(raw).hexdigest(),
                            byte_count=len(raw),
                            budget=budget,
                        )
                    )
                sources.append(
                    replace(
                        actual.source,
                        source_id=f"source{index}",
                        read_state="protected" if held else "verified",
                        payload=payload,
                        discovery=None if held else actual.source.discovery,
                    )
                )
            if fault == "omit-unused":
                sources.pop()
        code = observe_owner_implementation(Path(owner_module.__file__).parent, budget=budget)
        registered = registry()
        declared = contract("task" if fault == "wrong-domain" else "source")
        binding = ContextRootBinding(
            "code",
            "missing-project" if fault == "missing-project" else "PROJECT-A",
            "GROUP-B" if fault == "group" else "GROUP-A",
            "unrelated/src" if fault == "path" else "03_CODE/GROUP-A/repositories/PROJECT-A/src",
            "d" * 64,
        )
        body = declared.to_dict()
        body.pop("contract_digest")
        body["implementation_digest"] = (
            "f" * 64 if fault == "contract-code" else code.implementation_digest
        )
        body["root_bindings"] = [binding.to_dict()]
        if fault == "registry-format":
            formats = cast(list[dict[str, object]], body["source_formats"])
            for item in formats:
                if item["kind"] == "project-registry":
                    item["format_version"] = "project-registry.v2"
        elif fault == "source-format":
            body["source_formats"] = [
                {"kind": "project-registry", "format_version": "gotm-project-registry.v1"},
                {"kind": "source-capture", "format_version": "1.0"},
            ]
        selected_contract = ContextProducerContract1.from_dict(
            {**body, "contract_digest": canonical_digest(body)}, budget=budget
        )
        metadata_root = root / "owner-inputs"
        metadata_root.mkdir()
        registry_path, contract_path = (
            metadata_root / "registry.json",
            metadata_root / "contract.json",
        )
        registry_bytes = registered.to_bytes()
        if fault == "contract-kind":
            contract_bytes = json.dumps(definition().to_dict()).encode()
            contract_ref = TypedObjectRef1.from_dict(definition().reference())
        else:
            contract_bytes = json.dumps(selected_contract.to_dict()).encode()
            contract_ref = TypedObjectRef1.from_dict(selected_contract.reference())
        registry_path.write_bytes(registry_bytes)
        contract_path.write_bytes(contract_bytes)
        registry_ref = TypedObjectRef1.build(
            kind="project-registry",
            format_version="gotm-project-registry.v1",
            object_id=registered.generation_id,
            object_digest=registered.registry_sha256,
        )
        retained_registry, retained_contract = (
            stack.enter_context(
                RetainedContextSource(
                    path, reference=ref, raw_digest=hashlib.sha256(raw).hexdigest(), budget=budget
                )
            )
            for path, ref, raw in [
                (registry_path, registry_ref, registry_bytes),
                (contract_path, contract_ref, contract_bytes),
            ]
        )
        args: dict[str, object] = {
            "sources": tuple(sources),
            "registry_source": retained_registry,
            "contract_source": retained_contract,
            "implementation": code,
            "budget": budget,
        }
        yield UniverseSelection(args, tuple(sources), actual, budget)


def owner(selected: UniverseSelection, **changes: object) -> SourceUniverseOwner:
    """Construct the fixed owner only from actual host fixture inputs."""
    return SourceUniverseOwner(**cast(OwnerArguments, {**selected.arguments, **changes}))


def regions_for(selected: UniverseSelection) -> tuple[SourceRegion1, ...]:
    """Partition every included nonempty actual payload without claiming its meaning."""
    result = []
    for source in selected.sources:
        if source.payload is None:
            continue
        raw = source.payload.read()
        if raw:
            result.append(
                SourceRegion1.build(
                    source_id=source.source_id,
                    start_byte=0,
                    end_byte=len(raw),
                    payload=raw,
                    disposition="context",
                    rule_ids=(),
                    decision_ids=(),
                    reason_code="declared-context",
                )
            )
    return tuple(result)


@pytest.mark.parametrize("kind", ["capture", "native", "discovery"])
def test_complete_real_cohort_proofs_regions_and_spans_share_original_bytes(
    tmp_path: Path, kind: str
) -> None:
    """Original owner/source identities and complete partitions are rechecked through closure."""
    with universe_selection(tmp_path / "selected", kind) as selected:
        with owner(selected) as actual:
            entries = actual.observe()
            assert tuple(item.source_id for item in entries) == tuple(
                source.source_id for source in selected.sources
            )
            assert actual.observe() == entries
            actual.verify(entries)
            regions = regions_for(selected)
            source = selected.sources[0]
            assert source.payload is not None
            span = SourceSpan1.build(
                span_id="statement",
                source_id=source.source_id,
                start_byte=0,
                end_byte=1,
                payload=source.payload.read(),
            )
            assert actual.verify_partitions(entries, regions=regions, spans=(span,)) == regions
            assert all(item.provenance.owner_class == "source" for item in entries)
            assert all(item.provenance.subject_digest == item.byte_digest for item in entries)
            assert all(item.entry_digest != item.provenance.subject_digest for item in entries)
            if kind == "discovery":
                assert len(entries) == 3 and entries[2].byte_count == 0
        actual.close()
        with pytest.raises(ValueError, match="closed"):
            actual.observe()
        assert selected.sources[0].metadata.read() is not None


def test_complete_held_discovery_cohort_never_opens_original_files(tmp_path: Path) -> None:
    """Even missing protected source files retain all original receipt rows as held metadata."""
    with universe_selection(tmp_path / "selected", "discovery", state="protected") as selected:
        for path in selected.actual.root.iterdir():
            path.unlink()
        with owner(selected) as actual:
            entries = actual.observe()
            assert len(entries) == 3 and all(
                item.read_state == "protected" and item.byte_count is None for item in entries
            )
            assert all(
                item.provenance.subject_digest == item.existing_source.object_digest
                for item in entries
            )
            assert actual.verify_partitions(entries, regions=regions_for(selected), spans=()) == ()


@pytest.mark.parametrize(
    ("kind", "fault"),
    [
        ("capture", "contract-kind"),
        ("capture", "wrong-domain"),
        ("capture", "contract-code"),
        ("capture", "registry-format"),
        ("capture", "missing-project"),
        ("capture", "group"),
        ("capture", "path"),
        ("capture", "metadata-kind"),
        ("native", "source-format"),
        ("discovery", "omit-unused"),
        ("discovery", "mixed-held"),
    ],
)
def test_whole_original_registry_source_and_discovery_cohort_bindings_refuse(
    tmp_path: Path, kind: str, fault: str
) -> None:
    """Supported models cannot borrow the wrong producer, registry domain or incomplete receipt cohort."""
    with (
        universe_selection(tmp_path / "selected", kind, fault=fault) as selected,
        pytest.raises(ValueError),
    ):
        owner(selected)


def test_owner_requires_actual_complete_host_types_order_and_limits(tmp_path: Path) -> None:
    """No mutable cohort, duplicate source, forged code snapshot or caller reader is installed."""
    with universe_selection(tmp_path / "selected") as selected:
        mutations: tuple[dict[str, object], ...] = (
            {"sources": []},
            {"sources": ()},
            {"sources": ({},)},
            {"sources": selected.sources * 2},
            {
                "sources": (
                    replace(selected.sources[0], source_id="z"),
                    replace(selected.sources[0], source_id="a"),
                )
            },
            {"registry_source": {}},
            {"contract_source": {}},
            {"implementation": {}},
            {"budget": {}},
            {"budget": implementation_budget(max_references=3)},
            {"sources": selected.sources * 2, "budget": implementation_budget(max_sources=1)},
        )
        for changed in mutations:
            with pytest.raises(ValueError):
                owner(selected, **changed)
        original = cast(OwnerImplementationSnapshot, selected.arguments["implementation"])
        with pytest.raises(ValueError, match="implementation or lifetime changed"):
            owner(selected, implementation=replace(original, implementation_digest="f" * 64))


def test_complete_entry_verification_refuses_self_digested_foreign_metadata(
    tmp_path: Path,
) -> None:
    """Subsets, wrong concrete entries and a valid rehashed foreign locator cannot pass."""
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        entries = actual.observe()
        malformed_cohorts: tuple[object, ...] = ([], (), ({},))
        for malformed in malformed_cohorts:
            with pytest.raises(ValueError, match="complete actual entry"):
                actual.verify(cast(tuple[SourceUniverseEntry1, ...], malformed))
        data = entries[0].to_dict()
        data.pop("entry_digest")
        data["locator"] = "opaque:foreign"
        changed = SourceUniverseEntry1.from_dict(
            {**data, "entry_digest": canonical_digest(data)}, budget=selected.budget
        )
        with pytest.raises(ValueError, match="actual fixed source observations"):
            actual.verify((changed,))


def test_partitions_refuse_missing_reordered_foreign_overlapping_and_false_bytes(
    tmp_path: Path,
) -> None:
    """Each actual byte must belong to exactly one source-ordered original region."""
    with (
        universe_selection(tmp_path / "selected", "discovery") as selected,
        owner(selected) as actual,
    ):
        entries = actual.observe()
        regions = regions_for(selected)
        first = regions[0]
        assert selected.sources[0].payload is not None
        raw = selected.sources[0].payload.read()
        gap = SourceRegion1.build(
            source_id=first.source_id,
            start_byte=1,
            end_byte=len(raw),
            payload=raw,
            disposition="context",
            rule_ids=(),
            decision_ids=(),
            reason_code="gap",
        )
        foreign = SourceRegion1.build(
            source_id="foreign",
            start_byte=0,
            end_byte=1,
            payload=raw,
            disposition="context",
            rule_ids=(),
            decision_ids=(),
            reason_code="foreign",
        )
        wrong = SourceRegion1.build(
            source_id=first.source_id,
            start_byte=0,
            end_byte=len(raw),
            payload=b"x" * len(raw),
            disposition="context",
            rule_ids=(),
            decision_ids=(),
            reason_code="wrong-bytes",
        )
        mutations: tuple[object, ...] = (
            (),
            regions[:1],
            regions[::-1],
            (first, first),
            (foreign,),
            (gap,),
            (wrong,),
            ({},),
        )
        for changed in mutations:
            with pytest.raises(ValueError):
                actual.verify_partitions(
                    entries, regions=cast(tuple[SourceRegion1, ...], changed), spans=()
                )
        for changed_regions, changed_spans in (([], ()), ((), []), ((first,) * 65537, ())):
            with pytest.raises(ValueError, match="immutable reference budget"):
                actual.verify_partitions(
                    entries,
                    regions=cast(tuple[SourceRegion1, ...], changed_regions),
                    spans=cast(tuple[SourceSpan1, ...], changed_spans),
                )
        span = SourceSpan1.build(
            span_id="statement", source_id=first.source_id, start_byte=0, end_byte=1, payload=raw
        )
        foreign_span = SourceSpan1.build(
            span_id="foreign", source_id="foreign", start_byte=0, end_byte=1, payload=raw
        )
        malformed_spans: tuple[object, ...] = ((span, span), (foreign_span,), ({},))
        for spans in malformed_spans:
            with pytest.raises(ValueError):
                actual.verify_partitions(
                    entries, regions=regions, spans=cast(tuple[SourceSpan1, ...], spans)
                )


def test_complete_actual_raw_bytes_have_an_independent_total_ceiling(tmp_path: Path) -> None:
    """Two real seven-MiB sources exceed twelve MiB while package/interpreter checks fit."""
    with (
        universe_selection(tmp_path / "selected", source_bytes=7 * 1024**2) as selected,
        pytest.raises(ValueError, match="complete source universe exceeds its total byte budget"),
    ):
        owner(selected, budget=implementation_budget(max_total_source_bytes=12 * 1024**2))


def test_region_rule_and_decision_relations_consume_the_actual_owner_budget(
    tmp_path: Path,
) -> None:
    """Valid region metadata cannot add unbounded rule/decision relations to retained bytes."""
    with universe_selection(tmp_path / "selected") as selected:
        source = selected.sources[0]
        assert source.payload is not None
        raw = source.payload.read()
        for limits, rules, decisions in (
            (implementation_budget(max_rules=1), ("rule-a", "rule-b"), ()),
            (
                implementation_budget(max_references=512),
                (),
                tuple(f"decision-{index:04d}" for index in range(512)),
            ),
        ):
            with owner(selected, budget=limits) as actual:
                entries = actual.observe()
                region = SourceRegion1.build(
                    source_id=source.source_id,
                    start_byte=0,
                    end_byte=len(raw),
                    payload=raw,
                    disposition="normative" if rules else "context",
                    rule_ids=rules,
                    decision_ids=decisions,
                    reason_code="explicit-relations",
                )
                with pytest.raises(ValueError, match="region relations exceed"):
                    actual.verify_partitions(entries, regions=(region,), spans=())


def test_excluded_sources_remain_present_without_claiming_decision_acceptance(
    tmp_path: Path,
) -> None:
    """Declared exclusion preserves its source/proof and has no implicit accepted/ready flag."""
    with universe_selection(tmp_path / "selected") as selected:
        source = replace(
            selected.sources[0], disposition="excluded", disposition_decision="declared-exclusion"
        )
        with owner(selected, sources=(source,)) as actual:
            entries = actual.observe()
            assert len(entries) == 1 and entries[0].disposition_decision == "declared-exclusion"
            assert entries[0].read_state == "verified"
            assert actual.verify_partitions(entries, regions=(), spans=()) == ()


def test_actual_closing_failure_closes_owner_and_preserves_host_release_checks(
    tmp_path: Path,
) -> None:
    """A real late source edit refuses both owner closure and the host's raw lease closure."""
    with (
        pytest.raises(ValueError, match="identity changed"),
        universe_selection(tmp_path / "selected") as selected,
    ):
        actual = owner(selected)
        actual.observe()
        selected.actual.path.write_bytes(b"late original change")
        with pytest.raises(ValueError, match="identity changed"):
            actual.close()
        actual.close()
        with pytest.raises(ValueError, match="owner is closed"):
            actual.observe()
