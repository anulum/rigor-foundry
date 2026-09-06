# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — model-bound activation publication tests
"""Exercise activation models through the actual protected publication adapter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import cast

import pytest
from test_project_memory_activation_plan import Proposal
from test_project_memory_activation_plan import profiled_proposal as model_profiled_proposal
from test_project_memory_activation_plan import proposal as model_proposal

from rigor_foundry.project_memory_activation_publication import (
    ActivationPublicationLayout,
    ActivationRootBinding,
    PreparedProjectMemoryActivationPublication,
    prepare_project_memory_activation_publication,
)
from rigor_foundry.project_memory_models import ProjectMemoryManifest

SOURCE_CONTENT = b"Captured project identity source.\n"


def source_fixture(p: Proposal) -> Proposal:
    """Bind fixture metadata to genuine source bytes rather than placeholder hashes."""
    manifest = p.memory
    p.memory = ProjectMemoryManifest.build(
        project_id=manifest.project_id,
        generated_at=manifest.generated_at,
        previous_manifest_sha256=manifest.previous_manifest_sha256,
        parents=manifest.parents,
        profile=manifest.profile,
        group_id=manifest.group_id,
        records=tuple(
            replace(
                record,
                sources=tuple(
                    replace(source, sha256=hashlib.sha256(SOURCE_CONTENT).hexdigest())
                    for source in record.sources
                ),
            )
            for record in manifest.records
        ),
    )
    return p


def proposal() -> Proposal:
    """Build a v1 fixture with complete source content."""
    return source_fixture(model_proposal())


def profiled_proposal() -> Proposal:
    """Build a v2 fixture with complete source content."""
    return source_fixture(model_profiled_proposal())


def layout_for(p: Proposal) -> ActivationPublicationLayout:
    """Declare a generic test deployment; not production enrollment."""
    selected = next(
        project
        for project in p.cutover.candidate.projects
        if project.project_id == p.memory.project_id
    )
    memory = selected.canonical_path + "/agentic_project_memory"
    parents = {
        memory,
        memory + "/history/manifests",
        "state",
        "state/activation",
        "state/activation/run",
        "state/activation/run/prior",
    }
    parents.update(
        memory + "/" + record.content_path.rpartition("/")[0] for record in p.memory.records
    )
    parents.update(consumer.path.rpartition("/")[0] for consumer in p.cutover.candidate.consumers)
    return ActivationPublicationLayout(
        (ActivationRootBinding("deployment", "."),),
        "state/registry.json",
        "state/activation/run",
        dict.fromkeys(parents, "0700"),
        ("state/activation/run", "state/activation/run/prior"),
        ("state/activation/.lock",),
        {"state/activation/.lock": b"stable lock\n"},
    )


def prepare(
    p: Proposal,
    layout: ActivationPublicationLayout,
    *,
    operations: int = 1000,
    version: str = "v1",
) -> PreparedProjectMemoryActivationPublication:
    """Use only public activation preparation with complete prior bytes."""
    return prepare_project_memory_activation_publication(
        p.previous.to_bytes(),
        {output.consumer_id: output.to_bytes() for output in p.prior_outputs},
        p.cutover,
        p.memory,
        bootstrap_manifest=p.bootstrap,
        bootstrap_index=p.index,
        record_contents={p.memory.records[0].content_path: b"# Project identity\n"},
        source_contents={
            (source.source_id, source.locator, source.sha256): SOURCE_CONTENT
            for record in p.memory.records
            for source in record.sources
        },
        max_source_bytes=1024 * 1024,
        layout=layout,
        claim_task_id="activation-claim",
        content_domain="raw-bytes",
        max_operations=operations,
        max_content_bytes=1024 * 1024,
        schema_version=f"project-memory-activation-plan-binding.{version}",
    )


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_complete_model_to_protected_operation_connection(version: str) -> None:
    """Compile model content into ordered snapshot/lock effects without asserting execution."""
    p = proposal() if version == "v1" else profiled_proposal()
    layout = layout_for(p)
    prepared = prepare(p, layout, version=version)
    assert prepared.target_project == p.memory.project_id
    assert all(payload == SOURCE_CONTENT for _, payload in prepared.sources)
    assert prepared.content.plan_binding_sha256 == p.check(
        f"project-memory-activation-plan-binding.{version}"
    )
    memory_root = (
        next(
            project.canonical_path
            for project in p.cutover.candidate.projects
            if project.project_id == p.memory.project_id
        )
        + "/agentic_project_memory"
    )
    destinations = {(role, identity): path for role, identity, path in prepared.destinations}
    assert (
        destinations[("memory-manifest", "memory_manifest.json")]
        == memory_root + "/memory_manifest.json"
    )
    assert (
        destinations[("record", p.memory.records[0].content_path)]
        == memory_root + "/" + p.memory.records[0].content_path
    )
    for consumer in p.cutover.candidate.consumers:
        assert destinations[("consumer", consumer.consumer_id)] == consumer.path
    assert prepared.destinations[-1] == ("registry", "registry", layout.registry_path)
    body = json.loads(prepared.publication.operation_fields)
    auxiliary = body["auxiliary_operations"]
    assert [o["opcode"] for o in auxiliary[:5]] == ["mkdir", "fsync", "mkdir", "fsync", "lock"]
    assert auxiliary[-1]["opcode"] == "unlock"
    assert auxiliary[-3]["opcode"] == "rename"
    assert auxiliary[-3]["paths"][1]["relative_path"] == layout.registry_path
    originals = [o for o in prepared.content.objects if o.previous is not None]
    copied = auxiliary[5 : 5 + 3 * len(originals)]
    assert [o["opcode"] for o in copied] == ["create", "fsync", "fsync"] * len(originals)
    raw = dict(prepared.publication.contents)
    assert raw[hashlib.sha256(p.bootstrap).hexdigest()] == p.bootstrap
    assert raw[hashlib.sha256(p.index).hexdigest()] == p.index
    assert raw[hashlib.sha256(p.previous.to_bytes()).hexdigest()] == p.previous.to_bytes()
    for operation in auxiliary:
        if operation["opcode"] == "rename":
            assert (
                f".activation-{prepared.content.plan_binding_sha256}-"
                in operation["paths"][0]["relative_path"]
            )
    assert prepare(p, layout, version=version) == prepared


def test_longest_root_binding_keeps_parent_explicit_and_input_maps_detached() -> None:
    """Resolve nested roots explicitly and detach compilation from caller-owned maps."""
    p = proposal()
    layout = layout_for(p)
    project = next(
        project for project in p.previous.projects if project.project_id == p.memory.project_id
    )
    memory_root = project.canonical_path + "/agentic_project_memory"
    layout = replace(layout, roots=(*layout.roots, ActivationRootBinding("memory", memory_root)))
    result = prepare(p, layout)
    body = json.loads(result.publication.operation_fields)
    manifest = next(o for o in body["operations"] if o["relative_path"] == "memory_manifest.json")
    assert manifest["root_id"] == "memory"
    assert any(
        o["opcode"] == "fsync"
        and o["paths"][0]["root_id"] == "deployment"
        and o["paths"][0]["relative_path"] == memory_root
        for o in body["auxiliary_operations"]
    )
    cast(dict[str, str], layout.parent_modes).clear()
    cast(dict[str, bytes | None], layout.lock_contents).clear()
    assert (
        result.publication.operation_fields
        == json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    )


@pytest.mark.parametrize("budget", [False, 0, -1, 1.5, 2**53])
def test_invalid_operation_budget(budget: object) -> None:
    """Reject boolean, fractional and out-of-range operation capacities."""
    p = proposal()
    with pytest.raises(ValueError, match="positive exact"):
        prepare(p, layout_for(p), operations=cast(int, budget))


def test_layout_type_and_tuple_bounds() -> None:
    """Reject foreign layout objects and mutable or oversized root declarations."""
    p = proposal()
    with pytest.raises(ValueError, match="exact publication layout"):
        prepare(p, cast(ActivationPublicationLayout, object()))
    layout = layout_for(p)
    with pytest.raises(ValueError, match="layout tuple"):
        prepare(
            p, replace(layout, roots=cast(tuple[ActivationRootBinding, ...], list(layout.roots)))
        )
    with pytest.raises(ValueError, match="layout tuple"):
        prepare(p, replace(layout, roots=layout.roots * 3), operations=2)


@pytest.mark.parametrize("side", ["roots", "locks"])
def test_missing_root_or_lock_policy(side: str) -> None:
    """Refuse compilation without separately declared roots and acquisition policy."""
    p = proposal()
    layout = layout_for(p)
    layout = replace(layout, roots=()) if side == "roots" else replace(layout, lock_paths=())
    with pytest.raises(ValueError, match="explicit roots and lock policy"):
        prepare(p, layout)


@pytest.mark.parametrize("side", ["parents", "locks"])
def test_layout_mapping_bounds(side: str) -> None:
    """Bound parent and lock mapping counts independently of their content."""
    p = proposal()
    layout = layout_for(p)
    if side == "parents":
        layout = replace(layout, parent_modes={str(i): "0700" for i in range(101)})
    else:
        layout = replace(layout, lock_contents={str(i): None for i in range(101)})
    with pytest.raises(ValueError, match="layout mapping"):
        prepare(p, layout, operations=100)


@pytest.mark.parametrize(
    "roots",
    [
        (cast(ActivationRootBinding, object()),),
        (ActivationRootBinding("same", "."), ActivationRootBinding("same", "state")),
        (ActivationRootBinding("one", "."), ActivationRootBinding("two", ".")),
    ],
)
def test_malformed_or_ambiguous_roots(roots: tuple[ActivationRootBinding, ...]) -> None:
    """Reject non-binding objects and root identifier/location ambiguity."""
    p = proposal()
    with pytest.raises(ValueError, match="root"):
        prepare(p, replace(layout_for(p), roots=roots))


@pytest.mark.parametrize("path", ["", "/absolute", "a/../b", "a/.git/b", "a/*", "a" * 4097])
def test_invalid_layout_paths(path: str) -> None:
    """Reject deployment paths that escape portable relative-path syntax."""
    p = proposal()
    with pytest.raises(ValueError, match="portable"):
        prepare(p, replace(layout_for(p), transaction_path=path))


def test_lock_observations_are_exact_and_unique() -> None:
    """Require one exact observation for each uniquely named acquisition target."""
    p = proposal()
    layout = layout_for(p)
    for wrong in (
        replace(layout, lock_contents={}),
        replace(layout, lock_paths=layout.lock_paths * 2),
    ):
        with pytest.raises(ValueError, match="unique lock observations"):
            prepare(p, wrong)


def test_transaction_storage_cannot_overlap_memory_or_business_targets() -> None:
    """Keep preservation storage disjoint from project memory and business destinations."""
    p = proposal()
    layout = layout_for(p)
    project = next(
        project for project in p.previous.projects if project.project_id == p.memory.project_id
    )
    with pytest.raises(ValueError, match="overlaps project memory"):
        prepare(
            p, replace(layout, transaction_path=project.canonical_path + "/agentic_project_memory")
        )
    # Preserve other parent coverage so rejection reaches the business registry target.
    wrong = replace(layout, transaction_path="state")
    modes = dict(wrong.parent_modes)
    modes["state/prior"] = "0700"
    with pytest.raises(ValueError, match="overlaps a business target"):
        prepare(p, replace(wrong, parent_modes=modes))


def test_missing_and_extra_parent_modes_are_refused() -> None:
    """Require immediate-parent metadata without accepting unrelated declarations."""
    p = proposal()
    layout = layout_for(p)
    with pytest.raises(ValueError, match="exact parent mode"):
        prepare(p, replace(layout, parent_modes={}))
    with pytest.raises(ValueError, match="unrelated paths"):
        prepare(p, replace(layout, parent_modes={**layout.parent_modes, "foreign": "0700"}))


def test_unmapped_path_has_no_fallback_root() -> None:
    """Reject destinations outside declared roots instead of inventing a fallback."""
    p = proposal()
    layout = replace(layout_for(p), roots=(ActivationRootBinding("state", "state"),))
    with pytest.raises(ValueError, match="exact enrolled ancestor"):
        prepare(p, layout)


def test_top_level_parent_cannot_be_faked_as_a_dot_operation() -> None:
    """Refuse top-level parent references unsupported by the Core relative-path contract."""
    p = proposal()
    layout = layout_for(p)
    with pytest.raises(ValueError, match="exact enrolled ancestor"):
        prepare(
            p,
            replace(
                layout,
                registry_path="registry.json",
                parent_modes={**layout.parent_modes, "": "0700"},
            ),
        )


def test_original_model_binding_is_not_bypassed() -> None:
    """Preserve bootstrap identity validation when expanding publication effects."""
    p = proposal()
    p.bootstrap = p.bootstrap.replace(b"PROJECT-A", b"foreign")
    with pytest.raises(ValueError, match="selected empty scaffold"):
        prepare(p, layout_for(p))


def test_model_adapter_cannot_skip_source_content_verification() -> None:
    """Reject mismatching captured source bytes before generating activation effects."""
    p = proposal()
    source = p.memory.records[0].sources[0]
    with pytest.raises(ValueError, match="source content digest mismatch"):
        prepare_project_memory_activation_publication(
            p.previous.to_bytes(),
            {o.consumer_id: o.to_bytes() for o in p.prior_outputs},
            p.cutover,
            p.memory,
            bootstrap_manifest=p.bootstrap,
            bootstrap_index=p.index,
            record_contents={p.memory.records[0].content_path: b"# Project identity\n"},
            source_contents={(source.source_id, source.locator, source.sha256): b"unrelated"},
            max_source_bytes=100,
            layout=layout_for(p),
            claim_task_id="activation-claim",
            content_domain="raw-bytes",
            max_operations=1000,
            max_content_bytes=1024 * 1024,
        )
