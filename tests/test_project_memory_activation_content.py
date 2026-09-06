# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — activation content preparation tests
"""Exercise complete content binding through the public preparation boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from typing import cast

import pytest
from test_project_memory_activation_plan import Proposal, profiled_proposal, proposal

from rigor_foundry.project_memory_activation_content import (
    PreparedProjectMemoryActivationContent,
    prepare_project_memory_activation_content,
)
from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_primitives import PROJECT_MEMORY_MAX_RECORDS
from rigor_foundry.project_registry_models import PROJECT_REGISTRY_MAX_CONSUMERS


def prepare(
    p: Proposal,
    *,
    content: bytes = b"# Project identity\n",
    limit: int = 1024 * 1024,
    version: str = "v1",
) -> PreparedProjectMemoryActivationContent:
    """Invoke the public API with complete genuine model fixtures."""
    return prepare_project_memory_activation_content(
        p.previous.to_bytes(),
        {o.consumer_id: o.to_bytes() for o in p.prior_outputs},
        p.cutover,
        p.memory,
        bootstrap_manifest=p.bootstrap,
        bootstrap_index=p.index,
        record_contents={p.memory.records[0].content_path: content},
        max_content_bytes=limit,
        schema_version=f"project-memory-activation-plan-binding.{version}",
    )


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_content_binds_complete_plan_and_orders_registry_last(version: str) -> None:
    """Retain immutable model-bound content with bootstrap predecessors and registry-last order."""
    p = proposal() if version == "v1" else profiled_proposal()
    result = prepare(p, version=version)
    assert result.plan_binding_sha256 == p.check(
        f"project-memory-activation-plan-binding.{version}"
    )
    assert [o.role for o in result.objects] == [
        "record",
        "history",
        "memory-index",
        "memory-manifest",
        *["consumer" for _ in p.cutover.updates],
        "registry",
    ]
    record, history, index, manifest = result.objects[:4]
    assert record.identity == p.memory.records[0].content_path
    assert record.previous is history.previous is None
    assert (
        history.identity
        == f"history/manifests/{p.memory.generation_id}_{p.memory.manifest_sha256}.json"
    )
    assert history.candidate == manifest.candidate == p.memory.to_bytes()
    assert index.candidate == p.memory.index_text().encode()
    assert index.previous == p.index and manifest.previous == p.bootstrap
    assert result.objects[-1].candidate == p.cutover.candidate.to_bytes()
    assert result.total_bytes == sum(
        len(o.candidate) + len(o.previous or b"") for o in result.objects
    )
    assert prepare(p, limit=result.total_bytes, version=version) == result
    with pytest.raises(FrozenInstanceError):
        record.candidate = b"other"  # type: ignore[misc]  # Exercise frozen runtime boundary.


def test_preserves_raw_predecessors_and_detaches_input_mappings() -> None:
    """Preserve supplied bootstrap serialization and detach returned content from caller mappings."""
    p = proposal()
    raw_registry = p.previous.to_bytes()
    outputs = {o.consumer_id: o.to_bytes() for o in p.prior_outputs}
    p.bootstrap = json.dumps(json.loads(p.bootstrap), indent=3).encode() + b"\n"
    records = {p.memory.records[0].content_path: b"# Project identity\n"}
    result = prepare_project_memory_activation_content(
        raw_registry,
        outputs,
        p.cutover,
        p.memory,
        bootstrap_manifest=p.bootstrap,
        bootstrap_index=p.index,
        record_contents=records,
        max_content_bytes=1024 * 1024,
    )
    assert result.objects[-1].previous == raw_registry
    assert result.objects[3].previous == p.bootstrap
    assert {o.identity: o.previous for o in result.objects if o.role == "consumer"} == outputs
    snapshot = result.objects
    outputs.clear()
    records.clear()
    assert result.objects == snapshot and result.objects[0].candidate == b"# Project identity\n"


@pytest.mark.parametrize("side", ["registry", "consumer"])
def test_rejects_noncanonical_predecessor_instead_of_silently_normalizing(side: str) -> None:
    """Reject noncanonical prior registry/output bytes instead of silently rewriting provenance."""
    p = proposal()
    prior = p.previous.to_bytes()
    outputs = {o.consumer_id: o.to_bytes() for o in p.prior_outputs}
    if side == "registry":
        prior = json.dumps(json.loads(prior), indent=3).encode()
    else:
        key = next(iter(outputs))
        outputs[key] = json.dumps(json.loads(outputs[key]), indent=3).encode()
    with pytest.raises(ValueError, match="not canonical"):
        prepare_project_memory_activation_content(
            prior,
            outputs,
            p.cutover,
            p.memory,
            bootstrap_manifest=p.bootstrap,
            bootstrap_index=p.index,
            record_contents={},
            max_content_bytes=1024 * 1024,
        )


@pytest.mark.parametrize("budget", [0, -1, True, 1.5, 2**53, "1000"])
def test_rejects_invalid_budgets(budget: object) -> None:
    """Reject capacities outside the positive exactly representable integer contract."""
    with pytest.raises(ValueError, match="positive exact integer"):
        prepare(proposal(), limit=cast(int, budget))


@pytest.mark.parametrize("side", ["consumer", "record"])
def test_zero_byte_entries_cannot_bypass_representation_bounds(side: str) -> None:
    """Bound mapping cardinality independently of payload size, including empty values."""
    p = proposal()
    limit = PROJECT_REGISTRY_MAX_CONSUMERS if side == "consumer" else PROJECT_MEMORY_MAX_RECORDS
    excessive = {str(i): b"" for i in range(limit + 1)}
    with pytest.raises(ValueError, match="entry count"):
        prepare_project_memory_activation_content(
            p.previous.to_bytes(),
            excessive if side == "consumer" else {},
            p.cutover,
            p.memory,
            bootstrap_manifest=p.bootstrap,
            bootstrap_index=p.index,
            record_contents=excessive if side == "record" else {},
            max_content_bytes=1024 * 1024,
        )


def test_rejects_supplied_and_expanded_budget_overflow() -> None:
    """Enforce both supplied-input and expanded-output byte budgets."""
    p = proposal()
    with pytest.raises(ValueError, match="supplied"):
        prepare(p, limit=1)
    with pytest.raises(ValueError, match="prepared"):
        prepare(p, limit=prepare(p).total_bytes - 1)


@pytest.mark.parametrize("mutable", [bytearray(b"# Project identity\n"), memoryview(b"x"), "text"])
def test_refuses_non_immutable_content(mutable: object) -> None:
    """Reject mutable buffers and text at the immutable byte boundary."""
    with pytest.raises(ValueError, match="immutable bytes"):
        prepare(proposal(), content=cast(bytes, mutable))


@pytest.mark.parametrize("extra", [False, True])
def test_requires_exact_record_set(extra: bool) -> None:
    """Require complete selected record content with no unselected additions."""
    p = proposal()
    contents = {p.memory.records[0].content_path: b"# Project identity\n"} if extra else {}
    if extra:
        contents["records/identity/unselected.md"] = b"foreign\n"
    with pytest.raises(ValueError, match="exactly every"):
        prepare_project_memory_activation_content(
            p.previous.to_bytes(),
            {o.consumer_id: o.to_bytes() for o in p.prior_outputs},
            p.cutover,
            p.memory,
            bootstrap_manifest=p.bootstrap,
            bootstrap_index=p.index,
            record_contents=contents,
            max_content_bytes=1024 * 1024,
        )


def test_rejects_mislabelled_consumer_bytes() -> None:
    """Reject consumer metadata whose identity differs from its mapping key."""
    p = proposal()
    outputs = {o.consumer_id: o.to_bytes() for o in p.prior_outputs}
    outputs["wrong-id"] = outputs.pop(next(iter(outputs)))
    with pytest.raises(ValueError, match="identity differs"):
        prepare_project_memory_activation_content(
            p.previous.to_bytes(),
            outputs,
            p.cutover,
            p.memory,
            bootstrap_manifest=p.bootstrap,
            bootstrap_index=p.index,
            record_contents={},
            max_content_bytes=1024 * 1024,
        )


@pytest.mark.parametrize("content", [b"short\n", b"# Foreign identity\n"])
def test_rejects_content_not_matching_metadata(content: bytes) -> None:
    """Reject record bytes that differ in size or hash from selected metadata."""
    with pytest.raises(ValueError, match="bytes differ"):
        prepare(proposal(), content=content)


@pytest.mark.parametrize("content", [b"\xff\n", b"\xef\xbb\xbfx\n", b"x\x00\n", b"no newline"])
def test_rejects_digest_matching_invalid_markdown(content: bytes) -> None:
    """Reject malformed Markdown even when the record hash faithfully identifies it."""
    p = proposal()
    record = replace(
        p.memory.records[0],
        content_bytes=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
    p.memory = ProjectMemoryManifest.build(
        project_id=p.memory.project_id,
        generated_at=p.memory.generated_at,
        previous_manifest_sha256=None,
        parents=p.memory.parents,
        records=(record,),
    )
    with pytest.raises(ValueError):
        prepare(p, content=content)


def test_content_preparation_cannot_bypass_cross_object_validation() -> None:
    """Retain bootstrap project-identity checks across the content adapter."""
    p = proposal()
    p.bootstrap = p.bootstrap.replace(b"PROJECT-A", b"PROJECT-B")
    with pytest.raises(ValueError, match="selected empty scaffold"):
        prepare(p)


def test_content_preparation_does_not_infer_profile_upgrade() -> None:
    """Require explicit v2 selection rather than interpreting profiled inputs as v1."""
    with pytest.raises(ValueError, match="v1 memory activation"):
        prepare(profiled_proposal())
