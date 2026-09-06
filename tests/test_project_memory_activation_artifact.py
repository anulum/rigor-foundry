# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — activation intent artifact tests
"""Verify actual model-prepared content bindings and rejection of altered artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import cast

import pytest
from test_project_memory_activation_publication import (
    layout_for,
    prepare,
    profiled_proposal,
    proposal,
)

from rigor_foundry.project_memory_activation_artifact import (
    PROJECT_MEMORY_ACTIVATION_ARTIFACT_DOMAIN,
    encode_project_memory_activation_artifact,
    verify_project_memory_activation_artifact,
)


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_complete_intent_artifact_matches_independent_model_preparation(version: str) -> None:
    """Bind v1/v2 model content and operations without embedding private source bytes."""
    p = proposal() if version == "v1" else profiled_proposal()
    expected = prepare(p, layout_for(p), version=version)
    payload = encode_project_memory_activation_artifact(expected, max_artifact_bytes=65536)
    independently_prepared = prepare(p, layout_for(p), version=version)
    assert (
        verify_project_memory_activation_artifact(
            payload, independently_prepared, max_artifact_bytes=len(payload)
        )
        == hashlib.sha256(payload).hexdigest()
    )
    document = json.loads(payload)
    assert document["schema_version"] == PROJECT_MEMORY_ACTIVATION_ARTIFACT_DOMAIN
    assert document["target_project"] == p.memory.project_id
    assert document["plan_binding_sha256"] == expected.content.plan_binding_sha256
    assert (
        document["operation_fields_sha256"]
        == hashlib.sha256(expected.publication.operation_fields).hexdigest()
    )
    assert document["objects"][0]["previous"] is None
    assert (
        document["objects"][-1]["previous"]["sha256"]
        == hashlib.sha256(p.previous.to_bytes()).hexdigest()
    )
    assert (
        document["objects"][-1]["candidate"]["sha256"]
        == hashlib.sha256(p.cutover.candidate.to_bytes()).hexdigest()
    )
    assert document["destinations"][-1]["deployment_path"] == layout_for(p).registry_path
    assert document["sources"][0]["sha256"] == hashlib.sha256(expected.sources[0][1]).hexdigest()
    assert p.bootstrap not in payload and expected.sources[0][1] not in payload
    assert "status" not in document and "receipt" not in document


@pytest.mark.parametrize("budget", [True, 0, -1, 1.5, 2**53])
def test_invalid_exact_budget(budget: object) -> None:
    """Reject non-integral, boolean and out-of-range artifact capacity declarations."""
    p = proposal()
    with pytest.raises(ValueError, match="positive exact"):
        encode_project_memory_activation_artifact(
            prepare(p, layout_for(p)), max_artifact_bytes=cast(int, budget)
        )


def test_exact_budget_and_payload_limits() -> None:
    """Accept exact capacity but reject oversized or mutable artifact representations."""
    p = proposal()
    expected = prepare(p, layout_for(p))
    encoded = encode_project_memory_activation_artifact(expected, max_artifact_bytes=65536)
    with pytest.raises(ValueError, match="exceeds"):
        encode_project_memory_activation_artifact(expected, max_artifact_bytes=len(encoded) - 1)
    with pytest.raises(ValueError, match="bounded immutable"):
        verify_project_memory_activation_artifact(
            encoded + b"x", expected, max_artifact_bytes=len(encoded)
        )
    with pytest.raises(ValueError, match="bounded immutable"):
        verify_project_memory_activation_artifact(
            cast(bytes, bytearray(encoded)), expected, max_artifact_bytes=65536
        )


@pytest.mark.parametrize(
    "change",
    [
        "target",
        "objects",
        "sources",
        "destinations",
        "operations",
        "unknown",
        "duplicate",
        "encoding",
    ],
)
def test_altered_or_noncanonical_artifacts_are_refused(change: str) -> None:
    """Reject altered bindings and noncanonical encodings against independently prepared intent."""
    p = proposal()
    expected = prepare(p, layout_for(p))
    payload = encode_project_memory_activation_artifact(expected, max_artifact_bytes=65536)
    data = json.loads(payload)
    if change == "target":
        data["target_project"] = "FOREIGN"
    elif change == "objects":
        data["objects"].reverse()
    elif change == "sources":
        data["sources"] = []
    elif change == "destinations":
        data["destinations"][-1]["deployment_path"] = "foreign/registry.json"
    elif change == "operations":
        data["operation_fields_sha256"] = "0" * 64
    elif change == "unknown":
        data["status"] = "committed"
    changed = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    if change == "duplicate":
        changed = payload[:-1] + b',"target_project":"PROJECT-A"}'
    elif change == "encoding":
        changed = json.dumps(data, indent=2).encode()
    with pytest.raises(ValueError, match="independently prepared"):
        verify_project_memory_activation_artifact(changed, expected, max_artifact_bytes=65536)


def test_prepared_operations_cannot_change_without_invalidating_old_artifact() -> None:
    """Invalidate an existing artifact when its expected operation sequence changes."""
    p = proposal()
    expected = prepare(p, layout_for(p))
    original = encode_project_memory_activation_artifact(expected, max_artifact_bytes=65536)
    changed = replace(
        expected,
        publication=replace(expected.publication, operation_fields=b"different operations"),
    )
    with pytest.raises(ValueError, match="independently prepared"):
        verify_project_memory_activation_artifact(original, changed, max_artifact_bytes=65536)
