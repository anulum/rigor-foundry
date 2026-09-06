# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable activation intent artifact
"""Bind model-prepared activation intent, never authority or successful outcome.

The service must independently prepare the expected model using trusted current
sources, layout and policy. Comparing an artifact to itself, or to a model derived
only from untrusted submitted metadata, establishes no trust. Private metadata
must stay in the operator-enrolled content store, not public distribution outputs.
"""

from __future__ import annotations

import hashlib
import hmac

from .project_memory_activation_publication import PreparedProjectMemoryActivationPublication
from .project_memory_primitives import canonical_json_bytes

PROJECT_MEMORY_ACTIVATION_ARTIFACT_DOMAIN = "project-memory-activation-artifact.v1"


def encode_project_memory_activation_artifact(
    prepared: PreparedProjectMemoryActivationPublication,
    *,
    max_artifact_bytes: int,
) -> bytes:
    """Encode ordered content/path/source and complete-operation bindings.

    Uses existing RIGOR canonical JSON. The artifact ContentRef digest is raw
    SHA256 of these exact bytes, NOT the Core proposal or registry digest.
    ``prepared`` is plain data produced by model preparation, not a capability.
    This encoder cannot establish capture authenticity, sensitivity, fresh claims,
    physical roots, independent approval, enrollment or execution. All those gates
    remain separate. Invalid positive exact limits or size overflow raise ValueError.
    """
    if type(max_artifact_bytes) is not int or not 0 < max_artifact_bytes <= 2**53 - 1:
        raise ValueError("activation artifact budget must be a positive exact integer")
    artifact = {
        "schema_version": PROJECT_MEMORY_ACTIVATION_ARTIFACT_DOMAIN,
        "target_project": prepared.target_project,
        "plan_binding_sha256": prepared.content.plan_binding_sha256,
        "operation_fields_sha256": hashlib.sha256(
            prepared.publication.operation_fields
        ).hexdigest(),
        "destinations": [
            {"role": role, "identity": identity, "deployment_path": path}
            for role, identity, path in prepared.destinations
        ],
        "objects": [
            {
                "role": obj.role,
                "identity": obj.identity,
                "previous": None if obj.previous is None else _content_binding(obj.previous),
                "candidate": _content_binding(obj.candidate),
            }
            for obj in prepared.content.objects
        ],
        "sources": [
            {**source.to_dict(), "size_bytes": len(content)}
            for source, content in prepared.sources
        ],
    }
    encoded = canonical_json_bytes(artifact)
    if len(encoded) > max_artifact_bytes:
        raise ValueError("activation artifact exceeds its byte budget")
    return encoded


def verify_project_memory_activation_artifact(
    payload: bytes,
    expected: PreparedProjectMemoryActivationPublication,
    *,
    max_artifact_bytes: int,
) -> str:
    """Verify exact canonical bytes against an independently prepared expected model.

    Return the raw ContentRef SHA256, never an execution permit or receipt.
    The caller must obtain ``expected`` from trusted current preparation, not from
    the submitted artifact itself. Exact comparison rejects unknown fields,
    duplicate JSON keys, alternate encoding, reordered arrays and stale metadata.
    Payloads are not parsed, dereferenced, fetched or logged. Bounds, mutable input
    or any mismatch raise ValueError without leaking private artifact details.
    """
    canonical = encode_project_memory_activation_artifact(
        expected, max_artifact_bytes=max_artifact_bytes
    )
    if type(payload) is not bytes or len(payload) > max_artifact_bytes:
        raise ValueError("activation artifact requires bounded immutable bytes")
    if not hmac.compare_digest(payload, canonical):
        raise ValueError("activation artifact differs from independently prepared intent")
    return hashlib.sha256(payload).hexdigest()


def _content_binding(content: bytes) -> dict[str, object]:
    """Describe immutable payload identity without embedding its private bytes."""
    return {"sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}
