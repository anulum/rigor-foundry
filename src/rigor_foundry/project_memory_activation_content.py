# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable activation content preparation
"""Prepare exact content for a protected consumer without touching storage.

This is not a Core proposal or an execution permit. The subsequent effect
expansion must bind enrolled roots, observed preconditions, retained snapshots,
temporary names, locks, durability operations and successful receipt artifacts.
Raw prior bytes are retained, never regenerated from parsed metadata. A plan
binding digest does not certify a raw-file hash or filesystem custody.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

from .project_memory_activation_plan import validate_project_memory_activation_plan
from .project_memory_models import ProjectMemoryManifest
from .project_memory_primitives import PROJECT_MEMORY_MAX_RECORDS
from .project_registry_cutover import ProjectRegistryConsumerUpdate, ProjectRegistryCutoverPlan
from .project_registry_models import PROJECT_REGISTRY_MAX_CONSUMERS, ProjectRegistry
from .project_registry_views import ProjectRegistryConsumerOutput


@dataclass(frozen=True)
class ProjectMemoryActivationContent:
    """One immutable content pair, with an explicitly scoped logical identity.

    ``role`` is registry, consumer, record, history, memory-index or
    memory-manifest. Identities are not enrolled paths: consumers use their
    registry ID; memory artifacts use paths relative to the memory root.
    ``previous`` is exact supplied storage content, not canonical reconstruction.
    None describes an intended exclusive create, not an observed absent file.
    The future protected adapter must reject collisions before admission.
    """

    role: str
    identity: str
    previous: bytes | None
    candidate: bytes


@dataclass(frozen=True)
class PreparedProjectMemoryActivationContent:
    """Content ordered for registry-last activation, with no write authority.

    The existing plan digest binds model metadata and bootstrap bytes. It is
    not a digest of this container or the raw predecessor serialization.
    Content objects are plain immutable data; constructing them directly does
    not substitute for calling the validating preparation API.
    """

    plan_binding_sha256: str
    objects: tuple[ProjectMemoryActivationContent, ...]
    total_bytes: int


def prepare_project_memory_activation_content(
    previous_registry: bytes,
    previous_outputs: Mapping[str, bytes],
    cutover: ProjectRegistryCutoverPlan,
    memory: ProjectMemoryManifest,
    *,
    bootstrap_manifest: bytes,
    bootstrap_index: bytes,
    record_contents: Mapping[str, bytes],
    max_content_bytes: int,
    schema_version: str = "project-memory-activation-plan-binding.v1",
) -> PreparedProjectMemoryActivationContent:
    """Validate and freeze a complete activation's business content, without I/O.

    Parameters
    ----------
    previous_registry, previous_outputs:
        Exact prior storage bytes; output mapping keys must be consumer IDs.
    cutover, memory:
        Existing validated registry and memory models, defensively reparsed.
    bootstrap_manifest, bootstrap_index:
        Exact original scaffold bytes retained for later snapshot preservation.
    record_contents:
        Every selected record's immutable Markdown, keyed by content_path.
    max_content_bytes:
        Positive exact integer bounding supplied bytes and the returned content
        inventory, counting every prior and candidate artifact occurrence.
        Auxiliary snapshot, journal and temporary write budgets are separate.
    schema_version:
        Explicit existing activation binding version; no inferred v1/v2 upgrade.

    Returns
    -------
    PreparedProjectMemoryActivationContent
        Records, history, index, manifest, all consumers, then registry content.

    Raises
    ------
    ValueError
        For invalid bounds, mutable bytes, incomplete/extra/misidentified
        content, malformed Markdown, record digest mismatch or invalid plan.

    Notes
    -----
    No content is read, classified for secrets, written or activated. Models'
    canonical candidate bytes are reused; original predecessor bytes are not
    normalized. This preparation cannot be passed off as a complete write-set.
    """
    if type(max_content_bytes) is not int or not 0 < max_content_bytes <= 2**53 - 1:
        raise ValueError("activation content budget must be a positive exact integer")
    if (
        len(previous_outputs) > PROJECT_REGISTRY_MAX_CONSUMERS
        or len(record_contents) > PROJECT_MEMORY_MAX_RECORDS
    ):
        raise ValueError("activation content entry count exceeds model limits")
    prior_content = dict(previous_outputs)
    records = dict(record_contents)
    supplied = (
        previous_registry,
        bootstrap_manifest,
        bootstrap_index,
        *prior_content.values(),
        *records.values(),
    )
    if any(type(value) is not bytes for value in supplied):
        raise ValueError("activation content requires immutable bytes")
    if sum(len(value) for value in supplied) > max_content_bytes:
        raise ValueError("supplied activation content exceeds its byte budget")

    previous = ProjectRegistry.from_bytes(previous_registry)
    prior = tuple(
        ProjectRegistryConsumerOutput.from_bytes(value) for value in prior_content.values()
    )
    if any(key != output.consumer_id for key, output in zip(prior_content, prior, strict=True)):
        raise ValueError("prior consumer content identity differs from its key")
    memory = ProjectMemoryManifest.from_bytes(memory.to_bytes())
    cutover = ProjectRegistryCutoverPlan.build(
        cutover.candidate,
        expected_registry_sha256=cutover.expected_registry_sha256,
        updates=tuple(
            ProjectRegistryConsumerUpdate(
                update.consumer_id,
                update.expected_sha256,
                ProjectRegistryConsumerOutput.from_bytes(update.output.to_bytes()),
            )
            for update in cutover.updates
        ),
    )
    binding = validate_project_memory_activation_plan(
        previous,
        prior,
        cutover,
        memory,
        bootstrap_manifest=bootstrap_manifest,
        bootstrap_index=bootstrap_index,
        schema_version=schema_version,
    )
    if set(records) != {record.content_path for record in memory.records}:
        raise ValueError("activation requires exactly every selected record content")
    objects: list[ProjectMemoryActivationContent] = []
    for record in memory.records:
        content = records[record.content_path]
        if (
            len(content) != record.content_bytes
            or hashlib.sha256(content).hexdigest() != record.content_sha256
        ):
            raise ValueError("activation record bytes differ from their metadata")
        text = content.decode("utf-8")
        if text.startswith("\ufeff") or "\x00" in text or not text.endswith("\n"):
            raise ValueError("activation record is not BOM-free, NUL-free Markdown")
        objects.append(
            ProjectMemoryActivationContent("record", record.content_path, None, content)
        )
    manifest = memory.to_bytes()
    objects.extend(
        (
            ProjectMemoryActivationContent(
                "history",
                f"history/manifests/{memory.generation_id}_{memory.manifest_sha256}.json",
                None,
                manifest,
            ),
            ProjectMemoryActivationContent(
                "memory-index",
                "memory_index.md",
                bootstrap_index,
                memory.index_text().encode("utf-8"),
            ),
            ProjectMemoryActivationContent(
                "memory-manifest", "memory_manifest.json", bootstrap_manifest, manifest
            ),
        )
    )
    objects.extend(
        ProjectMemoryActivationContent(
            "consumer",
            update.consumer_id,
            prior_content[update.consumer_id],
            update.output.to_bytes(),
        )
        for update in cutover.updates
    )
    objects.append(
        ProjectMemoryActivationContent(
            "registry",
            "registry",
            previous_registry,
            cutover.candidate.to_bytes(),
        )
    )
    total = sum(len(obj.candidate) + len(obj.previous or b"") for obj in objects)
    if total > max_content_bytes:
        raise ValueError("prepared activation content exceeds its byte budget")
    return PreparedProjectMemoryActivationContent(binding, tuple(objects), total)
