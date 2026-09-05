# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory activation plan binding
"""Check an initial memory proposal without authorising or applying writes."""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import replace

from .project_memory_models import ProjectMemoryManifest
from .project_memory_primitives import (
    PROJECT_MEMORY_MAX_INDEX_BYTES,
    PROJECT_MEMORY_MAX_MANIFEST_BYTES,
)
from .project_registry_cutover import (
    ProjectRegistryCutoverPlan,
    validate_project_registry_transition,
)
from .project_registry_models import ProjectRegistry
from .project_registry_primitives import (
    project_registry_canonical_json,
    project_registry_strict_json,
)
from .project_registry_views import (
    ProjectRegistryConsumerOutput,
    validate_consumer_output_for_registry,
)


class ProjectMemoryActivationPlanInvalid(ValueError):
    """An activation proposal changes unrelated state or has inconsistent evidence."""


def validate_project_memory_activation_plan(
    previous: ProjectRegistry,
    previous_outputs: tuple[ProjectRegistryConsumerOutput, ...],
    cutover: ProjectRegistryCutoverPlan,
    memory: ProjectMemoryManifest,
    *,
    bootstrap_manifest: bytes,
    bootstrap_index: bytes,
) -> str:
    """Bind a single-project initial activation to an all-consumer registry plan.

    Parameters
    ----------
    previous:
        Validated predecessor registry supplied by the caller.
    previous_outputs:
        Every predecessor consumer, including unchanged global payloads.
    cutover:
        Candidate registry and exact expected/candidate consumer digests.
    memory:
        Initial v1 manifest, with no predecessor or unseen supersession.
    bootstrap_manifest:
        Original empty bootstrap bytes to preserve, not a reconstructed copy.
    bootstrap_index:
        Original bounded UTF-8 bootstrap index bytes to preserve.

    Returns
    -------
    str
        SHA-256 binding of all supplied objects and original bootstrap bytes.
        This is a proposal digest, never an authority or activation receipt.

    Raises
    ------
    ValueError
        If an input fails its existing v1 schema or the cross-object contract.
    RuntimeError
        If the existing registry cutover validator refuses the transaction.

    Notes
    -----
    This function performs no I/O. The operator must separately verify live
    authority, claims, Git baseline, source/content bytes, private filesystem,
    publication outputs and unchanged predecessors while holding write locks.
    A caller-supplied actor or digest is not proof of those conditions.
    """
    previous = ProjectRegistry.from_bytes(previous.to_bytes())
    memory = ProjectMemoryManifest.from_bytes(memory.to_bytes())
    cutover = ProjectRegistryCutoverPlan.build(
        cutover.candidate,
        expected_registry_sha256=cutover.expected_registry_sha256,
        updates=cutover.updates,
    )
    candidate = cutover.candidate
    validate_project_registry_transition(previous, candidate)
    if cutover.expected_registry_sha256 != previous.registry_sha256:
        raise ProjectMemoryActivationPlanInvalid("activation predecessor precondition differs")
    selected = next((p for p in previous.projects if p.project_id == memory.project_id), None)
    if selected is None or selected.memory_state != "scaffold-only":
        raise ProjectMemoryActivationPlanInvalid("activation requires a registered scaffold")
    if selected.lifecycle_state != "active" or selected.target_kind != "git-repository":
        raise ProjectMemoryActivationPlanInvalid("activation requires an active Git project")
    expected_projects = tuple(
        replace(p, memory_state="active") if p == selected else p for p in previous.projects
    )
    if (
        candidate.projects != expected_projects
        or candidate.groups != previous.groups
        or candidate.consumers != previous.consumers
    ):
        raise ProjectMemoryActivationPlanInvalid("activation changes unrelated registry state")
    if memory.previous_manifest_sha256 is not None or any(r.supersedes for r in memory.records):
        raise ProjectMemoryActivationPlanInvalid(
            "activation requires an initial memory generation"
        )
    authority = candidate.authority
    if any(
        r.actor.identity != authority.validator_identity
        or r.actor.claim_id != authority.validation_claim_id
        for r in memory.records
    ):
        raise ProjectMemoryActivationPlanInvalid("memory actor and registry provenance differ")
    if not authority.approved_at <= memory.generated_at <= candidate.generated_at:
        raise ProjectMemoryActivationPlanInvalid("activation generation order is invalid")

    prior = tuple(ProjectRegistryConsumerOutput.from_bytes(p.to_bytes()) for p in previous_outputs)
    if sorted(p.consumer_id for p in prior) != [c.consumer_id for c in previous.consumers]:
        raise ProjectMemoryActivationPlanInvalid("activation requires every predecessor consumer")
    by_id = {p.consumer_id: p for p in prior}
    for output in prior:
        validate_consumer_output_for_registry(previous, output)
    for update in cutover.updates:
        old = by_id[update.consumer_id]
        if update.expected_sha256 != old.output_sha256:
            raise ProjectMemoryActivationPlanInvalid("activation consumer precondition differs")
        if (
            old.consumer_kind not in {"group-view", "project-index"}
            and update.output.payload != old.payload
        ):
            raise ProjectMemoryActivationPlanInvalid("activation changes a global payload")

    group = next(g for g in previous.groups if g.group_id == selected.owning_group_id)
    memory_root = selected.canonical_path + "/agentic_project_memory"
    targets = {
        "ecosystem-boot": "AGENTS.md",
        "ecosystem-rules": "agentic-shared/SHARED_CONTEXT.md",
        "ecosystem-memory": "agentic-shared/memory/INDEX.md",
        "group-memory": group.memory_index_path,
        "project-sessions": f".coordination/sessions/{selected.project_id}",
        "project-handovers": f".coordination/handovers/{selected.project_id}",
        "vendor-memory": "agentic-shared/memory/vendors",
    }
    for parent in memory.parents:
        if parent.locator.rstrip("/") != posixpath.relpath(targets[parent.kind], memory_root):
            raise ProjectMemoryActivationPlanInvalid(
                "memory parent does not match its project layer"
            )
    if not bootstrap_manifest or len(bootstrap_manifest) > PROJECT_MEMORY_MAX_MANIFEST_BYTES:
        raise ProjectMemoryActivationPlanInvalid("bootstrap manifest byte bound failed")
    bootstrap = project_registry_strict_json(bootstrap_manifest)
    if not isinstance(bootstrap, dict):
        raise ProjectMemoryActivationPlanInvalid("bootstrap manifest must be an object")
    expected_bootstrap = {
        "schema_version": "project-memory.bootstrap.v1",
        "schema_status": "NON_RATIFIED_BOOTSTRAP",
        "activation_state": "SCAFFOLD_ONLY",
        "project_id": selected.project_id,
        "portfolio_id": selected.owning_group_id,
        "memory_root": "agentic_project_memory",
        "index": "memory_index.md",
        "records": [],
    }
    if set(bootstrap) != set(expected_bootstrap) | {
        "created_at",
        "owner_authority",
        "limitations",
    }:
        raise ProjectMemoryActivationPlanInvalid("bootstrap fields differ from the known scaffold")
    if any(bootstrap.get(key) != value for key, value in expected_bootstrap.items()):
        raise ProjectMemoryActivationPlanInvalid("bootstrap is not the selected empty scaffold")
    if not bootstrap_index or len(bootstrap_index) > PROJECT_MEMORY_MAX_INDEX_BYTES:
        raise ProjectMemoryActivationPlanInvalid("bootstrap index byte bound failed")
    index_text = bootstrap_index.decode("utf-8")
    if "\x00" in index_text or index_text.startswith("\ufeff") or not index_text.endswith("\n"):
        raise ProjectMemoryActivationPlanInvalid("bootstrap index is not bounded Markdown")
    binding: dict[str, object] = {
        "schema_version": "project-memory-activation-plan-binding.v1",
        "previous_registry_sha256": previous.registry_sha256,
        "candidate_registry_sha256": candidate.registry_sha256,
        "memory_manifest_sha256": memory.manifest_sha256,
        "bootstrap_manifest_sha256": hashlib.sha256(bootstrap_manifest).hexdigest(),
        "bootstrap_index_sha256": hashlib.sha256(bootstrap_index).hexdigest(),
        "consumers": [
            [u.consumer_id, u.expected_sha256, u.output.output_sha256] for u in cutover.updates
        ],
    }
    return hashlib.sha256(project_registry_canonical_json(binding)).hexdigest()
