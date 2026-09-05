# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-object memory activation plan tests
"""Reject inconsistent activation proposals through the public plan boundary."""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass, replace

import pytest
from test_project_memory_store import record
from test_project_registry_models import consumers, group, profiled_registry, project, registry

from rigor_foundry.project_memory_activation_plan import validate_project_memory_activation_plan
from rigor_foundry.project_memory_models import (
    ProjectMemoryManifest,
    ProjectMemoryRecord,
    project_memory_profile_parents,
)
from rigor_foundry.project_memory_primitives import ProjectMemoryActor, ProjectMemoryParent
from rigor_foundry.project_registry_cutover import (
    ProjectRegistryConsumerUpdate,
    ProjectRegistryCutoverPlan,
)
from rigor_foundry.project_registry_models import ProjectRegistry, ProjectRegistryConsumer
from rigor_foundry.project_registry_views import (
    ProjectRegistryConsumerOutput,
    build_registry_consumer_outputs,
)


@dataclass
class Proposal:
    previous: ProjectRegistry
    prior_outputs: tuple[ProjectRegistryConsumerOutput, ...]
    cutover: ProjectRegistryCutoverPlan
    memory: ProjectMemoryManifest
    bootstrap: bytes
    index: bytes = b"# Original project index\n"

    def check(self, schema_version: str = "project-memory-activation-plan-binding.v1") -> str:
        return validate_project_memory_activation_plan(
            self.previous,
            self.prior_outputs,
            self.cutover,
            self.memory,
            bootstrap_manifest=self.bootstrap,
            bootstrap_index=self.index,
            schema_version=schema_version,
        )


@pytest.mark.parametrize("side", ["previous", "candidate"])
def test_v1_activation_refuses_profiled_registry(side: str) -> None:
    p = proposal()
    if side == "previous":
        p.previous = profiled_registry(p.previous)
    else:
        candidate = profiled_registry(p.cutover.candidate)
        outputs = build_registry_consumer_outputs(
            candidate, {"global-boot": {"selector": "explicit"}}
        )
        prior = {output.consumer_id: output.output_sha256 for output in p.prior_outputs}
        p.cutover = ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=candidate.previous_registry_sha256,
            updates=tuple(
                ProjectRegistryConsumerUpdate.build(
                    output, expected_sha256=prior[output.consumer_id]
                )
                for output in outputs
            ),
        )
    with pytest.raises(
        ValueError, match="v1 memory activation cannot consume a profiled registry"
    ):
        p.check()


def proposal() -> Proposal:
    groups = (group(),)
    projects = (project(), project("PROJECT-B"))
    base = registry(groups=groups, projects=projects)
    extra = ProjectRegistryConsumer(
        "global-boot", "boot-resolver", "agentic-shared/boot.json", None, None
    )
    previous = replace(
        base,
        consumers=tuple(
            sorted((*consumers(projects, groups), extra), key=lambda c: c.consumer_id)
        ),
    )
    previous = ProjectRegistry.build(
        generated_at=base.generated_at,
        previous_registry_sha256=None,
        authority=base.authority,
        groups=groups,
        projects=projects,
        consumers=previous.consumers,
    )
    candidate = ProjectRegistry.build(
        generated_at="2026-09-04T12:03:00.000000Z",
        previous_registry_sha256=previous.registry_sha256,
        authority=previous.authority,
        groups=groups,
        projects=(replace(projects[0], memory_state="active"), projects[1]),
        consumers=previous.consumers,
    )
    old_outputs = build_registry_consumer_outputs(
        previous, {"global-boot": {"selector": "explicit"}}
    )
    outputs = build_registry_consumer_outputs(
        candidate,
        {
            c.consumer_id: {"selector": "explicit"}
            for c in candidate.consumers
            if c.kind not in {"group-view", "project-index"}
        },
    )
    plan = ProjectRegistryCutoverPlan.build(
        candidate,
        expected_registry_sha256=previous.registry_sha256,
        updates=tuple(
            ProjectRegistryConsumerUpdate.build(new, expected_sha256=old.output_sha256)
            for old, new in zip(old_outputs, outputs, strict=True)
        ),
    )
    identity = replace(
        record("identity-0001", b"# Project identity\n"),
        actor=ProjectMemoryActor(
            previous.authority.validator_identity, previous.authority.validation_claim_id
        ),
    )
    memory_root = projects[0].canonical_path + "/agentic_project_memory"
    targets = {
        "ecosystem-boot": "AGENTS.md",
        "ecosystem-rules": "agentic-shared/SHARED_CONTEXT.md",
        "ecosystem-memory": "agentic-shared/memory/INDEX.md",
        "group-memory": groups[0].memory_index_path,
        "project-sessions": ".coordination/sessions/PROJECT-A",
        "project-handovers": ".coordination/handovers/PROJECT-A",
        "vendor-memory": "agentic-shared/memory/vendors",
    }
    memory = ProjectMemoryManifest.build(
        project_id="PROJECT-A",
        generated_at="2026-09-04T12:02:00.000000Z",
        previous_manifest_sha256=None,
        parents=tuple(
            ProjectMemoryParent(k, posixpath.relpath(v, memory_root)) for k, v in targets.items()
        ),
        records=(identity,),
    )
    bootstrap = json.dumps(
        {
            "schema_version": "project-memory.bootstrap.v1",
            "schema_status": "NON_RATIFIED_BOOTSTRAP",
            "activation_state": "SCAFFOLD_ONLY",
            "project_id": "PROJECT-A",
            "portfolio_id": "GROUP-A",
            "memory_root": "agentic_project_memory",
            "index": "memory_index.md",
            "records": [],
            "created_at": "2026-09-04T11:00:00+00:00",
            "owner_authority": {"directive": "create scaffold"},
            "limitations": ["advisory"],
        }
    ).encode()
    return Proposal(previous, old_outputs, plan, memory, bootstrap)


def profiled_proposal() -> Proposal:
    """Build one complete v2 proposal with independent group membership."""
    p = proposal()
    groups = (group(), group("GROUP-B"))
    declared = consumers(p.previous.projects, groups) + tuple(
        c for c in p.previous.consumers if c.kind not in {"group-view", "project-index"}
    )
    p.previous = profiled_registry(
        ProjectRegistry.build(
            generated_at=p.previous.generated_at,
            previous_registry_sha256=None,
            authority=p.previous.authority,
            groups=groups,
            projects=p.previous.projects,
            consumers=tuple(sorted(declared, key=lambda c: c.consumer_id)),
        )
    )
    p.prior_outputs = build_registry_consumer_outputs(
        p.previous, {"global-boot": {"selector": "explicit"}}
    )
    candidate = replace(
        p.cutover.candidate,
        groups=groups,
        consumers=p.previous.consumers,
        profile=p.previous.profile,
        previous_registry_sha256=p.previous.registry_sha256,
    )
    rebuild_registry(p, candidate)
    assert p.previous.profile is not None
    p.memory = ProjectMemoryManifest.build(
        project_id=p.memory.project_id,
        generated_at=p.memory.generated_at,
        previous_manifest_sha256=None,
        records=p.memory.records,
        parents=project_memory_profile_parents(p.previous.profile, "GROUP-A", p.memory.project_id),
        profile=p.previous.profile,
        group_id="GROUP-A",
    )
    return p


def test_profiled_activation_requires_explicit_version_and_exact_objects() -> None:
    p = profiled_proposal()
    schema = "project-memory-activation-plan-binding.v2"
    digest = p.check(schema)
    assert digest == p.check(schema)
    assert len(digest) == 64
    with pytest.raises(ValueError, match="v1 memory activation"):
        p.check()
    with pytest.raises(ValueError, match="unsupported"):
        p.check("project-memory-activation-plan-binding.v99")
    p.index += b"\n"
    assert p.check(schema) != digest


@pytest.mark.parametrize(
    "case", ["legacy", "legacy-memory", "changed-candidate-profile", "foreign-group"]
)
def test_profiled_activation_refuses_mixed_profile_or_owner(case: str) -> None:
    from test_deployment_profile import encode_profile

    from rigor_foundry.deployment_profile import DeploymentProfile

    p = proposal() if case == "legacy" else profiled_proposal()
    if case == "legacy-memory":
        p.memory = proposal().memory
    elif case == "changed-candidate-profile":
        assert p.previous.profile is not None
        data = json.loads(p.previous.profile.to_bytes())
        data["profile_id"] = "different-profile"
        rebuild_registry(
            p,
            replace(
                p.cutover.candidate, profile=DeploymentProfile.from_bytes(encode_profile(data))
            ),
        )
    elif case == "foreign-group":
        assert p.memory.profile is not None
        p.memory = ProjectMemoryManifest.build(
            project_id=p.memory.project_id,
            generated_at=p.memory.generated_at,
            previous_manifest_sha256=None,
            records=p.memory.records,
            parents=project_memory_profile_parents(
                p.memory.profile, "GROUP-B", p.memory.project_id
            ),
            profile=p.memory.profile,
            group_id="GROUP-B",
        )
    with pytest.raises(ValueError, match=r"profiles|registered owner"):
        p.check("project-memory-activation-plan-binding.v2")


def rebuild_memory(
    p: Proposal,
    *,
    project_id: str | None = None,
    generated_at: str | None = None,
    previous_manifest_sha256: str | None = None,
    parents: tuple[ProjectMemoryParent, ...] | None = None,
    records: tuple[ProjectMemoryRecord, ...] | None = None,
) -> None:
    # Rebuild through the public constructor to test semantic, not digest, refusal.
    candidate = replace(
        p.memory,
        project_id=project_id or p.memory.project_id,
        generated_at=generated_at or p.memory.generated_at,
        previous_manifest_sha256=previous_manifest_sha256,
        parents=parents or p.memory.parents,
        records=records or p.memory.records,
    )
    p.memory = ProjectMemoryManifest.build(
        project_id=candidate.project_id,
        generated_at=candidate.generated_at,
        previous_manifest_sha256=candidate.previous_manifest_sha256,
        parents=candidate.parents,
        records=candidate.records,
        profile=candidate.profile,
        group_id=candidate.group_id,
    )


def rebuild_registry(p: Proposal, candidate: ProjectRegistry) -> None:
    candidate = ProjectRegistry.build(
        generated_at=candidate.generated_at,
        previous_registry_sha256=candidate.previous_registry_sha256,
        authority=candidate.authority,
        groups=candidate.groups,
        projects=candidate.projects,
        consumers=tuple(sorted(candidate.consumers, key=lambda c: c.consumer_id)),
        profile=candidate.profile,
    )
    outputs = build_registry_consumer_outputs(
        candidate,
        {
            c.consumer_id: {"selector": "explicit"}
            for c in candidate.consumers
            if c.kind not in {"group-view", "project-index"}
        },
    )
    old = {o.consumer_id: o.output_sha256 for o in p.prior_outputs}
    p.cutover = ProjectRegistryCutoverPlan.build(
        candidate,
        expected_registry_sha256=p.previous.registry_sha256,
        updates=tuple(
            ProjectRegistryConsumerUpdate.build(o, expected_sha256=old.get(o.consumer_id))
            for o in outputs
        ),
    )


def test_initial_proposal_digest_binds_original_bytes_without_mutating_inputs() -> None:
    p = proposal()
    before = (
        p.previous.to_bytes(),
        p.cutover.candidate.to_bytes(),
        p.memory.to_bytes(),
        p.bootstrap,
    )
    digest = p.check()
    assert len(digest) == 64 and digest == p.check()
    assert before == (
        p.previous.to_bytes(),
        p.cutover.candidate.to_bytes(),
        p.memory.to_bytes(),
        p.bootstrap,
    )
    p.index += b"\n"
    assert p.check() != digest
    p.index = b"# Original project index\n"
    p.bootstrap += b"\n"
    assert p.check() != digest


@pytest.mark.parametrize(
    "case",
    [
        "unknown-project",
        "prior-active",
        "paused",
        "non-git",
        "collateral-project",
        "collateral-group",
        "collateral-consumer",
        "memory-predecessor",
        "supersession",
        "actor",
        "claim",
        "time",
        "missing-prior",
        "duplicate-prior",
        "stale-registry",
        "stale-consumer",
        "missing-candidate",
        "global-payload",
        "parent",
    ],
)
def test_cross_object_inconsistency_is_refused(case: str) -> None:
    p = proposal()
    if case == "unknown-project":
        rebuild_memory(p, project_id="FOREIGN")
    elif case in {"prior-active", "paused", "non-git"}:
        old = p.previous.projects[0]
        if case == "prior-active":
            old = replace(old, memory_state="active")
        elif case == "paused":
            old = replace(old, lifecycle_state="paused")
        else:
            old = replace(old, target_kind="non-git-project")
        p.previous = ProjectRegistry.build(
            generated_at=p.previous.generated_at,
            previous_registry_sha256=None,
            authority=p.previous.authority,
            groups=p.previous.groups,
            projects=(old, p.previous.projects[1]),
            consumers=p.previous.consumers,
        )
        candidate = replace(
            p.cutover.candidate,
            previous_registry_sha256=p.previous.registry_sha256,
            projects=(replace(old, memory_state="active"), p.previous.projects[1]),
        )
        p.prior_outputs = build_registry_consumer_outputs(
            p.previous, {"global-boot": {"selector": "explicit"}}
        )
        rebuild_registry(p, candidate)
    elif case == "collateral-project":
        rebuild_registry(
            p,
            replace(
                p.cutover.candidate,
                projects=(
                    p.cutover.candidate.projects[0],
                    replace(p.cutover.candidate.projects[1], visibility="public"),
                ),
            ),
        )
    elif case == "collateral-group":
        rebuild_registry(
            p,
            replace(
                p.cutover.candidate,
                groups=(*p.cutover.candidate.groups, group("GROUP-B")),
                consumers=consumers(
                    p.cutover.candidate.projects, (*p.cutover.candidate.groups, group("GROUP-B"))
                )
                + tuple(c for c in p.cutover.candidate.consumers if c.kind == "boot-resolver"),
            ),
        )
    elif case == "collateral-consumer":
        rebuild_registry(
            p,
            replace(
                p.cutover.candidate,
                consumers=(
                    *p.cutover.candidate.consumers,
                    ProjectRegistryConsumer("other", "audit-selector", "other.json", None, None),
                ),
            ),
        )
    elif case == "memory-predecessor":
        rebuild_memory(p, previous_manifest_sha256="a" * 64)
    elif case == "supersession":
        rebuild_memory(p, records=(replace(p.memory.records[0], supersedes=("unknown-prior",)),))
    elif case in {"actor", "claim"}:
        actor = p.memory.records[0].actor
        actor = (
            replace(actor, identity="OTHER/worker")
            if case == "actor"
            else replace(actor, claim_id="other-claim")
        )
        rebuild_memory(p, records=(replace(p.memory.records[0], actor=actor),))
    elif case == "time":
        rebuild_memory(p, generated_at="2026-09-04T12:04:00.000000Z")
    elif case == "missing-prior":
        p.prior_outputs = p.prior_outputs[:-1]
    elif case == "duplicate-prior":
        p.prior_outputs += (p.prior_outputs[0],)
    elif case == "stale-registry":
        p.cutover = replace(p.cutover, expected_registry_sha256="a" * 64)
    elif case == "stale-consumer":
        p.cutover = replace(
            p.cutover,
            updates=(
                replace(p.cutover.updates[0], expected_sha256="a" * 64),
                *p.cutover.updates[1:],
            ),
        )
    elif case == "missing-candidate":
        p.cutover = replace(p.cutover, updates=p.cutover.updates[:-1])
    elif case == "global-payload":
        consumer = next(c for c in p.cutover.candidate.consumers if c.consumer_id == "global-boot")
        output = ProjectRegistryConsumerOutput.build(
            p.cutover.candidate, consumer, {"selector": "all"}
        )
        p.cutover = replace(
            p.cutover,
            updates=tuple(
                replace(u, output=output) if u.consumer_id == consumer.consumer_id else u
                for u in p.cutover.updates
            ),
        )
    elif case == "parent":
        rebuild_memory(
            p,
            parents=(
                replace(p.memory.parents[0], locator="../../FOREIGN.md"),
                *p.memory.parents[1:],
            ),
        )
    with pytest.raises((ValueError, RuntimeError)):
        p.check()


@pytest.mark.parametrize(
    "payload", [b"", b" " * 65537, b"[]", b"{}", b'{"schema_version":1,"schema_version":2}']
)
def test_unknown_bootstrap_is_never_treated_as_empty(payload: bytes) -> None:
    p = proposal()
    p.bootstrap = payload
    with pytest.raises(ValueError):
        p.check()


@pytest.mark.parametrize(
    "field,value",
    [
        ("project_id", "OTHER"),
        ("records", ["record"]),
        ("activation_state", "ACTIVE"),
        ("portfolio_id", "OTHER"),
    ],
)
def test_nonempty_or_foreign_bootstrap_refused(field: str, value: object) -> None:
    p = proposal()
    payload = json.loads(p.bootstrap)
    payload[field] = value
    p.bootstrap = json.dumps(payload).encode()
    with pytest.raises(ValueError):
        p.check()


@pytest.mark.parametrize(
    "payload", [b"", b" " * 16385, b"\xff\n", b"\x00\n", b"\xef\xbb\xbfindex\n", b"index"]
)
def test_unpreservable_index_is_refused(payload: bytes) -> None:
    p = proposal()
    p.index = payload
    with pytest.raises(ValueError):
        p.check()
