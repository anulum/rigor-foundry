# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory record and manifest tests
"""Verify canonical record, current-view, index and digest closure."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from test_deployment_profile import encode_profile, profile_document

from rigor_foundry.deployment_profile import DeploymentProfile
from rigor_foundry.project_memory_models import (
    ProjectMemoryManifest,
    ProjectMemoryRecord,
    project_memory_profile_parents,
)
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_PARENT_KINDS,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryInvalid,
    ProjectMemoryParent,
    ProjectMemorySource,
)


def parents() -> tuple[ProjectMemoryParent, ...]:
    """Return every required parent layer in canonical order."""
    locators = {
        "ecosystem-boot": "../../../AGENTS.md",
        "ecosystem-rules": "../../../agentic-shared/SHARED_CONTEXT.md",
        "ecosystem-memory": "../../../agentic-shared/memory/INDEX.md",
        "group-memory": "../../agentic_group_memory/memory_index.md",
        "project-sessions": "../../../.coordination/sessions/PROJECT/",
        "project-handovers": "../../../.coordination/handovers/PROJECT/",
        "vendor-memory": "../../../agentic-shared/memory/vendors/",
    }
    return tuple(
        ProjectMemoryParent.from_dict(
            {"kind": kind, "locator": locators[kind]},
            f"parents[{index}]",
        )
        for index, kind in enumerate(PROJECT_MEMORY_PARENT_KINDS)
    )


def record(
    record_id: str = "identity-0001",
    *,
    category: str = "identity",
    created_at: str = "2026-09-04T12:00:00.000000Z",
    observed_at: str = "2026-09-04T11:59:59.000000Z",
    freshness: ProjectMemoryFreshness | None = None,
    supersedes: tuple[str, ...] = (),
    content: bytes = b"# Project identity\n",
) -> ProjectMemoryRecord:
    """Build one exact admissible record fixture."""
    return ProjectMemoryRecord.for_content(
        record_id=record_id,
        category=category,
        created_at=created_at,
        observed_at=observed_at,
        freshness=freshness or ProjectMemoryFreshness("immutable", None),
        assertion_class="observation",
        sources=(ProjectMemorySource("source-1", "coordination/session.md", "a" * 64),),
        actor=ProjectMemoryActor("RIGOR-FOUNDRY/validator-1", "project-memory-write"),
        supersedes=supersedes,
        content=content,
    )


def manifest(*records: ProjectMemoryRecord) -> ProjectMemoryManifest:
    """Build one initial current-view fixture."""
    return ProjectMemoryManifest.build(
        project_id="PROJECT",
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_manifest_sha256=None,
        parents=parents(),
        records=tuple(sorted(records or (record(),), key=lambda item: item.record_id)),
    )


def profiled_manifest(
    base: ProjectMemoryManifest | None = None,
    *,
    root: str = "portfolios/SCIENCE",
    profile: DeploymentProfile | None = None,
) -> ProjectMemoryManifest:
    """Build a v2 memory using a real explicit alternative deployment layout."""
    base = manifest() if base is None else base
    profile = (
        DeploymentProfile.from_bytes(encode_profile(profile_document(root)))
        if profile is None
        else profile
    )
    return ProjectMemoryManifest.build(
        project_id=base.project_id,
        generated_at=base.generated_at,
        previous_manifest_sha256=base.previous_manifest_sha256,
        parents=project_memory_profile_parents(profile, "SCIENCE", base.project_id),
        records=base.records,
        profile=profile,
        group_id="SCIENCE",
    )


@pytest.mark.parametrize("root", ["portfolios/SCIENCE", "06_WEBMASTER"])
def test_profiled_memory_exact_index_and_roundtrip(root: str) -> None:
    current = profiled_manifest(root=root)
    assert ProjectMemoryManifest.from_bytes(current.to_bytes()) == current
    assert "`project-memory.v2`" in current.index_text()
    assert current.parents[0] == ProjectMemoryParent(
        "rules", "../" * (len(root.split("/")) + 3) + "policy/rules.md"
    )
    assert "agentic-shared" not in current.index_text()
    assert current.manifest_sha256 != manifest().manifest_sha256
    assert "deployment_profile" not in manifest().to_dict()


@pytest.mark.parametrize(
    "case",
    [
        "missing-profile",
        "legacy",
        "digest",
        "parents",
        "group",
        "missing-group",
        "parent-extra",
        "parent-order",
    ],
)
def test_profiled_memory_rejects_mixed_or_changed_bindings(case: str) -> None:
    data = json.loads(profiled_manifest().to_bytes())
    if case == "missing-profile":
        del data["deployment_profile"]
    elif case == "legacy":
        data["schema_version"] = "project-memory.v1"
    elif case == "digest":
        data["deployment_profile"]["profile_id"] = "changed"
    elif case == "parents":
        data["parents"][0]["locator"] = "../elsewhere.md"
    elif case == "group":
        data["group_id"] = "UNDECLARED"
    elif case == "missing-group":
        del data["group_id"]
    elif case == "parent-extra":
        data["parents"][0]["authority"] = True
    else:
        data["parents"].reverse()
    with pytest.raises(ProjectMemoryInvalid):
        ProjectMemoryManifest.from_bytes(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        )


@pytest.mark.parametrize("supersedes", [None, [f"record-{i:02d}" for i in range(17)]])
def test_record_rejects_unbounded_or_nonarray_supersession(supersedes: object) -> None:
    data = record().to_dict()
    data["supersedes"] = supersedes
    with pytest.raises(ProjectMemoryInvalid, match="supersedes count"):
        ProjectMemoryRecord.from_dict(data, "record")


def test_profiled_constructor_rejects_unbound_parents_and_group() -> None:
    current = profiled_manifest()
    for profile, group_id, selected_parents in (
        (None, "SCIENCE", parents()),
        (current.profile, None, current.parents),
        (current.profile, "SCIENCE", parents()),
    ):
        with pytest.raises(ProjectMemoryInvalid):
            ProjectMemoryManifest.build(
                project_id=current.project_id,
                generated_at=current.generated_at,
                previous_manifest_sha256=None,
                parents=selected_parents,
                records=current.records,
                profile=profile,
                group_id=group_id,
            )
    assert current.profile is not None
    with pytest.raises(ProjectMemoryInvalid, match="profile is invalid"):
        project_memory_profile_parents(
            replace(current.profile, profile_sha256="a" * 64), "SCIENCE", "PROJECT"
        )


def test_manifest_round_trip_is_canonical_and_content_addressed() -> None:
    """Canonical bytes, generated index and both digests close exactly."""
    candidate = manifest()
    payload = candidate.to_bytes()

    assert ProjectMemoryManifest.from_bytes(payload) == candidate
    assert (
        payload == json.dumps(candidate.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    )
    assert hashlib.sha256(candidate.index_text().encode()).hexdigest() == candidate.index_sha256
    unsigned = candidate.to_dict()
    unsigned.pop("manifest_sha256")
    canonical_unsigned = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical_unsigned).hexdigest() == candidate.manifest_sha256
    assert "../../../AGENTS.md" in candidate.index_text()
    assert "records/identity/identity-0001.md" in candidate.index_text()


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda value: value.update(schema_version="project-memory.v99"), "unsupported"),
        (lambda value: value.update(canonical_serializer="json"), "unsupported"),
        (lambda value: value.update(index_sha256="0" * 64), "index_sha256"),
        (lambda value: value.update(manifest_sha256="0" * 64), "manifest_sha256"),
        (lambda value: value.update(extra=True), "fields do not match"),
    ],
)
def test_manifest_rejects_version_digest_and_field_drift(
    mutate: object,
    message: str,
) -> None:
    """Unknown versions, changed closure and undeclared fields fail closed."""
    value = manifest().to_dict()
    assert callable(mutate)
    mutate(value)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ProjectMemoryInvalid, match=message):
        ProjectMemoryManifest.from_bytes(payload)


def test_manifest_rejects_noncanonical_bytes_and_duplicate_keys() -> None:
    """Equivalent pretty JSON and duplicate members are not accepted as JCS."""
    candidate = manifest()
    with pytest.raises(ProjectMemoryInvalid, match="not canonical"):
        ProjectMemoryManifest.from_bytes(json.dumps(candidate.to_dict(), indent=2).encode())
    duplicated = candidate.to_bytes().replace(
        b'{"canonical_serializer"', b'{"x":1,"x":2,"canonical_serializer"'
    )
    with pytest.raises(ProjectMemoryInvalid, match="duplicate keys"):
        ProjectMemoryManifest.from_bytes(duplicated)


def test_record_temporal_content_and_sensitivity_contracts() -> None:
    """Record identity binds path, bytes, digest, time, sources and sensitivity."""
    value = record().to_dict()
    value["content_path"] = "records/operations/identity-0001.md"
    with pytest.raises(ProjectMemoryInvalid, match="content_path"):
        ProjectMemoryRecord.from_dict(value, "record")

    value = record().to_dict()
    value["observed_at"] = "2026-09-04T12:00:01.000000Z"
    with pytest.raises(ProjectMemoryInvalid, match="must not follow"):
        ProjectMemoryRecord.from_dict(value, "record")

    value = record().to_dict()
    value["sensitivity"] = "MAXIMUM_SENSITIVITY"
    with pytest.raises(ProjectMemoryInvalid, match="not admissible"):
        ProjectMemoryRecord.from_dict(value, "record")

    value = record().to_dict()
    value["sources"] = [record().sources[0].to_dict()] * 2
    with pytest.raises(ProjectMemoryInvalid, match="sorted and unique"):
        ProjectMemoryRecord.from_dict(value, "record")


def test_manifest_requires_complete_parents_sorted_records_and_current_time() -> None:
    """Partial navigation, unordered identity and expired records never form a view."""
    item = record()
    with pytest.raises(ProjectMemoryInvalid, match="every canonical kind"):
        ProjectMemoryManifest.build(
            project_id="PROJECT",
            generated_at="2026-09-04T12:01:00.000000Z",
            previous_manifest_sha256=None,
            parents=parents()[:-1],
            records=(item,),
        )
    with pytest.raises(ProjectMemoryInvalid, match="sorted and unique"):
        ProjectMemoryManifest.build(
            project_id="PROJECT",
            generated_at="2026-09-04T12:01:00.000000Z",
            previous_manifest_sha256=None,
            parents=parents(),
            records=(record("z-record"), record("a-record")),
        )
    expired = record(freshness=ProjectMemoryFreshness("expires", "2026-09-04T12:00:30.000000Z"))
    with pytest.raises(ProjectMemoryInvalid, match="expired record"):
        manifest(expired)


def test_manifest_rejects_active_supersession_and_record_overflow() -> None:
    """A superseded identity cannot remain active and the 50-record cap is exact."""
    first = record("identity-0001")
    successor = record("identity-0002", supersedes=(first.record_id,))
    with pytest.raises(ProjectMemoryInvalid, match="another current record"):
        manifest(first, successor)

    records = tuple(record(f"identity-{index:04d}") for index in range(51))
    with pytest.raises(ProjectMemoryInvalid, match="record count"):
        manifest(*records)


def test_soft_rollover_is_advisory_but_hard_limit_is_enforced() -> None:
    """Content between 24 and 32 KiB is marked while content above 32 KiB fails."""
    large = record(content=b"# " + b"a" * 25000 + b"\n")
    assert large.exceeds_soft_content_limit
    with pytest.raises(ProjectMemoryInvalid, match="content_bytes"):
        record(content=b"# " + b"a" * 32768 + b"\n")


@pytest.mark.parametrize(
    "field, replacement, message",
    [
        ("category", "unknown", "category is unsupported"),
        ("assertion_class", "guess", "assertion_class is unsupported"),
        ("sources", [], "sources count"),
        ("supersedes", ["z", "a"], "supersedes must be sorted"),
        ("supersedes", ["identity-0001"], "cannot supersede itself"),
        ("content_bytes", True, "content_bytes is out of bounds"),
    ],
)
def test_record_schema_rejects_each_bounded_registry_failure(
    field: str,
    replacement: object,
    message: str,
) -> None:
    """Category, assertion, collection, self-edge and integer contracts are exact."""
    value = record().to_dict()
    value[field] = replacement
    with pytest.raises(ProjectMemoryInvalid, match=message):
        ProjectMemoryRecord.from_dict(value, "record")


def test_record_rejects_expiry_before_observation_and_future_creation() -> None:
    """Freshness and generation chronology cannot contradict observed time."""
    value = record().to_dict()
    value["freshness"] = {
        "policy": "expires",
        "valid_until": "2026-09-04T11:58:00.000000Z",
    }
    with pytest.raises(ProjectMemoryInvalid, match="must follow observed_at"):
        ProjectMemoryRecord.from_dict(value, "record")

    future = record(created_at="2026-09-04T12:02:00.000000Z")
    with pytest.raises(ProjectMemoryInvalid, match="created after"):
        manifest(future)


def test_manifest_parser_rejects_shape_generation_and_size_failures() -> None:
    """Array types, generation identity and the 64 KiB input cap are enforced."""
    candidate = manifest()
    for field, replacement, message in (
        ("parents", {}, "parents must be an array"),
        ("records", {}, "records must be an array"),
        ("generation_id", "bad", "generation_id is invalid"),
        ("generation_id", "20260904T120102000000Z", "does not match generated_at"),
    ):
        value = candidate.to_dict()
        value[field] = replacement
        if field not in {"parents", "records"}:
            unsigned = dict(value)
            unsigned.pop("manifest_sha256")
            value["manifest_sha256"] = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        with pytest.raises(ProjectMemoryInvalid, match=message):
            ProjectMemoryManifest.from_bytes(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            )
    with pytest.raises(ProjectMemoryInvalid, match="exceeds its byte bound"):
        ProjectMemoryManifest.from_bytes(b" " * 65537)


def test_manifest_byte_and_index_bounds_are_independently_enforced() -> None:
    """Large metadata and long current identities cannot bypass either view limit."""
    many_sources = tuple(
        ProjectMemorySource(f"source-{index:02d}", "x" * 1024, f"{index:064x}")
        for index in range(32)
    )
    records = tuple(
        ProjectMemoryRecord.for_content(
            record_id=f"record-{index:04d}",
            category="identity",
            created_at="2026-09-04T12:00:00.000000Z",
            observed_at="2026-09-04T11:59:00.000000Z",
            freshness=ProjectMemoryFreshness("immutable", None),
            assertion_class="observation",
            sources=many_sources,
            actor=ProjectMemoryActor("RIGOR-FOUNDRY/validator-1", "memory-write"),
            supersedes=(),
            content=b"# Record\n",
        )
        for index in range(2)
    )
    with pytest.raises(ProjectMemoryInvalid, match="manifest exceeds"):
        manifest(*records)

    long_records = tuple(
        record(f"r{index:02d}-" + "x" * 120, category="architecture-contracts")
        for index in range(50)
    )
    with pytest.raises(ProjectMemoryInvalid, match="index exceeds"):
        manifest(*long_records)
