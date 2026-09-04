# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry model tests
"""Exercise canonical registry identity, bounds and cross-record invariants."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

import rigor_foundry.project_registry_models as registry_models
from rigor_foundry.project_registry_models import (
    PROJECT_REGISTRY_SCHEMA_VERSION,
    ProjectRegistration,
    ProjectRegistry,
    ProjectRegistryAlias,
    ProjectRegistryAuthority,
    ProjectRegistryConsumer,
    ProjectRegistryGroup,
    ProjectRegistryInvalid,
    project_registry_canonical_json,
    project_registry_generation_id,
    project_registry_strict_json,
)


def authority() -> ProjectRegistryAuthority:
    """Return a fixed evidence-bound authority fixture."""
    return ProjectRegistryAuthority.from_dict(
        {
            "owner_id": "Miroslav Sotek",
            "approved_at": "2026-09-04T11:30:00.000000Z",
            "approval_reference": "coordination/owner-decision.md",
            "approval_sha256": "a" * 64,
            "validator_identity": "RIGOR-FOUNDRY/codex-7184",
            "validation_claim_id": "registry-contract",
        }
    )


def group(group_id: str = "GROUP-A") -> ProjectRegistryGroup:
    """Return one exact portfolio group fixture."""
    return ProjectRegistryGroup.from_dict(
        {
            "group_id": group_id,
            "root_path": f"03_CODE/{group_id}",
            "repositories_path": f"03_CODE/{group_id}/repositories",
            "memory_index_path": f"03_CODE/{group_id}/agentic_group_memory/memory_index.md",
            "lifecycle_state": "active",
        },
        "group",
    )


def project(
    project_id: str = "PROJECT-A",
    group_id: str = "GROUP-A",
    *,
    memory_state: str = "scaffold-only",
    aliases: tuple[ProjectRegistryAlias, ...] = (),
) -> ProjectRegistration:
    """Return one registered Git project fixture."""
    return ProjectRegistration.from_dict(
        {
            "project_id": project_id,
            "canonical_path": f"03_CODE/{group_id}/repositories/{project_id}",
            "owning_group_id": group_id,
            "affiliations": [],
            "target_kind": "git-repository",
            "lifecycle_state": "active",
            "visibility": "private",
            "memory_state": memory_state,
            "aliases": [alias.to_dict() for alias in aliases],
        },
        "project",
    )


def consumers(
    projects: tuple[ProjectRegistration, ...],
    groups: tuple[ProjectRegistryGroup, ...],
) -> tuple[ProjectRegistryConsumer, ...]:
    """Return the required deterministic group and project consumers."""
    values: list[ProjectRegistryConsumer] = []
    for item in groups:
        values.append(
            ProjectRegistryConsumer.from_dict(
                {
                    "consumer_id": f"group-view-{item.group_id}",
                    "kind": "group-view",
                    "path": f"{item.root_path}/agentic_group_memory/registry_view.json",
                    "group_id": item.group_id,
                    "project_id": None,
                },
                "consumer",
            )
        )
    for item in projects:
        if item.memory_state != "absent":
            values.append(
                ProjectRegistryConsumer.from_dict(
                    {
                        "consumer_id": f"project-index-{item.project_id}",
                        "kind": "project-index",
                        "path": f"{item.canonical_path}/agentic_project_memory/registry_binding.json",
                        "group_id": None,
                        "project_id": item.project_id,
                    },
                    "consumer",
                )
            )
    return tuple(sorted(values, key=lambda item: item.consumer_id))


def registry(
    *,
    groups: tuple[ProjectRegistryGroup, ...] | None = None,
    projects: tuple[ProjectRegistration, ...] | None = None,
    generated_at: str = "2026-09-04T12:00:00.000000Z",
    previous: str | None = None,
) -> ProjectRegistry:
    """Build one closed registry fixture."""
    selected_groups = (group(),) if groups is None else groups
    selected_projects = (project(),) if projects is None else projects
    return ProjectRegistry.build(
        generated_at=generated_at,
        previous_registry_sha256=previous,
        authority=authority(),
        groups=selected_groups,
        projects=selected_projects,
        consumers=consumers(selected_projects, selected_groups),
    )


def resign(value: dict[str, object]) -> dict[str, object]:
    """Recompute the registry closure after an intentional test mutation."""
    unsigned = {key: item for key, item in value.items() if key != "registry_sha256"}
    import hashlib

    value["registry_sha256"] = hashlib.sha256(
        project_registry_canonical_json(unsigned)
    ).hexdigest()
    return value


def test_registry_round_trip_is_canonical_and_content_addressed() -> None:
    """Exact canonical bytes preserve every independent project state."""
    candidate = registry()
    parsed = ProjectRegistry.from_bytes(candidate.to_bytes())

    assert parsed == candidate
    assert parsed.to_dict()["schema_version"] == PROJECT_REGISTRY_SCHEMA_VERSION
    assert parsed.projects[0].lifecycle_state == "active"
    assert parsed.projects[0].visibility == "private"
    assert parsed.projects[0].memory_state == "scaffold-only"
    assert project_registry_generation_id(parsed.generated_at) == parsed.generation_id
    assert "registry_sha256" not in parsed.to_dict(include_digest=False)


def test_registry_enforces_final_canonical_byte_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """The aggregate registry bound applies after every bounded record is parsed."""
    candidate = registry()
    monkeypatch.setattr(registry_models, "PROJECT_REGISTRY_MAX_BYTES", 1)
    with pytest.raises(ProjectRegistryInvalid, match="exceeds its byte bound"):
        ProjectRegistry.from_dict(candidate.to_dict())


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(schema_version="gotm-project-registry.v2"), "version"),
        (lambda value: value.update(extra=True), "fields"),
        (lambda value: value.update(registry_sha256="0" * 64), "digest"),
        (lambda value: value["groups"].append(value["groups"][0]), "sorted"),
        (lambda value: value.update(generated_at="2026-09-04T12:00:00Z"), "microsecond"),
    ],
)
def test_registry_rejects_schema_identity_and_digest_drift(
    mutation: object,
    match: str,
) -> None:
    """Schema additions, duplicate identities and digest changes fail closed."""
    value = registry().to_dict()
    callable_mutation = mutation
    assert callable(callable_mutation)
    callable_mutation(value)
    with pytest.raises(ProjectRegistryInvalid, match=match):
        ProjectRegistry.from_dict(value)


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}'])
def test_strict_json_rejects_duplicate_and_non_integer_numbers(payload: bytes) -> None:
    """Registry JSON cannot exploit duplicate keys, floats or non-finite values."""
    with pytest.raises(ProjectRegistryInvalid):
        project_registry_strict_json(payload)


def test_registry_rejects_noncanonical_json_encoding() -> None:
    """Semantically equivalent pretty JSON is not an accepted registry object."""
    payload = json.dumps(registry().to_dict(), indent=2).encode()
    with pytest.raises(ProjectRegistryInvalid, match="not canonical"):
        ProjectRegistry.from_bytes(payload)


def test_unassigned_project_requires_absent_memory() -> None:
    """An unassigned project cannot silently activate repo-local memory."""
    value = project().to_dict()
    value["owning_group_id"] = "UNASSIGNED"
    value["canonical_path"] = "03_CODE/OTHER/PROJECT-A"
    with pytest.raises(ProjectRegistryInvalid, match="unassigned"):
        ProjectRegistration.from_dict(value, "project")


def test_registered_git_path_must_match_owning_group() -> None:
    """A directory elsewhere in 03_CODE cannot become an implicit group member."""
    misplaced = project().to_dict()
    misplaced["canonical_path"] = "03_CODE/UNCONSOLIDATED/PROJECT-A"
    misplaced_project = ProjectRegistration.from_dict(misplaced, "project")
    with pytest.raises(ProjectRegistryInvalid, match="owning group"):
        registry(projects=(misplaced_project,))


def test_active_group_and_scaffold_project_require_exact_consumers() -> None:
    """A registry without its group or project view cannot close its digest graph."""
    value = registry().to_dict()
    value["consumers"] = value["consumers"][:1]
    unsigned = {key: item for key, item in value.items() if key != "registry_sha256"}
    import hashlib

    value["registry_sha256"] = hashlib.sha256(
        project_registry_canonical_json(unsigned)
    ).hexdigest()
    with pytest.raises(ProjectRegistryInvalid, match="project-index"):
        ProjectRegistry.from_dict(value)


def test_aliases_are_temporal_sorted_and_distinct_from_current_path() -> None:
    """Historical aliases retain bounded source and temporal evidence."""
    alias = ProjectRegistryAlias.from_dict(
        {
            "path": "03_CODE/PROJECT-A",
            "valid_from": "2026-01-01T00:00:00.000000Z",
            "retired_at": "2026-09-01T00:00:00.000000Z",
            "source_sha256": "b" * 64,
        },
        "alias",
    )
    candidate = registry(projects=(project(aliases=(alias,)),))
    assert candidate.projects[0].aliases == (alias,)
    invalid = alias.to_dict()
    invalid["retired_at"] = invalid["valid_from"]
    with pytest.raises(ProjectRegistryInvalid, match="follow"):
        ProjectRegistryAlias.from_dict(invalid, "alias")


def test_canonical_value_rejects_non_ascii_metadata() -> None:
    """The bounded registry profile excludes ambiguous non-ASCII metadata."""
    with pytest.raises(ProjectRegistryInvalid, match="ASCII"):
        project_registry_canonical_json({"owner": "Šotek"})


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(owner_id=""), "printable ASCII"),
        (lambda value: value.update(validator_identity="bad identity"), "portable identity"),
        (lambda value: value.update(approval_sha256="A" * 64), "lowercase SHA-256"),
        (
            lambda value: value.update(approved_at="2026-02-31T00:00:00.000000Z"),
            "calendar timestamp",
        ),
        (lambda value: value.update(validation_claim_id="bad/claim"), "portable identifier"),
        (lambda value: value.update(extra="field"), "fields"),
    ],
)
def test_authority_rejects_ambiguous_or_unbounded_identity(
    mutation: Callable[[dict[str, object]], None],
    match: str,
) -> None:
    """Approval evidence has an exact, portable and digest-bound shape."""
    value = authority().to_dict()
    mutation(value)
    with pytest.raises(ProjectRegistryInvalid, match=match):
        ProjectRegistryAuthority.from_dict(value)


@pytest.mark.parametrize(
    ("field", "replacement", "match"),
    [
        ("root_path", "03_CODE/WRONG", "root_path"),
        ("repositories_path", "03_CODE/GROUP-A/repos", "repositories_path"),
        ("memory_index_path", "03_CODE/GROUP-A/memory.md", "memory_index_path"),
        ("lifecycle_state", "unknown", "lifecycle_state"),
    ],
)
def test_group_paths_are_derived_from_stable_identity(
    field: str,
    replacement: str,
    match: str,
) -> None:
    """A group declaration cannot redirect consumers into another tree."""
    value = group().to_dict()
    value[field] = replacement
    with pytest.raises(ProjectRegistryInvalid, match=match):
        ProjectRegistryGroup.from_dict(value, "group")


@pytest.mark.parametrize(
    ("field", "replacement", "match"),
    [
        ("target_kind", "directory", "target_kind"),
        ("lifecycle_state", "deleted", "lifecycle_state"),
        ("visibility", "secret", "visibility"),
        ("memory_state", "implicit", "memory_state"),
        ("affiliations", "GROUP-B", "array"),
        ("aliases", "old-path", "count"),
    ],
)
def test_project_enums_and_collections_are_closed(
    field: str,
    replacement: object,
    match: str,
) -> None:
    """Independent project states use only exact v1 vocabulary and arrays."""
    value = project().to_dict()
    value[field] = replacement
    with pytest.raises(ProjectRegistryInvalid, match=match):
        ProjectRegistration.from_dict(value, "project")


def test_project_affiliations_aliases_and_retirement_are_consistent() -> None:
    """Affiliations and permanent aliases are ordered and cannot self-conflict."""
    value = project().to_dict()
    value["affiliations"] = ["GROUP-C", "GROUP-B"]
    with pytest.raises(ProjectRegistryInvalid, match="sorted and unique"):
        ProjectRegistration.from_dict(value, "project")

    alias = {
        "path": "03_CODE/OLD/PROJECT-A",
        "valid_from": "2026-01-01T00:00:00.000000Z",
        "retired_at": "2026-08-01T00:00:00.000000Z",
        "source_sha256": "b" * 64,
    }
    value = project().to_dict()
    value["aliases"] = [alias, alias]
    with pytest.raises(ProjectRegistryInvalid, match="path-unique"):
        ProjectRegistration.from_dict(value, "project")

    value = project().to_dict()
    alias["path"] = value["canonical_path"]
    value["aliases"] = [alias]
    with pytest.raises(ProjectRegistryInvalid, match="cannot also be an alias"):
        ProjectRegistration.from_dict(value, "project")

    value = project().to_dict()
    value.update(lifecycle_state="retired", memory_state="active")
    with pytest.raises(ProjectRegistryInvalid, match="retired"):
        ProjectRegistration.from_dict(value, "project")


@pytest.mark.parametrize(
    ("kind", "group_id", "project_id", "match"),
    [
        ("unknown", None, None, "kind"),
        ("group-view", None, None, "group-view scope"),
        ("project-index", None, None, "project-index scope"),
        ("boot-resolver", "GROUP-A", None, "global consumer"),
    ],
)
def test_consumer_scope_matches_its_kind(
    kind: str,
    group_id: str | None,
    project_id: str | None,
    match: str,
) -> None:
    """Global, group and project consumers cannot borrow each other's scope."""
    value = {
        "consumer_id": "consumer-a",
        "kind": kind,
        "path": "agentic-shared/consumer.json",
        "group_id": group_id,
        "project_id": project_id,
    }
    with pytest.raises(ProjectRegistryInvalid, match=match):
        ProjectRegistryConsumer.from_dict(value, "consumer")


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(canonical_serializer="other"), "serializer"),
        (lambda value: value.update(generation_id="bad"), "generation_id"),
        (
            lambda value: value.update(generation_id="20260904T120001000000Z"),
            "does not match",
        ),
        (
            lambda value: value["authority"].update(approved_at="2026-09-04T12:00:01.000000Z"),
            "approval cannot follow",
        ),
        (lambda value: value.update(groups=[]), "count"),
        (lambda value: value.update(projects=[]), "count"),
        (lambda value: value.update(consumers=[]), "count"),
    ],
)
def test_registry_rejects_invalid_generation_and_empty_graphs(
    mutation: Callable[[dict[str, object]], None],
    match: str,
) -> None:
    """Generation metadata and each required graph collection fail closed."""
    value = registry().to_dict()
    mutation(value)
    resign(value)
    with pytest.raises(ProjectRegistryInvalid, match=match):
        ProjectRegistry.from_dict(value)


def test_registry_rejects_unknown_relationships_and_path_collisions() -> None:
    """Only explicit groups and globally unique paths can form membership."""
    value = registry().to_dict()
    value["projects"][0]["owning_group_id"] = "GROUP-X"
    resign(value)
    with pytest.raises(ProjectRegistryInvalid, match="owning group"):
        ProjectRegistry.from_dict(value)

    value = registry().to_dict()
    value["projects"][0]["affiliations"] = ["GROUP-X"]
    resign(value)
    with pytest.raises(ProjectRegistryInvalid, match="unknown group"):
        ProjectRegistry.from_dict(value)

    groups = (group("GROUP-A"), group("GROUP-B"))
    affiliated = project().to_dict()
    affiliated["affiliations"] = ["GROUP-A"]
    affiliated_project = ProjectRegistration.from_dict(affiliated, "project")
    with pytest.raises(ProjectRegistryInvalid, match="duplicates its owning group"):
        registry(groups=groups, projects=(affiliated_project,))

    alias = ProjectRegistryAlias.from_dict(
        {
            "path": project().canonical_path,
            "valid_from": "2026-01-01T00:00:00.000000Z",
            "retired_at": "2026-08-01T00:00:00.000000Z",
            "source_sha256": "b" * 64,
        },
        "alias",
    )
    duplicate_path = project("PROJECT-B", aliases=(alias,))
    with pytest.raises(ProjectRegistryInvalid, match="globally unique"):
        registry(projects=(project(), duplicate_path))


def test_registry_rejects_consumer_collisions_and_wrong_targets() -> None:
    """Consumer identity and output paths are exact parts of the closed graph."""
    base = registry().to_dict()
    cases: list[tuple[Callable[[dict[str, object]], None], str]] = [
        (
            lambda value: value["consumers"][1].update(path=value["consumers"][0]["path"]),
            "paths must be unique",
        ),
        (
            lambda value: value["consumers"][0].update(group_id="GROUP-X"),
            "unknown group",
        ),
        (
            lambda value: value["consumers"][0].update(
                path="03_CODE/GROUP-A/agentic_group_memory/wrong.json"
            ),
            "does not match group",
        ),
        (
            lambda value: value["consumers"][1].update(project_id="PROJECT-X"),
            "unknown project",
        ),
        (
            lambda value: value["consumers"][1].update(
                path="03_CODE/GROUP-A/repositories/PROJECT-A/wrong.json"
            ),
            "does not match project",
        ),
    ]
    for mutation, match in cases:
        value = json.loads(json.dumps(base))
        mutation(value)
        resign(value)
        with pytest.raises(ProjectRegistryInvalid, match=match):
            ProjectRegistry.from_dict(value)


def test_registry_rejects_future_alias_and_invalid_byte_profiles() -> None:
    """Alias history cannot postdate its generation and bytes stay bounded/canonical."""
    alias = ProjectRegistryAlias.from_dict(
        {
            "path": "03_CODE/OLD/PROJECT-A",
            "valid_from": "2026-09-01T00:00:00.000000Z",
            "retired_at": "2026-09-05T00:00:00.000000Z",
            "source_sha256": "b" * 64,
        },
        "alias",
    )
    with pytest.raises(ProjectRegistryInvalid, match="cannot retire after"):
        registry(projects=(project(aliases=(alias,)),))
    with pytest.raises(ProjectRegistryInvalid, match="byte count"):
        ProjectRegistry.from_bytes(b"")
    with pytest.raises(ProjectRegistryInvalid, match="strict UTF-8"):
        ProjectRegistry.from_bytes(b"\xff")
    with pytest.raises(ProjectRegistryInvalid, match="JCS bound"):
        project_registry_canonical_json({"value": 2**53})
    with pytest.raises(ProjectRegistryInvalid, match="no-float"):
        project_registry_canonical_json({"value": 1.5})


def test_registry_requires_object_and_every_active_group_view() -> None:
    """Non-object input and a missing active-group consumer both fail closed."""
    with pytest.raises(ProjectRegistryInvalid, match="must be an object"):
        ProjectRegistry.from_dict([])

    value = registry().to_dict()
    value["consumers"] = value["consumers"][1:]
    resign(value)
    with pytest.raises(ProjectRegistryInvalid, match="active group"):
        ProjectRegistry.from_dict(value)


def test_explicit_unassigned_project_remains_memory_absent() -> None:
    """UNASSIGNED is explicit registry state, never inferred from 03_CODE discovery."""
    value = project(memory_state="absent").to_dict()
    value["owning_group_id"] = "UNASSIGNED"
    value["canonical_path"] = "03_CODE/UNCONSOLIDATED/PROJECT-A"
    unassigned = ProjectRegistration.from_dict(value, "project")
    candidate = registry(projects=(unassigned,))
    assert candidate.projects[0].owning_group_id == "UNASSIGNED"
    assert all(consumer.kind != "project-index" for consumer in candidate.consumers)
