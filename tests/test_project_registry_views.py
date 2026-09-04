# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry consumer-view tests
"""Exercise derived group/project outputs and explicit drift observations."""

from __future__ import annotations

import hashlib
import json

import pytest
from test_project_registry_models import authority, consumers, group, project

from rigor_foundry.project_registry_models import (
    PROJECT_REGISTRY_UNASSIGNED_GROUP,
    ProjectRegistration,
    ProjectRegistry,
    ProjectRegistryConsumer,
    ProjectRegistryInvalid,
    project_registry_canonical_json,
)
from rigor_foundry.project_registry_views import (
    PROJECT_GROUP_VIEW_SCHEMA_VERSION,
    PROJECT_MEMORY_REGISTRY_BINDING_SCHEMA_VERSION,
    ProjectRegistryConsumerOutput,
    build_group_view_output,
    build_project_index_output,
    build_registry_consumer_outputs,
    compare_registered_group_paths,
    validate_consumer_output_for_registry,
)


def registry_with_affiliation(*, include_global: bool = False) -> ProjectRegistry:
    """Return a two-group registry with one cross-group affiliation."""
    groups = (group("GROUP-A"), group("GROUP-B"))
    first = project("PROJECT-A", "GROUP-A")
    second_value = project("PROJECT-B", "GROUP-B").to_dict()
    second_value["affiliations"] = ["GROUP-A"]
    second = ProjectRegistration.from_dict(second_value, "project")
    declared = list(consumers((first, second), groups))
    if include_global:
        declared.append(
            ProjectRegistryConsumer.from_dict(
                {
                    "consumer_id": "boot-resolver",
                    "kind": "boot-resolver",
                    "path": "agentic-shared/memory/projects/registry_boot.json",
                    "group_id": None,
                    "project_id": None,
                },
                "consumer",
            )
        )
    return ProjectRegistry.build(
        generated_at="2026-09-04T12:00:00.000000Z",
        previous_registry_sha256=None,
        authority=authority(),
        groups=groups,
        projects=(first, second),
        consumers=tuple(sorted(declared, key=lambda item: item.consumer_id)),
    )


def test_group_view_separates_owned_and_affiliated_projects() -> None:
    """A group view distinguishes ownership from contract affiliation."""
    registry = registry_with_affiliation()
    consumer = next(
        item for item in registry.consumers if item.consumer_id == "group-view-GROUP-A"
    )
    output = build_group_view_output(registry, consumer)

    assert output.payload["schema_version"] == PROJECT_GROUP_VIEW_SCHEMA_VERSION
    assert [item["project_id"] for item in output.payload["owned_projects"]] == ["PROJECT-A"]
    assert [item["project_id"] for item in output.payload["affiliated_projects"]] == ["PROJECT-B"]
    assert ProjectRegistryConsumerOutput.from_bytes(output.to_bytes()) == output
    assert validate_consumer_output_for_registry(registry, output) == consumer
    assert "output_sha256" not in output.to_dict(include_digest=False)
    assert project_registry_canonical_json({"safe_integer": 1}) == b'{"safe_integer":1}'


def test_project_index_binds_only_registered_navigation_state() -> None:
    """Project binding output carries registry navigation without copied memory."""
    registry = registry_with_affiliation()
    consumer = next(
        item for item in registry.consumers if item.consumer_id == "project-index-PROJECT-B"
    )
    output = build_project_index_output(registry, consumer)

    assert output.payload == {
        "schema_version": PROJECT_MEMORY_REGISTRY_BINDING_SCHEMA_VERSION,
        "project_id": "PROJECT-B",
        "canonical_path": "03_CODE/GROUP-B/repositories/PROJECT-B",
        "owning_group_id": "GROUP-B",
        "affiliations": ["GROUP-A"],
        "memory_state": "scaffold-only",
    }


def test_complete_output_builder_requires_every_global_consumer() -> None:
    """The consumer graph cannot omit or invent a global resolver payload."""
    registry = registry_with_affiliation(include_global=True)
    with pytest.raises(ProjectRegistryInvalid, match="global consumer"):
        build_registry_consumer_outputs(registry, {})

    outputs = build_registry_consumer_outputs(
        registry,
        {"boot-resolver": {"schema_version": "gotm-project-boot-resolver.v1"}},
    )
    assert tuple(output.consumer_id for output in outputs) == tuple(
        consumer.consumer_id for consumer in registry.consumers
    )


def test_consumer_output_rejects_digest_and_registry_binding_drift() -> None:
    """A changed payload or registry digest is never accepted by a consumer."""
    registry = registry_with_affiliation()
    consumer = next(item for item in registry.consumers if item.kind == "group-view")
    output = build_group_view_output(registry, consumer)
    changed = output.to_dict()
    changed["output_sha256"] = "0" * 64
    with pytest.raises(ProjectRegistryInvalid, match="digest"):
        ProjectRegistryConsumerOutput.from_dict(changed)

    other = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=registry.registry_sha256,
        authority=authority(),
        groups=registry.groups,
        projects=registry.projects,
        consumers=registry.consumers,
    )
    with pytest.raises(ProjectRegistryInvalid, match="does not match"):
        validate_consumer_output_for_registry(other, output)


def test_explicit_group_drift_does_not_scan_unconsolidated_directories() -> None:
    """Only caller-supplied consolidated roots participate in drift evidence."""
    registry = registry_with_affiliation()
    drift = compare_registered_group_paths(
        registry,
        {
            "GROUP-A": (),
            "GROUP-B": (
                "03_CODE/GROUP-B/repositories/PROJECT-B",
                "03_CODE/GROUP-B/repositories/UNREGISTERED",
            ),
        },
    )
    by_group = {item.group_id: item for item in drift}
    assert by_group["GROUP-A"].missing_paths == ("03_CODE/GROUP-A/repositories/PROJECT-A",)
    assert by_group["GROUP-B"].unexpected_paths == ("03_CODE/GROUP-B/repositories/UNREGISTERED",)
    assert not by_group["GROUP-A"].is_clean


def test_drift_ignores_explicit_unassigned_non_git_projects() -> None:
    """Explicit non-group projects never become inferred group repository members."""
    group_record = group()
    unassigned_value = project(memory_state="absent").to_dict()
    unassigned_value.update(
        canonical_path="03_CODE/UNCONSOLIDATED/PROJECT-A",
        owning_group_id=PROJECT_REGISTRY_UNASSIGNED_GROUP,
        target_kind="non-git-project",
    )
    unassigned = ProjectRegistration.from_dict(unassigned_value, "project")
    registry = ProjectRegistry.build(
        generated_at="2026-09-04T12:00:00.000000Z",
        previous_registry_sha256=None,
        authority=authority(),
        groups=(group_record,),
        projects=(unassigned,),
        consumers=consumers((unassigned,), (group_record,)),
    )

    drift = compare_registered_group_paths(registry, {"GROUP-A": ()})

    assert drift[0].is_clean


@pytest.mark.parametrize(
    "observed",
    [
        {"GROUP-A": (), "GROUP-B": (), "OTHER": ()},
        {
            "GROUP-A": ("03_CODE/UNCONSOLIDATED/PROJECT-A",),
            "GROUP-B": (),
        },
        {
            "GROUP-A": (
                "03_CODE/GROUP-A/repositories/PROJECT-A",
                "03_CODE/GROUP-A/repositories/PROJECT-A",
            ),
            "GROUP-B": (),
        },
    ],
)
def test_drift_input_must_be_exact_bounded_and_unique(
    observed: dict[str, tuple[str, ...]],
) -> None:
    """Unknown groups, outside paths and duplicate observations fail closed."""
    with pytest.raises(ProjectRegistryInvalid):
        compare_registered_group_paths(registry_with_affiliation(), observed)


def test_view_builders_reject_the_wrong_consumer_scope() -> None:
    """Group and project generators cannot be called for another consumer kind."""
    registry = registry_with_affiliation()
    group_consumer = next(item for item in registry.consumers if item.kind == "group-view")
    project_consumer = next(item for item in registry.consumers if item.kind == "project-index")
    with pytest.raises(ProjectRegistryInvalid, match="group view"):
        build_group_view_output(registry, project_consumer)
    with pytest.raises(ProjectRegistryInvalid, match="project index"):
        build_project_index_output(registry, group_consumer)


def test_consumer_output_rejects_schema_kind_generation_and_encoding_drift() -> None:
    """Consumer envelopes are exact, bounded and canonically encoded."""
    registry = registry_with_affiliation()
    output = build_registry_consumer_outputs(registry, {})[0]

    cases = (
        ({**output.to_dict(), "extra": True}, "fields"),
        ({**output.to_dict(), "schema_version": "v2"}, "version"),
        ({**output.to_dict(), "consumer_kind": "unknown"}, "kind"),
        ({**output.to_dict(), "registry_generation_id": "bad"}, "generation"),
    )
    for value, match in cases:
        unsigned = {key: item for key, item in value.items() if key != "output_sha256"}
        value["output_sha256"] = hashlib.sha256(
            project_registry_canonical_json(unsigned)
        ).hexdigest()
        with pytest.raises(ProjectRegistryInvalid, match=match):
            ProjectRegistryConsumerOutput.from_dict(value)

    with pytest.raises(ProjectRegistryInvalid, match="byte count"):
        ProjectRegistryConsumerOutput.from_bytes(b"")
    pretty = json.dumps(output.to_dict(), indent=2).encode()
    with pytest.raises(ProjectRegistryInvalid, match="not canonical"):
        ProjectRegistryConsumerOutput.from_bytes(pretty)


def test_build_and_validate_reject_undeclared_consumer_identity() -> None:
    """An otherwise shaped output cannot escape the registry consumer graph."""
    registry = registry_with_affiliation()
    undeclared = ProjectRegistryConsumer.from_dict(
        {
            "consumer_id": "group-view-UNDECLARED",
            "kind": "group-view",
            "path": "03_CODE/GROUP-A/agentic_group_memory/registry_view.json",
            "group_id": "GROUP-A",
            "project_id": None,
        },
        "consumer",
    )
    with pytest.raises(ProjectRegistryInvalid, match="not declared"):
        ProjectRegistryConsumerOutput.build(registry, undeclared, {})

    output = build_registry_consumer_outputs(registry, {})[0]
    changed = output.to_dict()
    changed["consumer_id"] = "undeclared-output"
    unsigned = {key: item for key, item in changed.items() if key != "output_sha256"}
    changed["output_sha256"] = hashlib.sha256(
        project_registry_canonical_json(unsigned)
    ).hexdigest()
    with pytest.raises(ProjectRegistryInvalid, match="not declared"):
        validate_consumer_output_for_registry(
            registry,
            ProjectRegistryConsumerOutput.from_dict(changed),
        )


def test_project_index_rejects_absent_project_and_clean_drift_is_explicit() -> None:
    """Consumer generation and drift evidence never infer missing identities."""
    registry = registry_with_affiliation()
    absent = ProjectRegistryConsumer.from_dict(
        {
            "consumer_id": "project-index-MISSING",
            "kind": "project-index",
            "path": "03_CODE/GROUP-A/repositories/MISSING/agentic_project_memory/registry_binding.json",
            "group_id": None,
            "project_id": "MISSING",
        },
        "consumer",
    )
    with pytest.raises(ProjectRegistryInvalid, match="project is absent"):
        build_project_index_output(registry, absent)

    drift = compare_registered_group_paths(
        registry,
        {
            "GROUP-A": ("03_CODE/GROUP-A/repositories/PROJECT-A",),
            "GROUP-B": ("03_CODE/GROUP-B/repositories/PROJECT-B",),
        },
    )
    assert all(item.is_clean for item in drift)
