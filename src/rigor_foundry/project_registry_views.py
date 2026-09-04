# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry consumer views
"""Generate digest-bound registry views and compare explicit group observations."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

from .project_registry_models import (
    PROJECT_REGISTRY_CONSUMER_KINDS,
    PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
    ProjectRegistration,
    ProjectRegistry,
    ProjectRegistryConsumer,
    ProjectRegistryInvalid,
)
from .project_registry_primitives import (
    _digest,
    _identifier,
    _mapping,
    _relative_path,
    _string,
    project_registry_canonical_json,
    project_registry_strict_json,
)

PROJECT_REGISTRY_CONSUMER_SCHEMA_VERSION = "gotm-project-registry-consumer.v1"
PROJECT_GROUP_VIEW_SCHEMA_VERSION = "gotm-project-group-view.v1"
PROJECT_MEMORY_REGISTRY_BINDING_SCHEMA_VERSION = "gotm-project-memory-registry-binding.v1"
_GENERATION_ID = re.compile(r"[0-9]{8}T[0-9]{12}Z")

_OUTPUT_FIELDS = frozenset(
    {
        "schema_version",
        "consumer_id",
        "consumer_kind",
        "target_path",
        "registry_generation_id",
        "registry_sha256",
        "payload",
        "output_sha256",
    }
)


@dataclass(frozen=True)
class ProjectRegistryConsumerOutput:
    """One canonical consumer document bound to one registry generation."""

    consumer_id: str
    consumer_kind: str
    target_path: str
    registry_generation_id: str
    registry_sha256: str
    payload: dict[str, object]
    output_sha256: str

    @classmethod
    def build(
        cls,
        registry: ProjectRegistry,
        consumer: ProjectRegistryConsumer,
        payload: Mapping[str, object],
    ) -> ProjectRegistryConsumerOutput:
        """Build one output for an exactly declared registry consumer."""
        if consumer not in registry.consumers:
            raise ProjectRegistryInvalid("consumer is not declared by the registry")
        value: dict[str, object] = {
            "schema_version": PROJECT_REGISTRY_CONSUMER_SCHEMA_VERSION,
            "consumer_id": consumer.consumer_id,
            "consumer_kind": consumer.kind,
            "target_path": consumer.path,
            "registry_generation_id": registry.generation_id,
            "registry_sha256": registry.registry_sha256,
            "payload": dict(payload),
        }
        value["output_sha256"] = hashlib.sha256(project_registry_canonical_json(value)).hexdigest()
        return cls.from_dict(value)

    @classmethod
    def from_dict(cls, value: object) -> ProjectRegistryConsumerOutput:
        """Parse and validate one exact consumer output."""
        data = _mapping(value, "consumer output")
        if set(data) != _OUTPUT_FIELDS:
            raise ProjectRegistryInvalid("consumer output fields do not match its schema")
        if data.get("schema_version") != PROJECT_REGISTRY_CONSUMER_SCHEMA_VERSION:
            raise ProjectRegistryInvalid("consumer output schema version is unsupported")
        consumer_id = _identifier(data.get("consumer_id"), "consumer_id")
        consumer_kind = _string(data.get("consumer_kind"), "consumer_kind", 32)
        if consumer_kind not in PROJECT_REGISTRY_CONSUMER_KINDS:
            raise ProjectRegistryInvalid("consumer output kind is unsupported")
        payload = _mapping(data.get("payload"), "consumer output.payload")
        generation_id = _string(data.get("registry_generation_id"), "registry_generation_id", 35)
        if _GENERATION_ID.fullmatch(generation_id) is None:
            raise ProjectRegistryInvalid("consumer output generation is malformed")
        registry_sha256 = _digest(data.get("registry_sha256"), "registry_sha256")
        output_sha256 = _digest(data.get("output_sha256"), "output_sha256")
        unsigned = {key: item for key, item in data.items() if key != "output_sha256"}
        expected = hashlib.sha256(project_registry_canonical_json(unsigned)).hexdigest()
        if output_sha256 != expected:
            raise ProjectRegistryInvalid("consumer output digest does not close")
        return cls(
            consumer_id=consumer_id,
            consumer_kind=consumer_kind,
            target_path=_relative_path(data.get("target_path"), "target_path"),
            registry_generation_id=generation_id,
            registry_sha256=registry_sha256,
            payload=payload,
            output_sha256=output_sha256,
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> ProjectRegistryConsumerOutput:
        """Parse canonical output bytes and enforce the consumer byte limit."""
        if not payload or len(payload) > PROJECT_REGISTRY_MAX_CONSUMER_BYTES:
            raise ProjectRegistryInvalid("consumer output byte count is out of bounds")
        output = cls.from_dict(project_registry_strict_json(payload))
        if output.to_bytes() != payload:
            raise ProjectRegistryInvalid("consumer output bytes are not canonical")
        return output

    def to_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        """Serialise this consumer output."""
        value: dict[str, object] = {
            "schema_version": PROJECT_REGISTRY_CONSUMER_SCHEMA_VERSION,
            "consumer_id": self.consumer_id,
            "consumer_kind": self.consumer_kind,
            "target_path": self.target_path,
            "registry_generation_id": self.registry_generation_id,
            "registry_sha256": self.registry_sha256,
            "payload": self.payload,
        }
        if include_digest:
            value["output_sha256"] = self.output_sha256
        return value

    def to_bytes(self) -> bytes:
        """Return exact canonical consumer bytes."""
        return project_registry_canonical_json(self.to_dict())


def _project_navigation(project: ProjectRegistration) -> dict[str, object]:
    return {
        "project_id": project.project_id,
        "canonical_path": project.canonical_path,
        "lifecycle_state": project.lifecycle_state,
        "visibility": project.visibility,
        "memory_state": project.memory_state,
    }


def build_group_view_output(
    registry: ProjectRegistry,
    consumer: ProjectRegistryConsumer,
) -> ProjectRegistryConsumerOutput:
    """Generate one group's deterministic ownership and affiliation view."""
    if consumer.kind != "group-view" or consumer.group_id is None:
        raise ProjectRegistryInvalid("consumer is not a scoped group view")
    owned = tuple(
        project for project in registry.projects if project.owning_group_id == consumer.group_id
    )
    affiliated = tuple(
        project for project in registry.projects if consumer.group_id in project.affiliations
    )
    payload: dict[str, object] = {
        "schema_version": PROJECT_GROUP_VIEW_SCHEMA_VERSION,
        "group_id": consumer.group_id,
        "owned_projects": [_project_navigation(project) for project in owned],
        "affiliated_projects": [_project_navigation(project) for project in affiliated],
    }
    return ProjectRegistryConsumerOutput.build(registry, consumer, payload)


def build_project_index_output(
    registry: ProjectRegistry,
    consumer: ProjectRegistryConsumer,
) -> ProjectRegistryConsumerOutput:
    """Generate one project's deterministic registry binding."""
    if consumer.kind != "project-index" or consumer.project_id is None:
        raise ProjectRegistryInvalid("consumer is not a scoped project index")
    project = next(
        (item for item in registry.projects if item.project_id == consumer.project_id),
        None,
    )
    if project is None:
        raise ProjectRegistryInvalid("project-index consumer project is absent")
    payload: dict[str, object] = {
        "schema_version": PROJECT_MEMORY_REGISTRY_BINDING_SCHEMA_VERSION,
        "project_id": project.project_id,
        "canonical_path": project.canonical_path,
        "owning_group_id": project.owning_group_id,
        "affiliations": list(project.affiliations),
        "memory_state": project.memory_state,
    }
    return ProjectRegistryConsumerOutput.build(registry, consumer, payload)


def build_registry_consumer_outputs(
    registry: ProjectRegistry,
    global_payloads: Mapping[str, Mapping[str, object]],
) -> tuple[ProjectRegistryConsumerOutput, ...]:
    """Build every declared consumer output or fail on an incomplete plan."""
    declared_global = {
        consumer.consumer_id
        for consumer in registry.consumers
        if consumer.kind not in {"group-view", "project-index"}
    }
    if set(global_payloads) != declared_global:
        raise ProjectRegistryInvalid("global consumer payloads do not match the registry graph")
    outputs: list[ProjectRegistryConsumerOutput] = []
    for consumer in registry.consumers:
        if consumer.kind == "group-view":
            output = build_group_view_output(registry, consumer)
        elif consumer.kind == "project-index":
            output = build_project_index_output(registry, consumer)
        else:
            output = ProjectRegistryConsumerOutput.build(
                registry,
                consumer,
                global_payloads[consumer.consumer_id],
            )
        outputs.append(output)
    return tuple(outputs)


@dataclass(frozen=True)
class ProjectRegistryGroupDrift:
    """One explicit consolidated group's path drift without inferred membership."""

    group_id: str
    missing_paths: tuple[str, ...]
    unexpected_paths: tuple[str, ...]

    @property
    def is_clean(self) -> bool:
        """Return whether the supplied observation matches registered paths."""
        return not self.missing_paths and not self.unexpected_paths


def compare_registered_group_paths(
    registry: ProjectRegistry,
    observed_paths_by_group: Mapping[str, tuple[str, ...]],
) -> tuple[ProjectRegistryGroupDrift, ...]:
    """Compare caller-supplied group observations without scanning other directories."""
    registered_groups = {group.group_id: group for group in registry.groups}
    if set(observed_paths_by_group) != set(registered_groups):
        raise ProjectRegistryInvalid("observed group set must exactly match the registry")
    expected_by_group: dict[str, set[str]] = {group_id: set() for group_id in registered_groups}
    for project in registry.projects:
        if (
            project.owning_group_id in expected_by_group
            and project.target_kind == "git-repository"
        ):
            expected_by_group[project.owning_group_id].add(project.canonical_path)
    results: list[ProjectRegistryGroupDrift] = []
    for group_id in sorted(registered_groups):
        group = registered_groups[group_id]
        observed = tuple(
            _relative_path(path, f"observed_paths_by_group[{group_id}]")
            for path in observed_paths_by_group[group_id]
        )
        if observed != tuple(sorted(observed)) or len(observed) != len(set(observed)):
            raise ProjectRegistryInvalid("observed group paths must be sorted and unique")
        prefix = f"{group.repositories_path}/"
        if any(not path.startswith(prefix) for path in observed):
            raise ProjectRegistryInvalid("observed path is outside its consolidated group")
        expected = expected_by_group[group_id]
        results.append(
            ProjectRegistryGroupDrift(
                group_id=group_id,
                missing_paths=tuple(sorted(expected - set(observed))),
                unexpected_paths=tuple(sorted(set(observed) - expected)),
            )
        )
    return tuple(results)


def validate_consumer_output_for_registry(
    registry: ProjectRegistry,
    output: ProjectRegistryConsumerOutput,
) -> ProjectRegistryConsumer:
    """Return the exact declaration matched by a digest-bound output."""
    consumer = next(
        (item for item in registry.consumers if item.consumer_id == output.consumer_id),
        None,
    )
    if consumer is None:
        raise ProjectRegistryInvalid("consumer output is not declared by the registry")
    if (
        output.consumer_kind != consumer.kind
        or output.target_path != consumer.path
        or output.registry_generation_id != registry.generation_id
        or output.registry_sha256 != registry.registry_sha256
    ):
        raise ProjectRegistryInvalid("consumer output does not match its registry declaration")
    reparsed = ProjectRegistryConsumerOutput.from_bytes(output.to_bytes())
    if reparsed != output:
        raise ProjectRegistryInvalid("consumer output is not canonical")
    return consumer
