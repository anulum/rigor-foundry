# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical project registry contracts
"""Define the content-addressed GOTM project registry contract."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar, cast

from .project_registry_primitives import (
    _GENERATION_ID,
    _digest,
    _exact_fields,
    _identifier,
    _identity,
    _mapping,
    _relative_path,
    _string,
    _timestamp,
    project_registry_canonical_json,
    project_registry_generation_id,
    project_registry_strict_json,
)
from .project_registry_primitives import (
    ProjectRegistryInvalid as ProjectRegistryInvalid,
)

PROJECT_REGISTRY_SCHEMA_VERSION = "gotm-project-registry.v1"
PROJECT_REGISTRY_SERIALIZER = "RFC8785-JCS"
PROJECT_REGISTRY_UNASSIGNED_GROUP = "UNASSIGNED"
PROJECT_REGISTRY_MAX_BYTES = 2 * 1024 * 1024
PROJECT_REGISTRY_MAX_GROUPS = 32
PROJECT_REGISTRY_MAX_PROJECTS = 256
PROJECT_REGISTRY_MAX_CONSUMERS = 2_048
PROJECT_REGISTRY_MAX_ALIASES = 64
PROJECT_REGISTRY_MAX_CONSUMER_BYTES = 256 * 1024

PROJECT_REGISTRY_GROUP_LIFECYCLES = ("active", "retired")
PROJECT_REGISTRY_PROJECT_LIFECYCLES = (
    "active",
    "architecture-only",
    "paused",
    "retired",
)
PROJECT_REGISTRY_VISIBILITIES = ("local-only", "private", "public", "unverified")
PROJECT_REGISTRY_MEMORY_STATES = ("absent", "active", "scaffold-only")
PROJECT_REGISTRY_TARGET_KINDS = ("git-repository", "non-git-project")
PROJECT_REGISTRY_CONSUMER_KINDS = (
    "audit-selector",
    "backup-selector",
    "boot-resolver",
    "coordination-resolver",
    "group-view",
    "project-index",
)

_RegistryItem = TypeVar("_RegistryItem")


@dataclass(frozen=True)
class ProjectRegistryAuthority:
    """Owner approval and RIGOR validation bound to one generation."""

    owner_id: str
    approved_at: str
    approval_reference: str
    approval_sha256: str
    validator_identity: str
    validation_claim_id: str

    @classmethod
    def from_dict(cls, value: object, field: str = "authority") -> ProjectRegistryAuthority:
        """Parse one exact registry authority object."""
        data = _mapping(value, field)
        _exact_fields(
            data,
            frozenset(
                {
                    "owner_id",
                    "approved_at",
                    "approval_reference",
                    "approval_sha256",
                    "validator_identity",
                    "validation_claim_id",
                }
            ),
            field,
        )
        approved_at, _ = _timestamp(data.get("approved_at"), f"{field}.approved_at")
        return cls(
            owner_id=_string(data.get("owner_id"), f"{field}.owner_id", 128),
            approved_at=approved_at,
            approval_reference=_string(
                data.get("approval_reference"), f"{field}.approval_reference", 1024
            ),
            approval_sha256=_digest(data.get("approval_sha256"), f"{field}.approval_sha256"),
            validator_identity=_identity(
                data.get("validator_identity"), f"{field}.validator_identity"
            ),
            validation_claim_id=_identifier(
                data.get("validation_claim_id"), f"{field}.validation_claim_id"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise this authority object."""
        return {
            "owner_id": self.owner_id,
            "approved_at": self.approved_at,
            "approval_reference": self.approval_reference,
            "approval_sha256": self.approval_sha256,
            "validator_identity": self.validator_identity,
            "validation_claim_id": self.validation_claim_id,
        }


@dataclass(frozen=True)
class ProjectRegistryAlias:
    """One permanently retained former canonical project path."""

    path: str
    valid_from: str
    retired_at: str
    source_sha256: str

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectRegistryAlias:
        """Parse one historical path alias."""
        data = _mapping(value, field)
        _exact_fields(
            data,
            frozenset({"path", "valid_from", "retired_at", "source_sha256"}),
            field,
        )
        valid_from, start = _timestamp(data.get("valid_from"), f"{field}.valid_from")
        retired_at, end = _timestamp(data.get("retired_at"), f"{field}.retired_at")
        if end <= start:
            raise ProjectRegistryInvalid(f"{field}.retired_at must follow valid_from")
        return cls(
            path=_relative_path(data.get("path"), f"{field}.path"),
            valid_from=valid_from,
            retired_at=retired_at,
            source_sha256=_digest(data.get("source_sha256"), f"{field}.source_sha256"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise this historical alias."""
        return {
            "path": self.path,
            "valid_from": self.valid_from,
            "retired_at": self.retired_at,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class ProjectRegistryGroup:
    """One non-Git portfolio group and its memory navigation paths."""

    group_id: str
    root_path: str
    repositories_path: str
    memory_index_path: str
    lifecycle_state: str

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectRegistryGroup:
        """Parse and validate one group record."""
        data = _mapping(value, field)
        _exact_fields(
            data,
            frozenset(
                {
                    "group_id",
                    "root_path",
                    "repositories_path",
                    "memory_index_path",
                    "lifecycle_state",
                }
            ),
            field,
        )
        group_id = _identifier(data.get("group_id"), f"{field}.group_id")
        root_path = _relative_path(data.get("root_path"), f"{field}.root_path")
        repositories_path = _relative_path(
            data.get("repositories_path"), f"{field}.repositories_path"
        )
        memory_index_path = _relative_path(
            data.get("memory_index_path"), f"{field}.memory_index_path"
        )
        if root_path != f"03_CODE/{group_id}":
            raise ProjectRegistryInvalid(f"{field}.root_path does not match group identity")
        if repositories_path != f"{root_path}/repositories":
            raise ProjectRegistryInvalid(f"{field}.repositories_path does not match group root")
        if memory_index_path != f"{root_path}/agentic_group_memory/memory_index.md":
            raise ProjectRegistryInvalid(f"{field}.memory_index_path does not match group root")
        lifecycle = _string(data.get("lifecycle_state"), f"{field}.lifecycle_state", 32)
        if lifecycle not in PROJECT_REGISTRY_GROUP_LIFECYCLES:
            raise ProjectRegistryInvalid(f"{field}.lifecycle_state is unsupported")
        return cls(group_id, root_path, repositories_path, memory_index_path, lifecycle)

    def to_dict(self) -> dict[str, object]:
        """Serialise this group record."""
        return {
            "group_id": self.group_id,
            "root_path": self.root_path,
            "repositories_path": self.repositories_path,
            "memory_index_path": self.memory_index_path,
            "lifecycle_state": self.lifecycle_state,
        }


@dataclass(frozen=True)
class ProjectRegistration:
    """One stable project identity and its independent operational states."""

    project_id: str
    canonical_path: str
    owning_group_id: str
    affiliations: tuple[str, ...]
    target_kind: str
    lifecycle_state: str
    visibility: str
    memory_state: str
    aliases: tuple[ProjectRegistryAlias, ...]

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectRegistration:
        """Parse one project registration without resolving group references."""
        data = _mapping(value, field)
        _exact_fields(
            data,
            frozenset(
                {
                    "project_id",
                    "canonical_path",
                    "owning_group_id",
                    "affiliations",
                    "target_kind",
                    "lifecycle_state",
                    "visibility",
                    "memory_state",
                    "aliases",
                }
            ),
            field,
        )
        raw_affiliations = data.get("affiliations")
        raw_aliases = data.get("aliases")
        if not isinstance(raw_affiliations, list):
            raise ProjectRegistryInvalid(f"{field}.affiliations must be an array")
        if not isinstance(raw_aliases, list) or len(raw_aliases) > PROJECT_REGISTRY_MAX_ALIASES:
            raise ProjectRegistryInvalid(f"{field}.aliases count is out of bounds")
        affiliations = tuple(
            _identifier(item, f"{field}.affiliations[{index}]")
            for index, item in enumerate(cast(list[object], raw_affiliations))
        )
        aliases = tuple(
            ProjectRegistryAlias.from_dict(item, f"{field}.aliases[{index}]")
            for index, item in enumerate(cast(list[object], raw_aliases))
        )
        if affiliations != tuple(sorted(affiliations)) or len(affiliations) != len(
            set(affiliations)
        ):
            raise ProjectRegistryInvalid(f"{field}.affiliations must be sorted and unique")
        alias_paths = tuple(alias.path for alias in aliases)
        if alias_paths != tuple(sorted(alias_paths)) or len(alias_paths) != len(set(alias_paths)):
            raise ProjectRegistryInvalid(f"{field}.aliases must be sorted and path-unique")
        target_kind = _string(data.get("target_kind"), f"{field}.target_kind", 32)
        lifecycle = _string(data.get("lifecycle_state"), f"{field}.lifecycle_state", 32)
        visibility = _string(data.get("visibility"), f"{field}.visibility", 32)
        memory_state = _string(data.get("memory_state"), f"{field}.memory_state", 32)
        if target_kind not in PROJECT_REGISTRY_TARGET_KINDS:
            raise ProjectRegistryInvalid(f"{field}.target_kind is unsupported")
        if lifecycle not in PROJECT_REGISTRY_PROJECT_LIFECYCLES:
            raise ProjectRegistryInvalid(f"{field}.lifecycle_state is unsupported")
        if visibility not in PROJECT_REGISTRY_VISIBILITIES:
            raise ProjectRegistryInvalid(f"{field}.visibility is unsupported")
        if memory_state not in PROJECT_REGISTRY_MEMORY_STATES:
            raise ProjectRegistryInvalid(f"{field}.memory_state is unsupported")
        canonical_path = _relative_path(data.get("canonical_path"), f"{field}.canonical_path")
        if canonical_path in alias_paths:
            raise ProjectRegistryInvalid(f"{field}.canonical_path cannot also be an alias")
        owning_group_id = _identifier(data.get("owning_group_id"), f"{field}.owning_group_id")
        if owning_group_id == PROJECT_REGISTRY_UNASSIGNED_GROUP and memory_state != "absent":
            raise ProjectRegistryInvalid(f"{field} cannot activate memory while unassigned")
        if lifecycle == "retired" and memory_state == "active":
            raise ProjectRegistryInvalid(f"{field} cannot retain active memory while retired")
        return cls(
            project_id=_identifier(data.get("project_id"), f"{field}.project_id"),
            canonical_path=canonical_path,
            owning_group_id=owning_group_id,
            affiliations=affiliations,
            target_kind=target_kind,
            lifecycle_state=lifecycle,
            visibility=visibility,
            memory_state=memory_state,
            aliases=aliases,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise this project registration."""
        return {
            "project_id": self.project_id,
            "canonical_path": self.canonical_path,
            "owning_group_id": self.owning_group_id,
            "affiliations": list(self.affiliations),
            "target_kind": self.target_kind,
            "lifecycle_state": self.lifecycle_state,
            "visibility": self.visibility,
            "memory_state": self.memory_state,
            "aliases": [alias.to_dict() for alias in self.aliases],
        }


@dataclass(frozen=True)
class ProjectRegistryConsumer:
    """One exact registry-derived consumer that must move with a generation."""

    consumer_id: str
    kind: str
    path: str
    group_id: str | None
    project_id: str | None

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectRegistryConsumer:
        """Parse one consumer declaration and its scope."""
        data = _mapping(value, field)
        _exact_fields(
            data,
            frozenset({"consumer_id", "kind", "path", "group_id", "project_id"}),
            field,
        )
        kind = _string(data.get("kind"), f"{field}.kind", 32)
        if kind not in PROJECT_REGISTRY_CONSUMER_KINDS:
            raise ProjectRegistryInvalid(f"{field}.kind is unsupported")
        raw_group_id = data.get("group_id")
        raw_project_id = data.get("project_id")
        group_id = None if raw_group_id is None else _identifier(raw_group_id, f"{field}.group_id")
        project_id = (
            None if raw_project_id is None else _identifier(raw_project_id, f"{field}.project_id")
        )
        if kind == "group-view" and (group_id is None or project_id is not None):
            raise ProjectRegistryInvalid(f"{field} group-view scope is invalid")
        if kind == "project-index" and (project_id is None or group_id is not None):
            raise ProjectRegistryInvalid(f"{field} project-index scope is invalid")
        if kind not in {"group-view", "project-index"} and (
            group_id is not None or project_id is not None
        ):
            raise ProjectRegistryInvalid(f"{field} global consumer cannot have project scope")
        return cls(
            consumer_id=_identifier(data.get("consumer_id"), f"{field}.consumer_id"),
            kind=kind,
            path=_relative_path(data.get("path"), f"{field}.path"),
            group_id=group_id,
            project_id=project_id,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise this consumer declaration."""
        return {
            "consumer_id": self.consumer_id,
            "kind": self.kind,
            "path": self.path,
            "group_id": self.group_id,
            "project_id": self.project_id,
        }


_REGISTRY_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "generated_at",
        "canonical_serializer",
        "previous_registry_sha256",
        "authority",
        "groups",
        "projects",
        "consumers",
        "registry_sha256",
    }
)


@dataclass(frozen=True)
class ProjectRegistry:
    """One immutable, content-addressed registry generation."""

    generation_id: str
    generated_at: str
    previous_registry_sha256: str | None
    authority: ProjectRegistryAuthority
    groups: tuple[ProjectRegistryGroup, ...]
    projects: tuple[ProjectRegistration, ...]
    consumers: tuple[ProjectRegistryConsumer, ...]
    registry_sha256: str

    @classmethod
    def build(
        cls,
        *,
        generated_at: str,
        previous_registry_sha256: str | None,
        authority: ProjectRegistryAuthority,
        groups: tuple[ProjectRegistryGroup, ...],
        projects: tuple[ProjectRegistration, ...],
        consumers: tuple[ProjectRegistryConsumer, ...],
    ) -> ProjectRegistry:
        """Build and close one registry generation from validated values."""
        value: dict[str, object] = {
            "schema_version": PROJECT_REGISTRY_SCHEMA_VERSION,
            "generation_id": project_registry_generation_id(generated_at),
            "generated_at": generated_at,
            "canonical_serializer": PROJECT_REGISTRY_SERIALIZER,
            "previous_registry_sha256": previous_registry_sha256,
            "authority": authority.to_dict(),
            "groups": [group.to_dict() for group in groups],
            "projects": [project.to_dict() for project in projects],
            "consumers": [consumer.to_dict() for consumer in consumers],
        }
        value["registry_sha256"] = hashlib.sha256(
            project_registry_canonical_json(value)
        ).hexdigest()
        return cls.from_dict(value)

    @classmethod
    def from_dict(cls, value: object) -> ProjectRegistry:
        """Parse and cross-check one exact registry generation."""
        data = _mapping(value, "registry")
        _exact_fields(data, _REGISTRY_FIELDS, "registry")
        if data.get("schema_version") != PROJECT_REGISTRY_SCHEMA_VERSION:
            raise ProjectRegistryInvalid("registry schema version is unsupported")
        if data.get("canonical_serializer") != PROJECT_REGISTRY_SERIALIZER:
            raise ProjectRegistryInvalid("registry canonical serializer is unsupported")
        generated_at, generated = _timestamp(data.get("generated_at"), "registry.generated_at")
        generation_id = _string(data.get("generation_id"), "registry.generation_id", 35)
        if _GENERATION_ID.fullmatch(generation_id) is None:
            raise ProjectRegistryInvalid("registry.generation_id is malformed")
        if generation_id != project_registry_generation_id(generated_at):
            raise ProjectRegistryInvalid("registry.generation_id does not match generated_at")
        raw_previous = data.get("previous_registry_sha256")
        previous = (
            None if raw_previous is None else _digest(raw_previous, "previous_registry_sha256")
        )
        authority = ProjectRegistryAuthority.from_dict(data.get("authority"))
        _, approved = _timestamp(authority.approved_at, "authority.approved_at")
        if approved > generated:
            raise ProjectRegistryInvalid("authority approval cannot follow registry generation")
        groups = cls._parse_array(
            data.get("groups"),
            PROJECT_REGISTRY_MAX_GROUPS,
            ProjectRegistryGroup.from_dict,
            lambda item: item.group_id,
            "groups",
        )
        projects = cls._parse_array(
            data.get("projects"),
            PROJECT_REGISTRY_MAX_PROJECTS,
            ProjectRegistration.from_dict,
            lambda item: item.project_id,
            "projects",
        )
        consumers = cls._parse_array(
            data.get("consumers"),
            PROJECT_REGISTRY_MAX_CONSUMERS,
            ProjectRegistryConsumer.from_dict,
            lambda item: item.consumer_id,
            "consumers",
        )
        for project in projects:
            for alias in project.aliases:
                _, retired_at = _timestamp(alias.retired_at, "project alias retired_at")
                if retired_at > generated:
                    raise ProjectRegistryInvalid(
                        "project alias cannot retire after the registry generation"
                    )
        cls._validate_relations(groups, projects, consumers)
        registry_sha256 = _digest(data.get("registry_sha256"), "registry.registry_sha256")
        unsigned = {key: item for key, item in data.items() if key != "registry_sha256"}
        expected = hashlib.sha256(project_registry_canonical_json(unsigned)).hexdigest()
        if registry_sha256 != expected:
            raise ProjectRegistryInvalid("registry digest does not close")
        registry = cls(
            generation_id,
            generated_at,
            previous,
            authority,
            groups,
            projects,
            consumers,
            registry_sha256,
        )
        if len(registry.to_bytes()) > PROJECT_REGISTRY_MAX_BYTES:
            raise ProjectRegistryInvalid("registry exceeds its byte bound")
        return registry

    @staticmethod
    def _parse_array(
        value: object,
        maximum: int,
        parser: Callable[[object, str], _RegistryItem],
        identity: Callable[[_RegistryItem], str],
        field: str,
    ) -> tuple[_RegistryItem, ...]:
        if not isinstance(value, list) or not 1 <= len(value) <= maximum:
            raise ProjectRegistryInvalid(f"registry.{field} count is out of bounds")
        items = tuple(
            parser(item, f"registry.{field}[{index}]")
            for index, item in enumerate(cast(list[object], value))
        )
        identities = tuple(identity(item) for item in items)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise ProjectRegistryInvalid(f"registry.{field} must be sorted and identity-unique")
        return items

    @staticmethod
    def _validate_relations(
        groups: tuple[ProjectRegistryGroup, ...],
        projects: tuple[ProjectRegistration, ...],
        consumers: tuple[ProjectRegistryConsumer, ...],
    ) -> None:
        group_by_id = {group.group_id: group for group in groups}
        project_by_id = {project.project_id: project for project in projects}
        claimed_paths: dict[str, str] = {}
        for project in projects:
            if project.owning_group_id != PROJECT_REGISTRY_UNASSIGNED_GROUP:
                group = group_by_id.get(project.owning_group_id)
                if group is None:
                    raise ProjectRegistryInvalid("project owning group is not registered")
                if project.target_kind == "git-repository":
                    expected = f"{group.repositories_path}/{project.project_id}"
                    if project.canonical_path != expected:
                        raise ProjectRegistryInvalid(
                            "project canonical path does not match owning group"
                        )
            if project.owning_group_id in project.affiliations:
                raise ProjectRegistryInvalid("project affiliation duplicates its owning group")
            if any(group_id not in group_by_id for group_id in project.affiliations):
                raise ProjectRegistryInvalid("project affiliation names an unknown group")
            for path in (project.canonical_path, *(alias.path for alias in project.aliases)):
                if path in claimed_paths:
                    raise ProjectRegistryInvalid(
                        "project canonical and alias paths must be globally unique"
                    )
                claimed_paths[path] = project.project_id
        consumer_paths: set[str] = set()
        group_views: set[str] = set()
        project_indexes: set[str] = set()
        for consumer in consumers:
            if consumer.path in consumer_paths:
                raise ProjectRegistryInvalid("registry consumer paths must be unique")
            consumer_paths.add(consumer.path)
            if consumer.kind == "group-view":
                if consumer.group_id not in group_by_id:
                    raise ProjectRegistryInvalid("group-view consumer names an unknown group")
                group = group_by_id[consumer.group_id]
                if consumer.path != f"{group.root_path}/agentic_group_memory/registry_view.json":
                    raise ProjectRegistryInvalid("group-view consumer path does not match group")
                if consumer.group_id in group_views:
                    raise ProjectRegistryInvalid("a group has multiple group-view consumers")
                group_views.add(consumer.group_id)
            elif consumer.kind == "project-index":
                if consumer.project_id not in project_by_id:
                    raise ProjectRegistryInvalid("project-index consumer names an unknown project")
                project = project_by_id[consumer.project_id]
                if (
                    consumer.path
                    != f"{project.canonical_path}/agentic_project_memory/registry_binding.json"
                ):
                    raise ProjectRegistryInvalid(
                        "project-index consumer path does not match project"
                    )
                if consumer.project_id in project_indexes:
                    raise ProjectRegistryInvalid("a project has multiple project-index consumers")
                project_indexes.add(consumer.project_id)
        active_groups = {group.group_id for group in groups if group.lifecycle_state == "active"}
        if group_views != active_groups:
            raise ProjectRegistryInvalid(
                "every active group needs exactly one group-view consumer"
            )
        memory_projects = {
            project.project_id for project in projects if project.memory_state != "absent"
        }
        if project_indexes != memory_projects:
            raise ProjectRegistryInvalid(
                "every project with a memory root needs exactly one project-index consumer"
            )

    @classmethod
    def from_bytes(cls, payload: bytes) -> ProjectRegistry:
        """Parse canonical bytes and reject non-canonical encodings."""
        if not payload or len(payload) > PROJECT_REGISTRY_MAX_BYTES:
            raise ProjectRegistryInvalid("registry byte count is out of bounds")
        value = project_registry_strict_json(payload)
        registry = cls.from_dict(value)
        if registry.to_bytes() != payload:
            raise ProjectRegistryInvalid("registry bytes are not canonical")
        return registry

    def to_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        """Serialise this registry generation."""
        value: dict[str, object] = {
            "schema_version": PROJECT_REGISTRY_SCHEMA_VERSION,
            "generation_id": self.generation_id,
            "generated_at": self.generated_at,
            "canonical_serializer": PROJECT_REGISTRY_SERIALIZER,
            "previous_registry_sha256": self.previous_registry_sha256,
            "authority": self.authority.to_dict(),
            "groups": [group.to_dict() for group in self.groups],
            "projects": [project.to_dict() for project in self.projects],
            "consumers": [consumer.to_dict() for consumer in self.consumers],
        }
        if include_digest:
            value["registry_sha256"] = self.registry_sha256
        return value

    def to_bytes(self) -> bytes:
        """Return the exact canonical registry bytes."""
        return project_registry_canonical_json(self.to_dict())
