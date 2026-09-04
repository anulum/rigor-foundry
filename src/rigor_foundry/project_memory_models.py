# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory manifest contracts
"""Validate records and the private project-memory current view."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

from .project_memory_primitives import (
    PROJECT_MEMORY_ASSERTION_CLASSES,
    PROJECT_MEMORY_CATEGORIES,
    PROJECT_MEMORY_MAX_CONTENT_BYTES,
    PROJECT_MEMORY_MAX_INDEX_BYTES,
    PROJECT_MEMORY_MAX_MANIFEST_BYTES,
    PROJECT_MEMORY_MAX_RECORDS,
    PROJECT_MEMORY_MAX_SOURCES,
    PROJECT_MEMORY_MAX_SUPERSEDES,
    PROJECT_MEMORY_PARENT_KINDS,
    PROJECT_MEMORY_SCHEMA_VERSION,
    PROJECT_MEMORY_SENSITIVITY,
    PROJECT_MEMORY_SERIALIZER,
    PROJECT_MEMORY_SOFT_CONTENT_BYTES,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryInvalid,
    ProjectMemoryParent,
    ProjectMemorySource,
    canonical_json_bytes,
    generation_id_for,
)
from .project_memory_primitives import (
    require_digest as _digest,
)
from .project_memory_primitives import (
    require_exact_fields as _exact_fields,
)
from .project_memory_primitives import (
    require_identifier as _identifier,
)
from .project_memory_primitives import (
    require_mapping as _mapping,
)
from .project_memory_primitives import (
    require_string as _string,
)
from .project_memory_primitives import (
    require_timestamp as _timestamp,
)
from .project_memory_primitives import (
    strict_json as _strict_json,
)

_GENERATION_ID = re.compile(r"[0-9]{8}T[0-9]{12}Z")

_RECORD_FIELDS = frozenset(
    {
        "record_id",
        "category",
        "created_at",
        "observed_at",
        "freshness",
        "assertion_class",
        "sources",
        "sensitivity",
        "actor",
        "supersedes",
        "content_path",
        "content_bytes",
        "content_sha256",
    }
)


@dataclass(frozen=True)
class ProjectMemoryRecord:
    """Metadata closure for one immutable Markdown content file."""

    record_id: str
    category: str
    created_at: str
    observed_at: str
    freshness: ProjectMemoryFreshness
    assertion_class: str
    sources: tuple[ProjectMemorySource, ...]
    sensitivity: str
    actor: ProjectMemoryActor
    supersedes: tuple[str, ...]
    content_path: str
    content_bytes: int
    content_sha256: str

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectMemoryRecord:
        """Parse and cross-check one record metadata object."""
        data = _mapping(value, field)
        _exact_fields(data, _RECORD_FIELDS, field)
        record_id = _identifier(data.get("record_id"), f"{field}.record_id")
        category = _string(data.get("category"), f"{field}.category", maximum=32)
        if category not in PROJECT_MEMORY_CATEGORIES:
            raise ProjectMemoryInvalid(f"{field}.category is unsupported")
        created_at, created = _timestamp(data.get("created_at"), f"{field}.created_at")
        observed_at, observed = _timestamp(data.get("observed_at"), f"{field}.observed_at")
        if observed > created:
            raise ProjectMemoryInvalid(f"{field}.observed_at must not follow created_at")
        freshness = ProjectMemoryFreshness.from_dict(data.get("freshness"), f"{field}.freshness")
        if freshness.valid_until is not None:
            _, valid_until = _timestamp(freshness.valid_until, f"{field}.freshness.valid_until")
            if valid_until <= observed:
                raise ProjectMemoryInvalid(
                    f"{field}.freshness.valid_until must follow observed_at"
                )
        assertion_class = _string(
            data.get("assertion_class"), f"{field}.assertion_class", maximum=32
        )
        if assertion_class not in PROJECT_MEMORY_ASSERTION_CLASSES:
            raise ProjectMemoryInvalid(f"{field}.assertion_class is unsupported")
        raw_sources = data.get("sources")
        if (
            not isinstance(raw_sources, list)
            or not 1 <= len(raw_sources) <= PROJECT_MEMORY_MAX_SOURCES
        ):
            raise ProjectMemoryInvalid(f"{field}.sources count is out of bounds")
        sources = tuple(
            ProjectMemorySource.from_dict(item, f"{field}.sources[{index}]")
            for index, item in enumerate(cast(list[object], raw_sources))
        )
        source_ids = tuple(item.source_id for item in sources)
        if source_ids != tuple(sorted(source_ids)) or len(source_ids) != len(set(source_ids)):
            raise ProjectMemoryInvalid(f"{field}.sources must be sorted and unique by source_id")
        sensitivity = _string(data.get("sensitivity"), f"{field}.sensitivity", maximum=32)
        if sensitivity != PROJECT_MEMORY_SENSITIVITY:
            raise ProjectMemoryInvalid(f"{field}.sensitivity is not admissible")
        raw_supersedes = data.get("supersedes")
        if (
            not isinstance(raw_supersedes, list)
            or len(raw_supersedes) > PROJECT_MEMORY_MAX_SUPERSEDES
        ):
            raise ProjectMemoryInvalid(f"{field}.supersedes count is out of bounds")
        supersedes = tuple(
            _identifier(item, f"{field}.supersedes[{index}]")
            for index, item in enumerate(cast(list[object], raw_supersedes))
        )
        if supersedes != tuple(sorted(supersedes)) or len(supersedes) != len(set(supersedes)):
            raise ProjectMemoryInvalid(f"{field}.supersedes must be sorted and unique")
        if record_id in supersedes:
            raise ProjectMemoryInvalid(f"{field} cannot supersede itself")
        content_path = _string(data.get("content_path"), f"{field}.content_path", maximum=320)
        expected_path = f"records/{category}/{record_id}.md"
        if content_path != expected_path or PurePosixPath(content_path).as_posix() != content_path:
            raise ProjectMemoryInvalid(f"{field}.content_path does not match record identity")
        content_bytes = data.get("content_bytes")
        if (
            isinstance(content_bytes, bool)
            or not isinstance(content_bytes, int)
            or not 1 <= content_bytes <= PROJECT_MEMORY_MAX_CONTENT_BYTES
        ):
            raise ProjectMemoryInvalid(f"{field}.content_bytes is out of bounds")
        return cls(
            record_id=record_id,
            category=category,
            created_at=created_at,
            observed_at=observed_at,
            freshness=freshness,
            assertion_class=assertion_class,
            sources=sources,
            sensitivity=sensitivity,
            actor=ProjectMemoryActor.from_dict(data.get("actor"), f"{field}.actor"),
            supersedes=supersedes,
            content_path=content_path,
            content_bytes=content_bytes,
            content_sha256=_digest(data.get("content_sha256"), f"{field}.content_sha256"),
        )

    @classmethod
    def for_content(
        cls,
        *,
        record_id: str,
        category: str,
        created_at: str,
        observed_at: str,
        freshness: ProjectMemoryFreshness,
        assertion_class: str,
        sources: tuple[ProjectMemorySource, ...],
        actor: ProjectMemoryActor,
        supersedes: tuple[str, ...],
        content: bytes,
    ) -> ProjectMemoryRecord:
        """Build metadata for exact already-admitted Markdown bytes."""
        value: dict[str, object] = {
            "record_id": record_id,
            "category": category,
            "created_at": created_at,
            "observed_at": observed_at,
            "freshness": freshness.to_dict(),
            "assertion_class": assertion_class,
            "sources": [item.to_dict() for item in sources],
            "sensitivity": PROJECT_MEMORY_SENSITIVITY,
            "actor": actor.to_dict(),
            "supersedes": list(supersedes),
            "content_path": f"records/{category}/{record_id}.md",
            "content_bytes": len(content),
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }
        return cls.from_dict(value, "record")

    @property
    def exceeds_soft_content_limit(self) -> bool:
        """Return whether the content exceeds the rollover guidance."""
        return self.content_bytes > PROJECT_MEMORY_SOFT_CONTENT_BYTES

    def is_current_at(self, generated_at: str) -> bool:
        """Return whether the record remains active at one generation time."""
        _, generation_time = _timestamp(generated_at, "generated_at")
        if self.freshness.valid_until is None:
            return True
        _, valid_until = _timestamp(self.freshness.valid_until, "freshness.valid_until")
        return generation_time < valid_until

    def to_dict(self) -> dict[str, object]:
        """Serialise the record metadata."""
        return {
            "record_id": self.record_id,
            "category": self.category,
            "created_at": self.created_at,
            "observed_at": self.observed_at,
            "freshness": self.freshness.to_dict(),
            "assertion_class": self.assertion_class,
            "sources": [item.to_dict() for item in self.sources],
            "sensitivity": self.sensitivity,
            "actor": self.actor.to_dict(),
            "supersedes": list(self.supersedes),
            "content_path": self.content_path,
            "content_bytes": self.content_bytes,
            "content_sha256": self.content_sha256,
        }


_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "project_id",
        "generation_id",
        "generated_at",
        "canonical_serializer",
        "previous_manifest_sha256",
        "parents",
        "records",
        "index_sha256",
        "manifest_sha256",
    }
)


def _render_index(
    project_id: str,
    generation_id: str,
    parents: tuple[ProjectMemoryParent, ...],
    records: tuple[ProjectMemoryRecord, ...],
) -> str:
    """Render the bounded selective index from canonical manifest fields."""
    lines = [
        f"# {project_id} project memory index",
        "",
        f"**Schema:** `{PROJECT_MEMORY_SCHEMA_VERSION}`  ",
        f"**Generation:** `{generation_id}`  ",
        "**Authority:** private advisory evidence; revalidate against canonical sources",
        "",
        "## Parent layers",
        "",
    ]
    lines.extend(f"- `{parent.kind}`: [{parent.locator}]({parent.locator})" for parent in parents)
    lines.extend(
        [
            "",
            "## Current records",
            "",
            "| Category | Record | Observed | Freshness | Content |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(
        "| "
        f"{record.category} | `{record.record_id}` | `{record.observed_at}` | "
        f"`{record.freshness.policy}` | [{record.content_path}]({record.content_path}) |"
        for record in records
    )
    lines.extend(
        [
            "",
            "Load only the records required by the active task. Do not recursively ingest",
            "history, sibling projects, transcripts, broadcasts or vendor stores.",
            "",
        ]
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class ProjectMemoryManifest:
    """One content-addressed active view with a predecessor chain."""

    project_id: str
    generation_id: str
    generated_at: str
    previous_manifest_sha256: str | None
    parents: tuple[ProjectMemoryParent, ...]
    records: tuple[ProjectMemoryRecord, ...]
    index_sha256: str
    manifest_sha256: str

    @classmethod
    def build(
        cls,
        *,
        project_id: str,
        generated_at: str,
        previous_manifest_sha256: str | None,
        parents: tuple[ProjectMemoryParent, ...],
        records: tuple[ProjectMemoryRecord, ...],
    ) -> ProjectMemoryManifest:
        """Build and validate one canonical current-view generation."""
        project_id = _identifier(project_id, "project_id")
        generated_at, generation_time = _timestamp(generated_at, "generated_at")
        generation_id = generation_id_for(generated_at)
        if previous_manifest_sha256 is not None:
            previous_manifest_sha256 = _digest(
                previous_manifest_sha256, "previous_manifest_sha256"
            )
        parents = tuple(
            ProjectMemoryParent.from_dict(parent.to_dict(), f"parents[{index}]")
            for index, parent in enumerate(parents)
        )
        records = tuple(
            ProjectMemoryRecord.from_dict(record.to_dict(), f"records[{index}]")
            for index, record in enumerate(records)
        )
        parent_order = {kind: index for index, kind in enumerate(PROJECT_MEMORY_PARENT_KINDS)}
        parent_kinds = tuple(parent.kind for parent in parents)
        if (
            parent_kinds != tuple(sorted(parent_kinds, key=parent_order.__getitem__))
            or parent_kinds != PROJECT_MEMORY_PARENT_KINDS
        ):
            raise ProjectMemoryInvalid("parents must contain every canonical kind exactly once")
        if not records or len(records) > PROJECT_MEMORY_MAX_RECORDS:
            raise ProjectMemoryInvalid("current record count is out of bounds")
        record_ids = tuple(record.record_id for record in records)
        if record_ids != tuple(sorted(record_ids)) or len(record_ids) != len(set(record_ids)):
            raise ProjectMemoryInvalid("current records must be sorted and unique by record_id")
        active_ids = set(record_ids)
        for record in records:
            _, created = _timestamp(record.created_at, f"{record.record_id}.created_at")
            if created > generation_time:
                raise ProjectMemoryInvalid(
                    "a current record cannot be created after its generation"
                )
            if not record.is_current_at(generated_at):
                raise ProjectMemoryInvalid("an expired record cannot enter the current view")
            if active_ids.intersection(record.supersedes):
                raise ProjectMemoryInvalid(
                    "a current record cannot supersede another current record"
                )
        index = _render_index(project_id, generation_id, parents, records).encode("utf-8")
        if len(index) > PROJECT_MEMORY_MAX_INDEX_BYTES:
            raise ProjectMemoryInvalid("generated project-memory index exceeds its byte bound")
        index_sha256 = hashlib.sha256(index).hexdigest()
        unsigned: dict[str, object] = {
            "schema_version": PROJECT_MEMORY_SCHEMA_VERSION,
            "project_id": project_id,
            "generation_id": generation_id,
            "generated_at": generated_at,
            "canonical_serializer": PROJECT_MEMORY_SERIALIZER,
            "previous_manifest_sha256": previous_manifest_sha256,
            "parents": [parent.to_dict() for parent in parents],
            "records": [record.to_dict() for record in records],
            "index_sha256": index_sha256,
        }
        manifest_sha256 = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        manifest = cls(
            project_id=project_id,
            generation_id=generation_id,
            generated_at=generated_at,
            previous_manifest_sha256=previous_manifest_sha256,
            parents=parents,
            records=records,
            index_sha256=index_sha256,
            manifest_sha256=manifest_sha256,
        )
        if len(manifest.to_bytes()) > PROJECT_MEMORY_MAX_MANIFEST_BYTES:
            raise ProjectMemoryInvalid("canonical project-memory manifest exceeds its byte bound")
        return manifest

    @classmethod
    def from_bytes(cls, payload: bytes) -> ProjectMemoryManifest:
        """Parse an exact canonical manifest and verify every derived field."""
        if len(payload) > PROJECT_MEMORY_MAX_MANIFEST_BYTES:
            raise ProjectMemoryInvalid("canonical project-memory manifest exceeds its byte bound")
        data = _mapping(_strict_json(payload), "manifest")
        _exact_fields(data, _MANIFEST_FIELDS, "manifest")
        if data.get("schema_version") != PROJECT_MEMORY_SCHEMA_VERSION:
            raise ProjectMemoryInvalid("project-memory manifest schema version is unsupported")
        if data.get("canonical_serializer") != PROJECT_MEMORY_SERIALIZER:
            raise ProjectMemoryInvalid("project-memory canonical serializer is unsupported")
        generation_id = _string(data.get("generation_id"), "generation_id", maximum=22)
        if _GENERATION_ID.fullmatch(generation_id) is None:
            raise ProjectMemoryInvalid("generation_id is invalid")
        raw_previous = data.get("previous_manifest_sha256")
        previous = (
            None if raw_previous is None else _digest(raw_previous, "previous_manifest_sha256")
        )
        raw_parents = data.get("parents")
        if not isinstance(raw_parents, list):
            raise ProjectMemoryInvalid("parents must be an array")
        parents = tuple(
            ProjectMemoryParent.from_dict(item, f"parents[{index}]")
            for index, item in enumerate(cast(list[object], raw_parents))
        )
        raw_records = data.get("records")
        if not isinstance(raw_records, list):
            raise ProjectMemoryInvalid("records must be an array")
        records = tuple(
            ProjectMemoryRecord.from_dict(item, f"records[{index}]")
            for index, item in enumerate(cast(list[object], raw_records))
        )
        manifest = cls.build(
            project_id=_identifier(data.get("project_id"), "project_id"),
            generated_at=_timestamp(data.get("generated_at"), "generated_at")[0],
            previous_manifest_sha256=previous,
            parents=parents,
            records=records,
        )
        if generation_id != manifest.generation_id:
            raise ProjectMemoryInvalid("generation_id does not match generated_at")
        if _digest(data.get("index_sha256"), "index_sha256") != manifest.index_sha256:
            raise ProjectMemoryInvalid("index_sha256 does not match the generated index")
        if _digest(data.get("manifest_sha256"), "manifest_sha256") != manifest.manifest_sha256:
            raise ProjectMemoryInvalid("manifest_sha256 does not match the canonical manifest")
        if payload != manifest.to_bytes():
            raise ProjectMemoryInvalid("project-memory manifest bytes are not canonical JCS")
        return manifest

    def index_text(self) -> str:
        """Return the exact generated selective index."""
        return _render_index(self.project_id, self.generation_id, self.parents, self.records)

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete manifest including its integrity digest."""
        return {
            "schema_version": PROJECT_MEMORY_SCHEMA_VERSION,
            "project_id": self.project_id,
            "generation_id": self.generation_id,
            "generated_at": self.generated_at,
            "canonical_serializer": PROJECT_MEMORY_SERIALIZER,
            "previous_manifest_sha256": self.previous_manifest_sha256,
            "parents": [parent.to_dict() for parent in self.parents],
            "records": [record.to_dict() for record in self.records],
            "index_sha256": self.index_sha256,
            "manifest_sha256": self.manifest_sha256,
        }

    def to_bytes(self) -> bytes:
        """Return the canonical current/history manifest bytes."""
        return canonical_json_bytes(self.to_dict())
