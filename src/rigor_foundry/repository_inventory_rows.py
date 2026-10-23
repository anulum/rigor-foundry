# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete repository inventory preimages
"""Validate bounded inventory and full-stage index preimages without scanning."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
    require_string,
)
from .model_primitives import require_digest, require_git_object, require_identifier
from .policy_read_budget import PolicyReadBudget1

_MAX_ROWS = 65536
_MODES = frozenset({"100644", "100755", "120000", "160000"})
_FILE_FIELDS = frozenset(
    {"relative_path", "kind", "mode", "object_id", "byte_digest", "byte_count", "language", "role"}
)
_INDEX_FIELDS = frozenset({"relative_path", "stage", "mode", "object_id"})


def require_inventory_path(value: object) -> str:
    """Require one exact portable path below a root, excluding Git administration."""
    text = require_string(value, "inventory relative path")
    path = PurePosixPath(text)
    if (
        not path.parts
        or path.is_absolute()
        or path.as_posix() != text
        or any(part.casefold() in {"..", ".git"} for part in path.parts)
        or "\\" in text
        or "\0" in text
        or ":" in path.parts[0]
    ):
        raise ValueError("inventory path must be normalized, relative and outside Git metadata")
    return text


def _row_limit(budget: PolicyReadBudget1) -> int:
    """Revalidate explicit parser ceilings before inspecting any row collection."""
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    return PolicyReadBudget1.from_dict(budget.to_dict()).max_references


@dataclass(frozen=True)
class RepositoryFileRow:
    """Inline exact file observation, including explicit unsupported or missing data.

    Language/role null retains an unresolved classification. It cannot establish
    completeness or admission. This value has no independent header or digest.
    """

    relative_path: str
    kind: str
    mode: str | None
    object_id: str | None
    byte_digest: str | None
    byte_count: int | None
    language: str | None
    role: str | None

    def __post_init__(self) -> None:
        """Apply the same closed field and relational checks to direct instances."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Serialize exact data while refusing contradictory byte or Git identities."""
        path = require_inventory_path(self.relative_path)
        kind = require_string(self.kind, "inventory file kind")
        if kind not in {"regular", "symlink", "gitlink", "deleted", "unsupported"}:
            raise ValueError("unsupported inventory file kind")
        mode = None if self.mode is None else require_string(self.mode, "inventory mode")
        if mode is not None and mode not in _MODES:
            raise ValueError("unsupported inventory Git mode")
        expected = {"regular": {"100644", "100755"}, "symlink": {"120000"}, "gitlink": {"160000"}}
        if kind in expected and mode not in expected[kind]:
            raise ValueError("inventory kind differs from its Git mode")
        object_id = (
            None
            if self.object_id is None
            else require_git_object(self.object_id, "inventory object")
        )
        digest = (
            None
            if self.byte_digest is None
            else require_digest(self.byte_digest, "inventory byte digest")
        )
        count = (
            None
            if self.byte_count is None
            else require_integer(self.byte_count, "inventory byte count", minimum=0)
        )
        if (digest is None) != (count is None):
            raise ValueError("inventory byte digest and count must be present together")
        if kind in {"regular", "symlink"} and digest is None:
            raise ValueError("present inventory bytes must have an exact identity")
        if kind in {"deleted", "gitlink"} and digest is not None:
            raise ValueError("deleted files and gitlinks do not carry file bytes")
        if kind == "gitlink" and object_id is None:
            raise ValueError("inventory gitlink requires its commit identity")
        return {
            "relative_path": path,
            "kind": kind,
            "mode": mode,
            "object_id": object_id,
            "byte_digest": digest,
            "byte_count": count,
            "language": None
            if self.language is None
            else require_identifier(self.language, "inventory language"),
            "role": None if self.role is None else require_identifier(self.role, "inventory role"),
        }

    @classmethod
    def from_dict(cls, value: object) -> RepositoryFileRow:
        """Parse all inline fields, including required nullable values."""
        data = require_mapping(value, "repository file row")
        require_exact_fields(data, _FILE_FIELDS, "repository file row")
        return cls(
            relative_path=require_inventory_path(data["relative_path"]),
            kind=require_string(data["kind"], "inventory file kind"),
            mode=None if data["mode"] is None else require_string(data["mode"], "inventory mode"),
            object_id=None
            if data["object_id"] is None
            else require_git_object(data["object_id"], "inventory object"),
            byte_digest=None
            if data["byte_digest"] is None
            else require_digest(data["byte_digest"], "inventory byte digest"),
            byte_count=None
            if data["byte_count"] is None
            else require_integer(data["byte_count"], "inventory byte count", minimum=0),
            language=None
            if data["language"] is None
            else require_identifier(data["language"], "inventory language"),
            role=None
            if data["role"] is None
            else require_identifier(data["role"], "inventory role"),
        )


def parse_repository_file_rows(
    value: object, *, budget: PolicyReadBudget1
) -> tuple[RepositoryFileRow, ...]:
    """Parse one ordered complete preimage without dropping duplicate or unknown rows."""
    limit = _row_limit(budget)
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("inventory rows must be an array within the reference budget")
    rows = tuple(RepositoryFileRow.from_dict(item) for item in value)
    paths = tuple(row.relative_path for row in rows)
    if paths != tuple(sorted(set(paths))):
        raise ValueError("inventory rows must be sorted and unique")
    return rows


def repository_file_rows_digest(
    rows: tuple[RepositoryFileRow, ...], *, budget: PolicyReadBudget1
) -> str:
    """Hash every revalidated inline row, including unresolved classifications."""
    limit = _row_limit(budget)
    if (
        not isinstance(rows, tuple)
        or len(rows) > limit
        or any(type(row) is not RepositoryFileRow for row in rows)
    ):
        raise ValueError("inventory requires bounded immutable file rows")
    values = [row.to_dict() for row in rows]
    parse_repository_file_rows(values, budget=budget)
    return canonical_digest(values)


@dataclass(frozen=True)
class RepositoryIndexEntry:
    """Inline Git index entry retaining stages one through three as well as zero."""

    relative_path: str
    stage: int
    mode: str
    object_id: str

    def __post_init__(self) -> None:
        """Reject malformed direct index entries."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Revalidate exact path, stage, mode and full object identity."""
        stage = require_integer(self.stage, "index stage", minimum=0)
        if stage > 3:
            raise ValueError("index stage exceeds three")
        mode = require_string(self.mode, "index mode")
        if mode not in _MODES:
            raise ValueError("unsupported index Git mode")
        return {
            "relative_path": require_inventory_path(self.relative_path),
            "stage": stage,
            "mode": mode,
            "object_id": require_git_object(self.object_id, "index object"),
        }

    @classmethod
    def from_dict(cls, value: object) -> RepositoryIndexEntry:
        """Parse an exact inline index entry without a stage-zero filter."""
        data = require_mapping(value, "repository index entry")
        require_exact_fields(data, _INDEX_FIELDS, "repository index entry")
        return cls(
            require_inventory_path(data["relative_path"]),
            require_integer(data["stage"], "index stage", minimum=0),
            require_string(data["mode"], "index mode"),
            require_git_object(data["object_id"], "index object"),
        )


@dataclass(frozen=True)
class RepositoryIndexState:
    """Exact inline index preimage with independently checked unmerged path union."""

    entries: tuple[RepositoryIndexEntry, ...]
    unmerged_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        """Apply hard collection ceilings and relations before a caller can serialize."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Keep all stages and refuse missing, contradictory or reordered entries."""
        if (
            not isinstance(self.entries, tuple)
            or not isinstance(self.unmerged_paths, tuple)
            or len(self.entries) + len(self.unmerged_paths) > _MAX_ROWS
        ):
            raise ValueError("index requires bounded immutable collections")
        if any(type(item) is not RepositoryIndexEntry for item in self.entries):
            raise ValueError("index requires actual index entry records")
        entries = [item.to_dict() for item in self.entries]
        keys = tuple((item.relative_path, item.stage) for item in self.entries)
        key_set = set(keys)
        if keys != tuple(sorted(key_set)):
            raise ValueError("index entries must be sorted and unique")
        unmerged = tuple(sorted({path for path, stage in keys if stage != 0}))
        declared = tuple(require_inventory_path(path) for path in self.unmerged_paths)
        if declared != unmerged or any((path, 0) in key_set for path in unmerged):
            raise ValueError("index unmerged paths must exactly match nonzero stages")
        lengths = {len(item.object_id) for item in self.entries}
        if len(lengths) > 1:
            raise ValueError("index mixes Git object formats")
        return {"entries": entries, "unmerged_paths": list(declared)}

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RepositoryIndexState:
        """Bound arrays before parsing the exact closed index preimage."""
        limit = _row_limit(budget)
        data = require_mapping(value, "repository index state")
        require_exact_fields(
            data, frozenset({"entries", "unmerged_paths"}), "repository index state"
        )
        entries, paths = data["entries"], data["unmerged_paths"]
        if (
            not isinstance(entries, list)
            or not isinstance(paths, list)
            or len(entries) + len(paths) > limit
        ):
            raise ValueError("index arrays exceed the reference budget or have invalid types")
        return cls(
            tuple(RepositoryIndexEntry.from_dict(item) for item in entries),
            tuple(require_inventory_path(path) for path in paths),
        )

    def digest(self, *, budget: PolicyReadBudget1) -> str:
        """Hash the complete revalidated index under explicit parser ceilings."""
        limit = _row_limit(budget)
        if len(self.entries) + len(self.unmerged_paths) > limit:
            raise ValueError("index exceeds the reference budget")
        return canonical_digest(self.to_dict())


def parse_git_index_state(payload: bytes, *, budget: PolicyReadBudget1) -> RepositoryIndexState:
    """Parse actual ``git ls-files --stage -z`` bytes, retaining every stage.

    This decoder neither invokes Git nor chooses its executable or repository.
    An installed owner must perform those actions under its own existing guards.
    """
    limit = _row_limit(budget)
    if not isinstance(payload, bytes) or len(payload) > budget.max_document_bytes:
        raise ValueError("Git index bytes exceed the document budget or have invalid type")
    if payload and not payload.endswith(b"\0"):
        raise ValueError("Git index output lacks its final NUL")
    if payload.count(b"\0") > limit:
        raise ValueError("Git index output exceeds the reference budget")
    entries: list[dict[str, object]] = []
    for raw in payload.split(b"\0")[:-1]:
        metadata, separator, path = raw.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise ValueError("malformed Git index entry")
        try:
            mode, object_id, stage = (field.decode("ascii") for field in fields)
            relative = path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Git index contains a non-UTF8 path or non-ASCII metadata") from exc
        if stage not in {"0", "1", "2", "3"}:
            raise ValueError("Git index stage must be exactly zero through three")
        entries.append(
            {"relative_path": relative, "stage": int(stage), "mode": mode, "object_id": object_id}
        )
    unmerged = sorted({str(item["relative_path"]) for item in entries if item["stage"] != 0})
    return RepositoryIndexState.from_dict(
        {"entries": entries, "unmerged_paths": unmerged}, budget=budget
    )
