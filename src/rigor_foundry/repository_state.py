# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent repository state identities
"""Bind repository observations without an enclosing inventory or owner proof."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .model_primitives import require_digest, require_git_object, require_identifier
from .task_definition import TYPED_OBJECT_REF_SCHEMA_VERSION

REPOSITORY_STATE_SCHEMA_VERSION = "1.0"
_IDENTITIES = ("project_id", "root_id", "registry_generation_id")
_GIT_OBJECTS = ("baseline_head", "head", "head_tree")
_DIGESTS = (
    "registry_sha256",
    "baseline_inventory_digest",
    "index_state_digest",
    "worktree_state_digest",
    "untracked_state_digest",
    "generated_state_digest",
    "configured_roots_digest",
)
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "repository_state_digest",
        *_IDENTITIES,
        *_GIT_OBJECTS,
        *_DIGESTS,
    }
)


@dataclass(frozen=True)
class RepositoryState1:
    """Independent source identity; a digest is not proof of an actual observation.

    An installed inventory owner must retain and verify the complete preimages,
    current Git state and configured domain. This parser performs no filesystem
    traversal, Git invocation, source selection or owner installation.
    """

    project_id: str
    root_id: str
    registry_generation_id: str
    registry_sha256: str
    baseline_head: str
    head: str
    head_tree: str
    baseline_inventory_digest: str
    index_state_digest: str
    worktree_state_digest: str
    untracked_state_digest: str
    generated_state_digest: str
    configured_roots_digest: str
    repository_state_digest: str

    schema_version: ClassVar[str] = REPOSITORY_STATE_SCHEMA_VERSION
    object_kind: ClassVar[str] = "repository-state"

    def __post_init__(self) -> None:
        """Reject invalid direct construction and a mismatched complete digest."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        """Validate all independent fields, including one consistent Git format."""
        body: dict[str, object] = {
            "schema_version": REPOSITORY_STATE_SCHEMA_VERSION,
            "object_kind": "repository-state",
        }
        for name in _IDENTITIES:
            body[name] = require_identifier(getattr(self, name), name)
        objects = tuple(require_git_object(getattr(self, name), name) for name in _GIT_OBJECTS)
        if len({len(value) for value in objects}) != 1:
            raise ValueError("repository state mixes Git object formats")
        body.update(zip(_GIT_OBJECTS, objects, strict=True))
        for name in _DIGESTS:
            body[name] = require_digest(getattr(self, name), name)
        return body

    @classmethod
    def build(
        cls,
        *,
        project_id: str,
        root_id: str,
        registry_generation_id: str,
        registry_sha256: str,
        baseline_head: str,
        head: str,
        head_tree: str,
        baseline_inventory_digest: str,
        index_state_digest: str,
        worktree_state_digest: str,
        untracked_state_digest: str,
        generated_state_digest: str,
        configured_roots_digest: str,
    ) -> RepositoryState1:
        """Bind every explicit observation identity without deriving missing inputs."""
        body: dict[str, object] = {
            "schema_version": REPOSITORY_STATE_SCHEMA_VERSION,
            "object_kind": "repository-state",
            "project_id": project_id,
            "root_id": root_id,
            "registry_generation_id": registry_generation_id,
            "registry_sha256": registry_sha256,
            "baseline_head": baseline_head,
            "head": head,
            "head_tree": head_tree,
            "baseline_inventory_digest": baseline_inventory_digest,
            "index_state_digest": index_state_digest,
            "worktree_state_digest": worktree_state_digest,
            "untracked_state_digest": untracked_state_digest,
            "generated_state_digest": generated_state_digest,
            "configured_roots_digest": configured_roots_digest,
        }
        return cls.from_dict({**body, "repository_state_digest": canonical_digest(body)})

    @classmethod
    def from_dict(cls, value: object) -> RepositoryState1:
        """Parse the exact closed header and fields without legacy coercion."""
        data = require_mapping(value, "repository state")
        require_exact_fields(data, _FIELDS, "repository state")
        if (
            data["schema_version"] != REPOSITORY_STATE_SCHEMA_VERSION
            or data["object_kind"] != "repository-state"
        ):
            raise ValueError("unsupported repository state")
        return cls(
            **{name: require_identifier(data[name], name) for name in _IDENTITIES},
            **{name: require_git_object(data[name], name) for name in _GIT_OBJECTS},
            **{name: require_digest(data[name], name) for name in _DIGESTS},
            repository_state_digest=require_digest(
                data["repository_state_digest"], "repository state digest"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate direct instances and serialize the complete identity."""
        body = self._body()
        digest = require_digest(self.repository_state_digest, "repository state digest")
        if digest != canonical_digest(body):
            raise ValueError("repository state digest differs")
        return {**body, "repository_state_digest": digest}

    def reference(self) -> dict[str, object]:
        """Return a source reference by root and digest without selecting a locator."""
        checked = self.to_dict()
        body: dict[str, object] = {
            "schema_version": TYPED_OBJECT_REF_SCHEMA_VERSION,
            "object_kind": "typed-object-ref",
            "kind": "repository-state",
            "format_version": REPOSITORY_STATE_SCHEMA_VERSION,
            "object_id": checked["root_id"],
            "object_digest": checked["repository_state_digest"],
        }
        return {**body, "ref_digest": canonical_digest(body)}
