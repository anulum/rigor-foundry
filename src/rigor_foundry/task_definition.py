# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — general task definitions
"""Represent declared general work without manufacturing an audit remediation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1

TASK_DEFINITION_SCHEMA_VERSION = "1.0"
TASK_IDENTITY_SCHEMA_VERSION = "1.0"
TYPED_OBJECT_REF_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "task_id",
        "revision",
        "actor_ids",
        "project_id",
        "group_id",
        "root_ids",
        "statement",
        "lifecycle",
        "definition_digest",
    }
)
_MAX_REFERENCES = 65536


def _identities(value: object, field: str) -> tuple[str, ...]:
    """Validate a bounded immutable sorted set of portable identity values."""
    if not isinstance(value, tuple) or not 1 <= len(value) <= _MAX_REFERENCES:
        raise ValueError("task identity arrays must be nonempty bounded tuples")
    items = tuple(require_identifier(item, field) for item in value)
    if items != tuple(sorted(set(items))):
        raise ValueError("task identities must be sorted and unique")
    return items


@dataclass(frozen=True)
class TaskDefinition1:
    """Declared task identity and scope, requiring an independent installed owner.

    This record is general task-source data. It neither changes the existing
    remediation WorkTask nor proves user authority, a claim or an actual event.
    """

    task_id: str
    revision: str
    actor_ids: tuple[str, ...]
    project_id: str
    group_id: str
    root_ids: tuple[str, ...]
    statement: str
    lifecycle: str
    definition_digest: str

    schema_version: ClassVar[str] = TASK_DEFINITION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "task-definition"

    def __post_init__(self) -> None:
        """Validate direct construction and the complete version-bound digest."""
        body = self._body()
        if require_digest(self.definition_digest, "task definition digest") != canonical_digest(
            body
        ):
            raise ValueError("task definition digest differs")

    def _body(self) -> dict[str, object]:
        """Return validated fields without altering declared text or identity order."""
        actors = _identities(self.actor_ids, "task actor identity")
        roots = _identities(self.root_ids, "task root identity")
        if len(actors) + len(roots) + 2 > _MAX_REFERENCES:
            raise ValueError("task definition exceeds the implementation reference ceiling")
        return {
            "schema_version": TASK_DEFINITION_SCHEMA_VERSION,
            "object_kind": "task-definition",
            "task_id": require_identifier(self.task_id, "task identity"),
            "revision": require_string(self.revision, "task revision"),
            "actor_ids": list(actors),
            "project_id": require_identifier(self.project_id, "task project identity"),
            "group_id": require_identifier(self.group_id, "task group identity"),
            "root_ids": list(roots),
            "statement": require_string(self.statement, "task statement"),
            "lifecycle": require_identifier(self.lifecycle, "task lifecycle"),
        }

    @classmethod
    def build(
        cls,
        *,
        task_id: str,
        revision: str,
        actor_ids: tuple[str, ...],
        project_id: str,
        group_id: str,
        root_ids: tuple[str, ...],
        statement: str,
        lifecycle: str,
        budget: PolicyReadBudget1,
    ) -> TaskDefinition1:
        """Build explicit general task data under the supplied parser reference budget."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if len(actor_ids) + len(root_ids) + 2 > limits.max_references:
            raise ValueError("task definition exceeds the reference budget")
        actors = _identities(actor_ids, "task actor identity")
        roots = _identities(root_ids, "task root identity")
        body: dict[str, object] = {
            "schema_version": TASK_DEFINITION_SCHEMA_VERSION,
            "object_kind": "task-definition",
            "task_id": task_id,
            "revision": revision,
            "actor_ids": list(actors),
            "project_id": project_id,
            "group_id": group_id,
            "root_ids": list(roots),
            "statement": statement,
            "lifecycle": lifecycle,
        }
        return cls.from_dict({**body, "definition_digest": canonical_digest(body)}, budget=budget)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> TaskDefinition1:
        """Parse closed general-task fields without appointing their trusted producer."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "task definition")
        require_exact_fields(data, _FIELDS, "task definition")
        if (
            data["schema_version"] != TASK_DEFINITION_SCHEMA_VERSION
            or data["object_kind"] != "task-definition"
        ):
            raise ValueError("unsupported task definition")
        actors = data["actor_ids"]
        roots = data["root_ids"]
        if not isinstance(actors, list) or not isinstance(roots, list):
            raise ValueError("task identity fields must be arrays")
        if len(actors) + len(roots) + 2 > limits.max_references:
            raise ValueError("task definition exceeds the reference budget")
        return cls(
            require_identifier(data["task_id"], "task identity"),
            require_string(data["revision"], "task revision"),
            _identities(tuple(actors), "task actor identity"),
            require_identifier(data["project_id"], "task project identity"),
            require_identifier(data["group_id"], "task group identity"),
            _identities(tuple(roots), "task root identity"),
            require_string(data["statement"], "task statement"),
            require_identifier(data["lifecycle"], "task lifecycle"),
            require_digest(data["definition_digest"], "task definition digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize exact declared data after revalidating direct instances."""
        body = self._body()
        digest = require_digest(self.definition_digest, "task definition digest")
        if digest != canonical_digest(body):
            raise ValueError("task definition digest differs")
        return {**body, "definition_digest": digest}

    def reference(self) -> dict[str, object]:
        """Return the exact typed reference to this integrity-checked definition."""
        checked = self.to_dict()
        body: dict[str, object] = {
            "schema_version": TYPED_OBJECT_REF_SCHEMA_VERSION,
            "object_kind": "typed-object-ref",
            "kind": "task-definition",
            "format_version": TASK_DEFINITION_SCHEMA_VERSION,
            "object_id": checked["task_id"],
            "object_digest": checked["definition_digest"],
        }
        return {**body, "ref_digest": canonical_digest(body)}

    def identity_digest(
        self,
        *,
        actor_id: str,
        root_id: str,
        budget: PolicyReadBudget1,
    ) -> str:
        """Derive the independent task identity before containing proofs or context.

        Parameters
        ----------
        actor_id : str
            Declared actor whose membership is checked, not authenticated here.
        root_id : str
            Declared root whose registry/current ownership must be checked by host.
        budget : PolicyReadBudget1
            Explicit reference ceiling used to revalidate the entire definition.

        Returns
        -------
        str
            Canonical identity digest with no enclosing context or producer proof.

        Raises
        ------
        ValueError
            Definition integrity, budget or declared membership is invalid.

        Notes
        -----
        An installed owner must still verify the retained source, actual registry,
        initiating authority and current observation before trusting this identity.
        """
        checked = TaskDefinition1.from_dict(self.to_dict(), budget=budget)
        actor = require_identifier(actor_id, "task identity actor")
        root = require_identifier(root_id, "task identity root")
        if actor not in checked.actor_ids or root not in checked.root_ids:
            raise ValueError("actor or root is outside the declared task definition")
        return canonical_digest(
            {
                "schema_version": TASK_IDENTITY_SCHEMA_VERSION,
                "object_kind": "task-identity",
                "task_id": checked.task_id,
                "task_definition": checked.reference(),
                "actor_id": actor,
                "project_id": checked.project_id,
                "group_id": checked.group_id,
                "root_id": root,
            }
        )
