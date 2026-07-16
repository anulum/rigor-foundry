# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — task-definition-bound work closure
"""Bind an immutable task definition to its verified closure event chain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .audit_primitives import canonical_digest, require_integer, require_mapping
from .model_primitives import require_digest, require_identifier
from .work_models import WorkEvent, WorkRecord, WorkTask

WORK_CLOSURE_SCHEMA_VERSION = "1.0"

_WORK_CLOSURE_FIELDS = frozenset(
    {
        "schema_version",
        "task_id",
        "definition_digest",
        "closure_event_digest",
        "event_count",
        "closure_digest",
    }
)


@dataclass(frozen=True)
class WorkClosure:
    """Content-addressed binding between one task and its closed event chain."""

    task_id: str
    definition_digest: str
    closure_event_digest: str
    event_count: int
    closure_digest: str

    @classmethod
    def build(cls, record: WorkRecord) -> WorkClosure:
        """Build a closure from one integrity-checked work record.

        Parameters
        ----------
        record:
            Work record containing exactly one independently verified closure.

        Returns
        -------
        WorkClosure
            Stable task-definition and event-chain binding.

        Raises
        ------
        ValueError
            If the work record has not reached the closed state.

        """
        task = WorkTask.from_dict(record.task.to_dict())
        events = tuple(WorkEvent.from_dict(event.to_dict()) for event in record.events)
        verified = WorkRecord.build(task, events)
        if verified != record:
            raise ValueError("work closure input is not an exact integrity-checked record")
        closed = tuple(event for event in verified.events if event.state == "closed")
        if len(closed) != 1:
            raise ValueError("work closure requires exactly one closed lifecycle event")
        event = closed[0]
        fields: dict[str, object] = {
            "schema_version": WORK_CLOSURE_SCHEMA_VERSION,
            "task_id": verified.task.task_id,
            "definition_digest": verified.task.definition_digest,
            "closure_event_digest": event.event_digest,
            "event_count": event.sequence,
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(cls, fields: dict[str, object], digest: str) -> WorkClosure:
        """Construct one closure from validated canonical fields."""
        return cls(
            task_id=cast(str, fields["task_id"]),
            definition_digest=cast(str, fields["definition_digest"]),
            closure_event_digest=cast(str, fields["closure_event_digest"]),
            event_count=cast(int, fields["event_count"]),
            closure_digest=digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete work-closure record."""
        return {
            "schema_version": WORK_CLOSURE_SCHEMA_VERSION,
            "task_id": self.task_id,
            "definition_digest": self.definition_digest,
            "closure_event_digest": self.closure_event_digest,
            "event_count": self.event_count,
            "closure_digest": self.closure_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkClosure:
        """Parse and integrity-check one work-closure record."""
        data = require_mapping(value, "work_closure")
        if frozenset(data) != _WORK_CLOSURE_FIELDS:
            raise ValueError("work-closure fields do not match schema")
        if data.get("schema_version") != WORK_CLOSURE_SCHEMA_VERSION:
            raise ValueError("unsupported work-closure schema version")
        fields: dict[str, object] = {
            "schema_version": WORK_CLOSURE_SCHEMA_VERSION,
            "task_id": require_identifier(data.get("task_id"), "work_closure.task_id"),
            "definition_digest": require_digest(
                data.get("definition_digest"),
                "work_closure.definition_digest",
            ),
            "closure_event_digest": require_digest(
                data.get("closure_event_digest"),
                "work_closure.closure_event_digest",
            ),
            "event_count": require_integer(
                data.get("event_count"),
                "work_closure.event_count",
                minimum=1,
            ),
        }
        recorded = require_digest(data.get("closure_digest"), "work_closure.closure_digest")
        if recorded != canonical_digest(fields):
            raise ValueError("work-closure digest does not match its content")
        return cls._from_fields(fields, recorded)

    def valid_for(self, record: WorkRecord) -> bool:
        """Return whether this closure exactly binds ``record``."""
        try:
            rebuilt = WorkClosure.build(record)
        except ValueError:
            return False
        return rebuilt == self
