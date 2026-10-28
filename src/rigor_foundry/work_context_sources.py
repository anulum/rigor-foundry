# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original remediation source projections
"""Retain original work definitions, full event chains and closures with fixed parsers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TypeAlias, cast

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .policy_read_budget import PolicyReadBudget1
from .typed_object_reference import TypedObjectRef1
from .work_closure import WORK_CLOSURE_SCHEMA_VERSION, WorkClosure
from .work_models import WORK_SCHEMA_VERSION, WorkEvent, WorkRecord, WorkTask

WorkSource: TypeAlias = WorkTask | WorkRecord | WorkClosure
_RECORD_FIELDS = frozenset({"schema_version", "object_kind", "task", "events"})


@dataclass(frozen=True)
class WorkRecordSource1:
    """Retained-source projection of an original unchanged WorkRecord.

    Parameters
    ----------
    record : WorkRecord
        Complete original task and event chain, rebuilt by its owning public API.
    budget : PolicyReadBudget1
        Explicit retained selection limits, excluded from the source wire identity.

    Raises
    ------
    ValueError
        If the actual record, original chain or explicit source limits fail.

    Notes
    -----
    The original WorkRecord has no serialization method. This source adapter
    preserves the retained-reader serialization interface without modifying it.
    """

    record: WorkRecord
    budget: PolicyReadBudget1 = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        """Validate actual original data and source limits on direct construction."""
        if type(self.record) is not WorkRecord:
            raise ValueError("actual original work record is required")
        work_context_source_data(self.record, budget=self.budget)

    def to_dict(self) -> dict[str, object]:
        """Serialize the complete original source projection under its held limits.

        Returns
        -------
        dict of str to object
            Exact original task and every original lifecycle event.

        Raises
        ------
        ValueError
            If original source types, budgets, integrity or chain relations fail.
        """
        return work_context_source_data(self.record, budget=self.budget)

    def reference(self) -> dict[str, object]:
        """Return the complete retained-source identity, distinct from event identity.

        Returns
        -------
        dict of str to object
            Exact source kind/version/task ID and complete projection digest.

        Raises
        ------
        ValueError
            If any original source or explicit allocation check refuses.
        """
        return work_context_source_reference(self.record, budget=self.budget).to_dict()


WorkSourceTarget: TypeAlias = WorkTask | WorkRecordSource1 | WorkClosure


def _budget(value: PolicyReadBudget1) -> PolicyReadBudget1:
    if type(value) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    return PolicyReadBudget1.from_dict(value.to_dict())


def _bound(value: object, limits: PolicyReadBudget1, remaining: list[int], depth: int = 0) -> None:
    if not isinstance(value, (dict, list, tuple)):
        return
    remaining[0] -= len(value)
    if remaining[0] < 0 or depth >= limits.max_depth:
        raise ValueError("work source exceeds its reference or depth budget")
    children = (
        tuple(require_mapping(value, "work source").values())
        if isinstance(value, dict)
        else cast(Sequence[object], value)
    )
    for child in children:
        _bound(child, limits, remaining, depth + 1)


def parse_work_context_source(
    kind: str, value: object, *, budget: PolicyReadBudget1
) -> WorkSource:
    """Resolve only original work records under explicit allocation bounds.

    Parameters
    ----------
    kind : str
        Exact work-task, work-record or work-closure source role.
    value : object
        Original task/closure data or the complete retained task/event projection.
    budget : PolicyReadBudget1
        Aggregate collection and nesting limits before owning parser allocation.

    Returns
    -------
    WorkTask or WorkRecord or WorkClosure
        Actual original owning model; parsing confers no current authority.

    Raises
    ------
    ValueError
        If a role, closed field, budget, original digest or event relation fails.
    """
    limits = _budget(budget)
    if kind not in {"work-task", "work-record", "work-closure"}:
        raise ValueError("unsupported original work source kind")
    _bound(value, limits, [limits.max_references])
    data = require_mapping(value, "work source")
    if kind == "work-task":
        return WorkTask.from_dict(data)
    if kind == "work-closure":
        return WorkClosure.from_dict(data)
    require_exact_fields(data, _RECORD_FIELDS, "retained work record")
    if data["schema_version"] != WORK_SCHEMA_VERSION or data["object_kind"] != "work-record":
        raise ValueError("unsupported retained work record")
    raw = data["events"]
    if not isinstance(raw, list):
        raise ValueError("retained work events must be an array")
    task = WorkTask.from_dict(data["task"])
    return WorkRecord.build(task, tuple(WorkEvent.from_dict(item) for item in raw))


def work_context_source_data(value: WorkSource, *, budget: PolicyReadBudget1) -> dict[str, object]:
    """Serialize a verified original model without changing its legacy child bytes.

    Parameters
    ----------
    value : WorkTask or WorkRecord or WorkClosure
        Actual original model, not an envelope appointed by decoded metadata.
    budget : PolicyReadBudget1
        Explicit whole source collection and nesting ceilings.

    Returns
    -------
    dict of str to object
        Original task/closure wire or the new exact retained full-record projection.

    Raises
    ------
    ValueError
        If types, original integrity, event relations or allocation limits fail.

    Notes
    -----
    WorkRecord previously has no public serialization or complete object digest.
    Its retained-source projection binds the exact original task and all events.
    It does not replace an existing event, definition or closure digest.
    """
    limits = _budget(budget)
    if type(value) not in {WorkTask, WorkRecord, WorkClosure}:
        raise ValueError("actual original work model is required")
    if isinstance(value, WorkRecord):
        if (
            type(value.task) is not WorkTask
            or type(value.events) is not tuple
            or len(value.events) > limits.max_references
            or any(type(event) is not WorkEvent for event in value.events)
        ):
            raise ValueError("work record requires bounded actual immutable children")
        task, events = value.task, value.events
    elif isinstance(value, WorkTask):
        task, events = value, ()
    else:
        task, events = None, ()
    count = len(events)
    if task is not None:
        count += sum(
            len(items)
            for items in (
                task.dependencies,
                task.acceptance_gates,
                task.affected_surfaces,
                task.prohibited_shortcuts,
            )
        )
    for event in events:
        count += len(event.evidence) + sum(len(item.command) for item in event.evidence)
    if count > limits.max_references:
        raise ValueError("work source exceeds its reference budget before serialization")
    if isinstance(value, WorkRecord):
        kind = "work-record"
        data: dict[str, object] = {
            "schema_version": WORK_SCHEMA_VERSION,
            "object_kind": kind,
            "task": value.task.to_dict(),
            "events": [event.to_dict() for event in value.events],
        }
    else:
        kind = "work-task" if isinstance(value, WorkTask) else "work-closure"
        data = value.to_dict()
    checked = parse_work_context_source(kind, data, budget=limits)
    if checked != value:
        raise ValueError("original work object differs from its verified source")
    return data


def work_context_source_reference(
    value: WorkSource, *, budget: PolicyReadBudget1
) -> TypedObjectRef1:
    """Derive an exact reference from the original owning model and complete projection.

    Parameters
    ----------
    value : WorkTask or WorkRecord or WorkClosure
        Actual model whose original integrity is revalidated.
    budget : PolicyReadBudget1
        Explicit complete source allocation limits.

    Returns
    -------
    TypedObjectRef1
        Original definition/closure identity or complete retained-record identity.

    Raises
    ------
    ValueError
        If the original source model or allocation contract is invalid.
    """
    data = work_context_source_data(value, budget=budget)
    if isinstance(value, WorkTask):
        kind, identity, digest, version = (
            "work-task",
            value.task_id,
            value.definition_digest,
            WORK_SCHEMA_VERSION,
        )
    elif isinstance(value, WorkClosure):
        kind, identity, digest, version = (
            "work-closure",
            value.task_id,
            value.closure_digest,
            WORK_CLOSURE_SCHEMA_VERSION,
        )
    else:
        kind, identity, digest, version = (
            "work-record",
            value.task.task_id,
            canonical_digest(data),
            WORK_SCHEMA_VERSION,
        )
    return TypedObjectRef1.build(
        kind=kind, format_version=version, object_id=identity, object_digest=digest
    )
