# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original remediation context bindings
"""Bind actual retained remediation definitions and complete original lifecycle records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .context_source_lease import RetainedContextSource
from .model_primitives import require_digest
from .policy_read_budget import PolicyReadBudget1
from .typed_object_reference import TypedObjectRef1
from .work_closure import WorkClosure
from .work_context_sources import WorkRecordSource1, work_context_source_reference
from .work_models import WorkRecord, WorkTask

REMEDIATION_TASK_BINDING_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {"schema_version", "object_kind", "task", "record", "closure", "binding_digest"}
)


@dataclass(frozen=True)
class RemediationTaskBinding1:
    """Closed references whose actual original definition/event relations need verification.

    Parameters
    ----------
    task : TypedObjectRef1
        Original WorkTask1 definition identity.
    record, closure : TypedObjectRef1 or None
        Optional original complete event record and its independently verified closure.
    binding_digest : str
        Complete metadata identity; parsing does not verify actual retained sources.
    """

    task: TypedObjectRef1
    record: TypedObjectRef1 | None
    closure: TypedObjectRef1 | None
    binding_digest: str
    schema_version: ClassVar[str] = REMEDIATION_TASK_BINDING_SCHEMA_VERSION
    object_kind: ClassVar[str] = "remediation-task-binding"

    def __post_init__(self) -> None:
        """Validate direct immutable source references and the complete binding digest."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        refs = (self.task, self.record, self.closure)
        for ref, kind in zip(refs, ("work-task", "work-record", "work-closure"), strict=True):
            if ref is None and kind != "work-task":
                continue
            if type(ref) is not TypedObjectRef1 or (ref.kind, ref.format_version) != (kind, "1.0"):
                raise ValueError(
                    "remediation binding requires original fixed work reference kinds"
                )
            ref.to_dict()
        if self.closure is not None and self.record is None:
            raise ValueError("a remediation closure requires its original full record")
        if any(ref is not None and ref.object_id != self.task.object_id for ref in refs):
            raise ValueError("remediation references name different original task identities")
        return {
            "schema_version": REMEDIATION_TASK_BINDING_SCHEMA_VERSION,
            "object_kind": "remediation-task-binding",
            "task": self.task.to_dict(),
            "record": None if self.record is None else self.record.to_dict(),
            "closure": None if self.closure is None else self.closure.to_dict(),
        }

    @classmethod
    def build(
        cls,
        *,
        task: TypedObjectRef1,
        record: TypedObjectRef1 | None,
        closure: TypedObjectRef1 | None,
        budget: PolicyReadBudget1,
    ) -> RemediationTaskBinding1:
        """Build a bounded exact reference binding without authenticating source metadata.

        Parameters
        ----------
        task, record, closure : TypedObjectRef1 or None
            Original definition and optional record/closure references.
        budget : PolicyReadBudget1
            Explicit aggregate nested-reference ceiling.

        Returns
        -------
        RemediationTaskBinding1
            Integrity-checked data, still requiring actual source verification.

        Raises
        ------
        ValueError
            If fixed kinds, identity relations, source shapes or budgets disagree.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if sum(ref is not None for ref in (task, record, closure)) > limits.max_references:
            raise ValueError("remediation references exceed the reference budget")
        if type(task) is not TypedObjectRef1 or any(
            ref is not None and type(ref) is not TypedObjectRef1 for ref in (record, closure)
        ):
            raise ValueError("actual remediation source references are required")
        body = {
            "schema_version": REMEDIATION_TASK_BINDING_SCHEMA_VERSION,
            "object_kind": "remediation-task-binding",
            "task": task.to_dict(),
            "record": None if record is None else record.to_dict(),
            "closure": None if closure is None else closure.to_dict(),
        }
        return cls.from_dict({**body, "binding_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RemediationTaskBinding1:
        """Parse only exact original remediation reference/version relationships.

        Parameters
        ----------
        value : object
            Complete decoded binding mapping.
        budget : PolicyReadBudget1
            Explicit whole reference-allocation ceiling.

        Returns
        -------
        RemediationTaskBinding1
            Closed integrity-checked original references.

        Raises
        ------
        ValueError
            If fields, versions, counts or the final binding digest fail.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "remediation task binding")
        require_exact_fields(data, _FIELDS, "remediation task binding")
        if data["schema_version"] != "1.0" or data["object_kind"] != "remediation-task-binding":
            raise ValueError("unsupported remediation task binding")
        if (
            sum(data[name] is not None for name in ("task", "record", "closure"))
            > limits.max_references
        ):
            raise ValueError("remediation references exceed the reference budget")
        return cls(
            TypedObjectRef1.from_dict(data["task"]),
            None if data["record"] is None else TypedObjectRef1.from_dict(data["record"]),
            None if data["closure"] is None else TypedObjectRef1.from_dict(data["closure"]),
            require_digest(data["binding_digest"], "remediation binding digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate and serialize the entire original reference binding.

        Returns
        -------
        dict of str to object
            Exact original references and their complete binding identity.

        Raises
        ------
        ValueError
            If kinds, task identities, optional dependencies or integrity disagree.
        """
        body = self._body()
        digest = require_digest(self.binding_digest, "remediation binding digest")
        if digest != canonical_digest(body):
            raise ValueError("remediation binding digest differs")
        return {**body, "binding_digest": digest}


@dataclass(frozen=True)
class RemediationSources:
    """Actual host-retained original work sources borrowed for complete revalidation.

    Parameters
    ----------
    task : RetainedContextSource
        Independently selected original WorkTask source.
    record, closure : RetainedContextSource or None
        Optional actual complete event record and closure selections.

    Raises
    ------
    ValueError
        If source entries are metadata, wrong types or a closure omits its record.

    Notes
    -----
    These entries remain host-owned and must stay open through the consumer.
    Source identity does not authenticate an initiating event or grant permission.
    """

    task: RetainedContextSource
    record: RetainedContextSource | None = None
    closure: RetainedContextSource | None = None

    def __post_init__(self) -> None:
        """Accept only actual retained selections and complete optional dependencies."""
        if type(self.task) is not RetainedContextSource or any(
            source is not None and type(source) is not RetainedContextSource
            for source in (self.record, self.closure)
        ):
            raise ValueError("actual retained remediation source entries are required")
        if self.closure is not None and self.record is None:
            raise ValueError("a remediation closure requires its original full record")

    def observe(self, *, budget: PolicyReadBudget1) -> RemediationTaskBinding1:
        """Rebuild the complete original definition/event/closure source relationships.

        Parameters
        ----------
        budget : PolicyReadBudget1
            Explicit source/reference allocation ceilings.

        Returns
        -------
        RemediationTaskBinding1
            Data compared with these actual original retained entries.

        Raises
        ------
        ValueError, RuntimeError, OSError
            If any original selection, type, complete chain or closing read refuses.
        """
        self.__post_init__()
        task = self.task.read()
        record_source = None if self.record is None else self.record.read()
        closure = None if self.closure is None else self.closure.read()
        if (
            type(task) is not WorkTask
            or (record_source is not None and type(record_source) is not WorkRecordSource1)
            or (closure is not None and type(closure) is not WorkClosure)
        ):
            raise ValueError("remediation source differs from its actual fixed work role")
        record = record_source.record if isinstance(record_source, WorkRecordSource1) else None
        if isinstance(record, WorkRecord) and record.task != task:
            raise ValueError("original record differs from the selected task definition")
        if isinstance(closure, WorkClosure) and (
            not isinstance(record, WorkRecord) or not closure.valid_for(record)
        ):
            raise ValueError("original closure differs from the selected complete record")
        result = RemediationTaskBinding1.build(
            task=work_context_source_reference(task, budget=budget),
            record=None
            if record is None
            else work_context_source_reference(record, budget=budget),
            closure=None
            if closure is None
            else work_context_source_reference(closure, budget=budget),
            budget=budget,
        )
        for source in (self.task, self.record, self.closure):
            if source is not None:
                source.read()
        return result
