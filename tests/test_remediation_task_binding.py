# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original remediation source binding tests
"""Verify real retained work files and complete original task/event/closure relationships."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_maintained_surface import rehashed
from test_task_definition import definition
from test_work_context_sources import sources

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.remediation_task_binding import RemediationSources, RemediationTaskBinding1
from rigor_foundry.typed_object_reference import TypedObjectRef1
from rigor_foundry.work_closure import WorkClosure
from rigor_foundry.work_context_sources import (
    WorkSource,
    work_context_source_data,
    work_context_source_reference,
)
from rigor_foundry.work_models import WorkTask


def binding() -> RemediationTaskBinding1:
    """Bind original validated work-model identities as inert source metadata."""
    values = sources()
    refs = tuple(work_context_source_reference(v, budget=implementation_budget()) for v in values)
    return RemediationTaskBinding1.build(
        task=refs[0],
        record=refs[1],
        closure=refs[2],
        budget=implementation_budget(),
    )


@contextmanager
def retained(path: Path, value: WorkSource) -> Iterator[RetainedContextSource]:
    """Retain a real original work source in its own stable parent directory."""
    path.parent.mkdir(parents=True)
    limits = implementation_budget()
    payload = json.dumps(work_context_source_data(value, budget=limits)).encode()
    path.write_bytes(payload)
    with RetainedContextSource(
        path,
        reference=work_context_source_reference(value, budget=limits),
        raw_digest=hashlib.sha256(payload).hexdigest(),
        budget=limits,
    ) as source:
        yield source


@pytest.mark.parametrize("count", (1, 2, 3))
def test_actual_retained_sources_bind_optional_original_records_and_closures(
    tmp_path: Path, count: int
) -> None:
    """Definitions need no invented closure; present closures require the complete original record."""
    with ExitStack() as stack:
        held = [
            stack.enter_context(retained(tmp_path / f"source{i}/source.json", value))
            for i, value in enumerate(sources()[:count])
        ]
        owner = RemediationSources(
            held[0],
            None if count < 2 else held[1],
            None if count < 3 else held[2],
        )
        actual = owner.observe(budget=implementation_budget())
        assert actual.task == held[0].reference
        assert (actual.record is None) is (count < 2)
        assert (actual.closure is None) is (count < 3)
        assert (
            RemediationTaskBinding1.from_dict(
                json.loads(json.dumps(actual.to_dict())), budget=implementation_budget()
            )
            == actual
        )
        assert owner.observe(budget=implementation_budget()) == actual
        assert held[0].read() == sources()[0]


@pytest.mark.parametrize(
    "fault", ("task-role", "record-role", "closure-role", "definition", "closure-definition")
)
def test_actual_original_source_role_or_definition_disagreement_refuses(
    tmp_path: Path, fault: str
) -> None:
    """Matching task labels never replace exact definitions or original closure identity."""
    originals = list(sources())
    if fault == "task-role":
        originals[0] = originals[2]
    elif fault == "record-role":
        originals[1] = originals[0]
    elif fault == "closure-role":
        originals[2] = originals[0]
    elif fault == "definition":
        original = originals[0]
        assert isinstance(original, WorkTask)
        data = original.to_dict()
        data["title"] = "Another actual source definition"
        data.pop("definition_digest")
        originals[0] = WorkTask.from_dict({**data, "definition_digest": canonical_digest(data)})
    else:
        original_closure = originals[2]
        assert isinstance(original_closure, WorkClosure)
        data = original_closure.to_dict()
        data["definition_digest"] = "f" * 64
        originals[2] = WorkClosure.from_dict(rehashed(data, "closure_digest"))
    with ExitStack() as stack:
        held = [
            stack.enter_context(retained(tmp_path / f"source{i}/source.json", value))
            for i, value in enumerate(originals)
        ]
        with pytest.raises(ValueError):
            RemediationSources(*held).observe(budget=implementation_budget())


def test_remediation_binding_versions_types_reference_roles_and_budgets_refuse() -> None:
    """Closed parsing does not enrol a provider or accept unrelated original task identities."""
    value = binding()
    for data in [
        {**value.to_dict(), "loader": "caller"},
        rehashed({**value.to_dict(), "schema_version": "2.0"}, "binding_digest"),
        rehashed({**value.to_dict(), "object_kind": "other"}, "binding_digest"),
    ]:
        with pytest.raises(ValueError):
            RemediationTaskBinding1.from_dict(data, budget=implementation_budget())
    wrong = TypedObjectRef1.from_dict(definition().reference())
    with pytest.raises(ValueError):
        replace(value, task=wrong)
    with pytest.raises(ValueError):
        replace(value, record=wrong)
    with pytest.raises(ValueError):
        replace(value, closure=wrong)
    with pytest.raises(ValueError, match="different original"):
        replace(
            value,
            record=TypedObjectRef1.build(
                kind="work-record",
                format_version="1.0",
                object_id="another",
                object_digest="d" * 64,
            ),
        )
    with pytest.raises(ValueError, match="original full record"):
        replace(value, record=None)
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, binding_digest="f" * 64)
    with pytest.raises(ValueError):
        replace(value, task=cast(TypedObjectRef1, {}))
    with pytest.raises(ValueError, match="reference budget"):
        RemediationTaskBinding1.from_dict(
            value.to_dict(), budget=implementation_budget(max_references=1)
        )
    for limits in (cast(PolicyReadBudget1, {}), implementation_budget(max_references=1)):
        with pytest.raises(ValueError):
            RemediationTaskBinding1.build(
                task=value.task,
                record=value.record,
                closure=value.closure,
                budget=limits,
            )
    with pytest.raises(ValueError):
        RemediationTaskBinding1.from_dict(value.to_dict(), budget=cast(PolicyReadBudget1, {}))
    for wrong_pair in [
        (cast(TypedObjectRef1, {}), None),
        (value.task, cast(TypedObjectRef1, {})),
    ]:
        with pytest.raises(ValueError, match="actual remediation"):
            RemediationTaskBinding1.build(
                task=wrong_pair[0],
                record=wrong_pair[1],
                closure=None,
                budget=implementation_budget(),
            )
    for args in [
        (cast(RetainedContextSource, {}), None, None),
        (cast(RetainedContextSource, {}), cast(RetainedContextSource, {}), None),
    ]:
        with pytest.raises(ValueError, match="actual retained"):
            RemediationSources(*args)


def test_actual_remediation_selection_refuses_missing_record_and_closed_use(
    tmp_path: Path,
) -> None:
    """Borrowed retained sources remain required until the final real consumer read."""
    with retained(tmp_path / "task/source.json", sources()[0]) as source:
        with pytest.raises(ValueError, match="original full record"):
            RemediationSources(source, closure=source)
        with pytest.raises(ValueError, match="actual retained"):
            RemediationSources(source, record=cast(RetainedContextSource, {}))
        owner = RemediationSources(source)
        source.close()
        with pytest.raises(ValueError, match="closed"):
            owner.observe(budget=implementation_budget())
