# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original work context source tests
"""Exercise actual legacy definitions, full lifecycle source files and closed parsers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_work_models import lifecycle, task

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.context_source_resolution import parse_context_source_target
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.work_closure import WorkClosure
from rigor_foundry.work_context_sources import (
    WorkRecordSource1,
    WorkSource,
    parse_work_context_source,
    work_context_source_data,
    work_context_source_reference,
)
from rigor_foundry.work_models import WorkEvent, WorkRecord, WorkTask


def sources() -> tuple[WorkSource, ...]:
    """Use original public work-model builders and their complete actual lifecycle."""
    definition, events = lifecycle()
    record = WorkRecord.build(definition, events)
    return definition, record, WorkClosure.build(record)


@pytest.mark.parametrize("position", (0, 1, 2))
def test_actual_original_sources_round_trip_through_retained_files(
    tmp_path: Path, position: int
) -> None:
    """Fixed owning parsers preserve definition/closure and complete event-chain identities."""
    original = sources()[position]
    limits = implementation_budget()
    payload = json.dumps(work_context_source_data(original, budget=limits)).encode()
    ref = work_context_source_reference(original, budget=limits)
    path = tmp_path / "source.json"
    path.write_bytes(payload)
    with RetainedContextSource(
        path,
        reference=ref,
        raw_digest=hashlib.sha256(payload).hexdigest(),
        budget=limits,
    ) as retained:
        parsed = retained.read()
        if isinstance(original, WorkRecord):
            assert isinstance(parsed, WorkRecordSource1)
            assert parsed.record == original
            assert parsed.to_dict() == json.loads(payload)
            assert parsed.reference() == ref.to_dict()
            assert parsed == WorkRecordSource1(
                original, implementation_budget(max_references=2048)
            )
        else:
            assert parsed == original
        assert parse_context_source_target(ref, json.loads(payload), budget=limits) == parsed
    assert ref.object_id == task().task_id
    if isinstance(original, WorkRecord):
        assert ref.object_digest == canonical_digest(json.loads(payload))
        assert ref.object_digest != original.current.event_digest
    else:
        expected = (
            original.definition_digest
            if isinstance(original, WorkTask)
            else original.closure_digest
        )
        assert ref.object_digest == expected


@pytest.mark.parametrize("fault", ("version", "kind", "extra", "events", "chain", "task"))
def test_complete_record_source_refuses_malformed_or_unjoined_children(fault: str) -> None:
    """Unmodified original owner parsers revalidate every retained child and transition."""
    limits = implementation_budget()
    data = work_context_source_data(sources()[1], budget=limits)
    if fault == "version":
        data["schema_version"] = "2.0"
    elif fault == "kind":
        data["object_kind"] = "caller-record"
    elif fault == "extra":
        data["loader"] = "caller"
    elif fault == "events":
        data["events"] = ()
    elif fault == "chain":
        events = cast(list[dict[str, object]], data["events"])
        data["events"] = events[1:]
    else:
        data["task"] = {}
    with pytest.raises(ValueError):
        parse_work_context_source("work-record", data, budget=limits)


def test_original_definition_changes_propagate_to_complete_record_source_identity() -> None:
    """Equal old event chains cannot hide a changed original task definition."""
    definition, events = lifecycle()
    data = definition.to_dict()
    data["title"] = "Another original remediation definition"
    data.pop("definition_digest")
    data["definition_digest"] = canonical_digest(data)
    altered = type(definition).from_dict(data)
    limits = implementation_budget()
    original = work_context_source_reference(WorkRecord.build(definition, events), budget=limits)
    changed = work_context_source_reference(WorkRecord.build(altered, events), budget=limits)
    assert original.object_digest != changed.object_digest


def test_work_source_allocation_types_and_complete_object_integrity_refuse() -> None:
    """Budgets precede child materialisation and no arbitrary source kind chooses a parser."""
    limits = implementation_budget()
    original = sources()[1]
    with pytest.raises(ValueError, match="unsupported"):
        parse_work_context_source("caller", {}, budget=limits)
    with pytest.raises(ValueError, match="budget is required"):
        parse_work_context_source("work-task", {}, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="actual original"):
        work_context_source_data(cast(WorkSource, {}), budget=limits)
    with pytest.raises(ValueError, match="actual original work record"):
        WorkRecordSource1(cast(WorkRecord, {}), limits)
    for data in [{}, {"task": [0] * 8}, {"task": {"nested": {"deep": []}}}]:
        with pytest.raises(ValueError):
            parse_work_context_source(
                "work-task", data, budget=implementation_budget(max_references=4, max_depth=2)
            )
    assert isinstance(original, WorkRecord)
    for wrong in [
        replace(original, task=cast(WorkTask, {})),
        replace(original, events=cast(tuple[WorkEvent, ...], [])),
        replace(original, events=cast(tuple[WorkEvent, ...], (None,))),
        replace(original, events=original.events * 20),
    ]:
        with pytest.raises(ValueError, match="bounded actual"):
            work_context_source_data(wrong, budget=implementation_budget(max_references=10))
    with pytest.raises(ValueError, match="before serialization"):
        work_context_source_data(original, budget=implementation_budget(max_references=10))
    bad_event = replace(original.events[0], reason="changed without original event digest")
    with pytest.raises(ValueError):
        work_context_source_data(
            replace(original, events=(bad_event, *original.events[1:])), budget=limits
        )
    with pytest.raises(ValueError, match="differs from its verified"):
        work_context_source_data(
            replace(task(), dependencies=cast(tuple[str, ...], [])), budget=limits
        )
