# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — work closure identity tests
"""Verify task-bound closure identity through real lifecycle records."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import cast

import pytest
from test_work_models import lifecycle

import rigor_foundry.models as models_module
from rigor_foundry.work_closure import WorkClosure
from rigor_foundry.work_models import WorkEvent, WorkRecord, WorkTask


def test_closure_identity_round_trips_and_rejects_forged_records() -> None:
    """Closure identity binds the exact task and closed-event chain."""
    definition, events = lifecycle()
    record = WorkRecord.build(definition, events)
    closure = WorkClosure.build(record)
    assert WorkClosure.from_dict(closure.to_dict()) == closure
    assert closure.valid_for(record)
    assert WorkClosure.build(WorkRecord.build(definition, events[:7])) == closure

    unclosed = WorkRecord.build(definition, events[:6])
    with pytest.raises(ValueError, match="exactly one closed"):
        WorkClosure.build(unclosed)
    assert not closure.valid_for(unclosed)

    forged_task = replace(definition, definition_digest="0" * 64)
    with pytest.raises(ValueError, match="task definition digest"):
        WorkClosure.build(WorkRecord.build(forged_task, events))
    forged_event = replace(events[6], event_digest="0" * 64)
    with pytest.raises(ValueError, match="work-event digest"):
        WorkClosure.build(WorkRecord.build(definition, (*events[:6], forged_event)))
    noncanonical_record = WorkRecord(
        task=definition,
        events=cast(tuple[WorkEvent, ...], list(events)),
    )
    with pytest.raises(ValueError, match="exact integrity-checked"):
        WorkClosure.build(noncanonical_record)

    for field, value, message in (
        ("schema_version", "9", "schema"),
        ("definition_digest", "0" * 64, "digest does not match"),
        ("closure_event_digest", "0" * 64, "digest does not match"),
        ("event_count", 0, "integer"),
        ("closure_digest", "0" * 64, "digest does not match"),
    ):
        encoded = deepcopy(closure.to_dict())
        encoded[field] = value
        with pytest.raises(ValueError, match=message):
            WorkClosure.from_dict(encoded)
    unknown = closure.to_dict()
    unknown["unbound"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        WorkClosure.from_dict(unknown)

    task_data = definition.to_dict()
    task_data.pop("definition_digest")
    task_data["created_at"] = "2026-07-15T10:06:00Z"
    task_data["definition_digest"] = models_module.canonical_digest(task_data)
    changed_task = WorkTask.from_dict(task_data)
    changed_closure = WorkClosure.build(WorkRecord.build(changed_task, events))
    assert changed_closure.closure_event_digest == closure.closure_event_digest
    assert changed_closure.closure_digest != closure.closure_digest
    assert not closure.valid_for(WorkRecord.build(changed_task, events))
