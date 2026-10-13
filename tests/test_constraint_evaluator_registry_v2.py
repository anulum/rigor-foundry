# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed built-in evaluator registry tests
"""Exercise exact registry bytes after code identity moved to the host pin."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from rigor_foundry.constraint_evaluator_registry_v2 import (
    BUILTIN_EVALUATORS_V2,
    ConstraintEvaluatorRegistryV2,
)
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.project_registry_primitives import project_registry_strict_json


def _changed(**fields: object) -> bytes:
    """Return re-canonicalized bytes after one registry body mutation."""
    body = cast(
        dict[str, object],
        project_registry_strict_json(ConstraintEvaluatorRegistryV2.build().body_bytes),
    )
    body.update(fields)
    return canonical_journal_json_v2(body)


def test_fixed_registry_binds_four_subjects_without_code_loading() -> None:
    """The registry has one ID per subject and no executable loader."""
    registry = ConstraintEvaluatorRegistryV2.build()
    assert ConstraintEvaluatorRegistryV2.from_bytes(registry.body_bytes) == registry
    assert all(
        registry.has_subject_evaluator(subject, identifier)
        for identifier, subject in BUILTIN_EVALUATORS_V2
    )
    assert not registry.has_subject_evaluator("rate", "builtin.window.v2")
    assert b"admission_code_digest" not in registry.body_bytes


@pytest.mark.parametrize(
    "value",
    [
        [],
        [{"id": "builtin.rate.v2", "subject": "rate"}],
        [
            {"id": identifier, "subject": subject}
            for identifier, subject in reversed(BUILTIN_EVALUATORS_V2)
        ],
        [{"id": identifier, "subject": subject} for identifier, subject in BUILTIN_EVALUATORS_V2]
        + [{"id": "builtin.rate.v2", "subject": "rate"}],
    ],
)
def test_incomplete_unsorted_or_duplicate_evaluators_refuse(value: list[object]) -> None:
    """A new pinned digest cannot admit a different four-subject mapping."""
    with pytest.raises(ValueError, match="v2 content differs"):
        ConstraintEvaluatorRegistryV2.from_bytes(_changed(evaluators=value))


def test_legacy_fields_wrong_subject_code_or_noncanonical_bytes_refuse() -> None:
    """Only the fixed evaluator registry shape and canonical encoding are accepted."""
    with pytest.raises(ValueError, match="fields differ"):
        ConstraintEvaluatorRegistryV2.from_bytes(_changed(code_digest="b" * 64))
    with pytest.raises(ValueError, match="fields differ"):
        ConstraintEvaluatorRegistryV2.from_bytes(_changed(admission_code_digest="a" * 64))
    with pytest.raises(ValueError, match="v2 content differs"):
        ConstraintEvaluatorRegistryV2.from_bytes(_changed(schema="wrong"))
    registry = ConstraintEvaluatorRegistryV2.build()
    with pytest.raises(ValueError, match="not canonical"):
        ConstraintEvaluatorRegistryV2.from_bytes(registry.body_bytes + b"\n")
    with pytest.raises(ValueError, match="strict JSON"):
        ConstraintEvaluatorRegistryV2.from_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(ValueError, match="must be bytes"):
        ConstraintEvaluatorRegistryV2.from_bytes(cast(bytes, "not bytes"))
    assert replace(registry, registry_digest="b" * 64) != registry
