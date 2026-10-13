# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 Stage B result wire tests
"""Exercise admitted-part records through the public parser and export."""

import copy
import json
from typing import cast

import pytest

from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.models import canonical_digest
from rigor_foundry.stage_b_result_v2 import STAGE_B_RESULT_SCHEMA_V2, StageBResultV2


def _body() -> dict[str, object]:
    """Build a closed structural result fixture without asserting selected evaluation."""
    return {
        "schema": STAGE_B_RESULT_SCHEMA_V2,
        "part_index": 0,
        "outcome": "admit",
        "effect_class": "local-file-write",
        "target_ref": {"form": "path", "value": "/tmp/output"},
        "admitting_clause_digests": ["1" * 64, "2" * 64],
        "constraint_results": [
            {
                "clause_digest": "3" * 64,
                "subject": "rate",
                "evaluator_id": "builtin.rate.v2",
                "result": "pass",
            },
            {
                "clause_digest": "4" * 64,
                "subject": "window",
                "evaluator_id": "builtin.window.v2",
                "result": "pass",
            },
        ],
        "semantics_set_digest": "5" * 64,
        "scope_expansion_digest": "6" * 64,
    }


def test_admitted_part_has_exact_canonical_digest_and_roundtrip() -> None:
    """Bind canonical result round trips and every changed digest field to exact result bytes."""
    body = _body()
    result = StageBResultV2.from_dict(body)
    assert result.to_dict() == body
    assert result.body_bytes == canonical_journal_json_v2(body)
    assert result.result_digest == canonical_digest(body)
    changed = copy.deepcopy(body)
    changed["scope_expansion_digest"] = "7" * 64
    assert StageBResultV2.from_dict(changed).result_digest != result.result_digest
    with pytest.raises(ValueError, match="canonical bytes"):
        StageBResultV2(result.body_bytes, "0" * 64).to_dict()
    with pytest.raises(ValueError, match="bytes differ"):
        StageBResultV2(cast(bytes, "not bytes"), result.result_digest).to_dict()
    with pytest.raises(ValueError):
        StageBResultV2(b"not json", result.result_digest).to_dict()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema", "other"),
        ("part_index", True),
        ("part_index", -1),
        ("outcome", "refuse"),
        ("effect_class", "unknown"),
        ("effect_class", []),
        ("target_ref", {"form": "path", "value": "relative"}),
        ("admitting_clause_digests", []),
        ("admitting_clause_digests", "not a list"),
        ("admitting_clause_digests", ["2" * 64, "1" * 64]),
        ("admitting_clause_digests", ["1" * 64, "1" * 64]),
        ("admitting_clause_digests", ["bad"]),
        ("constraint_results", "not a list"),
        ("constraint_results", [{"clause_digest": "3" * 64, "subject": "rate"}]),
        ("semantics_set_digest", "bad"),
        ("scope_expansion_digest", "bad"),
    ],
)
def test_invalid_top_level_field_refuses(field: str, replacement: object) -> None:
    """Reject invalid top-level admission-result values through the public parser."""
    body = _body()
    body[field] = replacement
    with pytest.raises(ValueError):
        StageBResultV2.from_dict(body)


def test_missing_or_extra_field_refuses() -> None:
    """Require the exact closed admission-result field set."""
    body = _body()
    del body["target_ref"]
    with pytest.raises(ValueError):
        StageBResultV2.from_dict(body)
    body = _body()
    body["extra"] = "value"
    with pytest.raises(ValueError):
        StageBResultV2.from_dict(body)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("clause_digest", "bad"),
        ("subject", "unknown"),
        ("subject", []),
        ("evaluator_id", "bad id"),
        ("evaluator_id", "builtin.window.v2"),
        ("result", "refuse"),
        ("extra", "value"),
    ],
)
def test_invalid_constraint_field_refuses(field: str, replacement: object) -> None:
    """Reject invalid constraint-row values within an otherwise valid admission result."""
    body = _body()
    rows = cast(list[dict[str, object]], body["constraint_results"])
    rows[0][field] = replacement
    with pytest.raises(ValueError):
        StageBResultV2.from_dict(body)


def test_constraint_order_uniqueness_and_subject_collision_refuse() -> None:
    """Require ordered unique constraint identities disjoint from admitting clause identities."""
    body = _body()
    rows = cast(list[dict[str, object]], body["constraint_results"])
    rows.reverse()
    with pytest.raises(ValueError, match="sorted and unique"):
        StageBResultV2.from_dict(body)
    body = _body()
    rows = cast(list[dict[str, object]], body["constraint_results"])
    rows[1]["clause_digest"] = rows[0]["clause_digest"]
    with pytest.raises(ValueError, match="sorted and unique"):
        StageBResultV2.from_dict(body)
    body = _body()
    rows = cast(list[dict[str, object]], body["constraint_results"])
    rows[0]["clause_digest"] = "1" * 64
    with pytest.raises(ValueError, match="both admit and constrain"):
        StageBResultV2.from_dict(body)


def test_empty_constraint_list_is_valid_but_result_requires_an_admit() -> None:
    """Preserve a valid empty constraint array within an otherwise admitted canonical result."""
    body = _body()
    body["constraint_results"] = []
    result = StageBResultV2.from_dict(body)
    assert json.loads(result.body_bytes)["constraint_results"] == []
