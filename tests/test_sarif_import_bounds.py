# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded and typed SARIF value reading tests
"""Verify the one field rule and the byte bounds on values of a real exported SARIF result."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.sarif_import_bounds import (
    ResultSkipped,
    bounded_text,
    bounded_value,
    json_bytes,
    present_field,
)

ROOT = Path(__file__).resolve().parents[1]
REAL_SARIF = ROOT / "tests/fixtures/sarif/canonical-states.sarif"


def _result() -> dict[str, Any]:
    """Return the first result of a real SARIF file that RigorFoundry exported."""
    loaded: dict[str, Any] = json.loads(REAL_SARIF.read_text(encoding="utf-8"))["runs"][0][
        "results"
    ][0]
    return loaded


def test_an_absent_field_takes_its_default_and_a_present_one_must_have_its_type() -> None:
    """Absent gives the default, a typed value is returned, and a mistyped or null value skips."""
    result = _result()
    assert present_field(result, "baselineState", str, "malformed", "absent") == "absent"
    assert present_field(result, "kind", str, "malformed", None) == result["kind"]
    for value in (None, 3, ["fail"]):
        with pytest.raises(ResultSkipped) as skipped:
            present_field({**result, "kind": value}, "kind", str, "malformed-kind", "fail")
        assert skipped.value.reason == "malformed-kind" and str(skipped.value) == "malformed-kind"


def test_text_is_cut_on_a_character_boundary_within_its_byte_bound() -> None:
    """A message of two-byte characters is cut below the bound, never inside a character."""
    text = _result()["message"]["text"]
    assert bounded_text(text, len(text.encode())) == (text, False)
    kept, cut = bounded_text("é" * 10, 7)
    assert (kept, cut) == ("é" * 3, True)


def test_a_value_is_kept_up_to_its_bound_and_by_digest_past_it() -> None:
    """Properties fit at exactly their canonical size, and one byte less keeps only the digest."""
    properties = _result()["properties"]
    size = len(json_bytes(properties))
    digest = hashlib.sha256(json_bytes(properties)).hexdigest()
    assert bounded_value(properties, size) == (properties, digest, False)
    assert bounded_value(properties, size - 1) == (None, digest, True)
    assert json_bytes({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()
