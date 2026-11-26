# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — strict JSON lockfile reading witnesses
"""Witness strict JSON lockfile reading: refusals by name, and the line of every object key."""

from __future__ import annotations

import sys

import pytest

from rigor_foundry.lockfile_json import json_key_lines, load_lockfile_json
from rigor_foundry.lockfile_model import LockfileRefusal

DOCUMENT = """{
  "name": "fixture",
  "packages": {
    "": {"dependencies": {"local-lib": "file:./local-lib"}},
    "local-lib": {
      "version": "1.0.0"
    },
    "node_modules/a\\"b": {"resolved": "x:", "list": [{"inner": 1}, "k:"]}
  }
}
"""


def test_a_strict_document_loads_and_every_key_has_its_line() -> None:
    """Each object key is indexed by its full key path, so equal names in other objects differ."""
    assert load_lockfile_json(DOCUMENT)["name"] == "fixture"
    lines = json_key_lines(DOCUMENT)
    assert lines[("name",)] == 2
    assert lines[("packages",)] == 3
    assert lines[("packages", "")] == 4
    assert lines[("packages", "", "dependencies", "local-lib")] == 4
    assert lines[("packages", "local-lib")] == 5
    assert lines[("packages", "local-lib", "version")] == 6
    assert lines[("packages", 'node_modules/a"b')] == 8
    assert lines[("packages", 'node_modules/a"b', "resolved")] == 8
    assert ("packages", 'node_modules/a"b', "list", "inner") not in lines
    assert ("k:",) not in lines


@pytest.mark.parametrize(
    "text",
    [
        "",
        "{",
        "[]",
        '"text"',
        "{} {}",
        '{"a": NaN}',
        '{"a": Infinity}',
        '{"a": 1.5e400}',
    ],
)
def test_text_that_is_not_one_strict_json_object_is_unparseable(text: str) -> None:
    """Anything but one JSON object without non-finite numbers is refused as ``unparseable``.

    Parameters
    ----------
    text : str
        The refused text.
    """
    with pytest.raises(LockfileRefusal) as refused:
        load_lockfile_json(text)
    assert refused.value.reason == "unparseable"


@pytest.mark.parametrize(
    "text",
    ['{"a": 1, "a": 2}', '{"p": {"node_modules/x": {}, "node_modules/x": {}}}'],
)
def test_a_duplicate_key_is_a_conflicting_entry(text: str) -> None:
    """A key repeated in one object is refused, never resolved by keeping the last one.

    Parameters
    ----------
    text : str
        A document with one duplicated key.
    """
    with pytest.raises(LockfileRefusal) as refused:
        load_lockfile_json(text)
    assert refused.value.reason == "conflicting-entries"


def test_nesting_past_the_recursion_limit_is_unparseable_without_a_traceback() -> None:
    """A structurally hostile file is refused, so it cannot crash the scan.

    CPython's JSON decoder guards its own C recursion, whose limit is above
    ``sys.getrecursionlimit()`` on 3.12 and later, so the witness nests far past both.
    """
    depth = max(200_000, sys.getrecursionlimit() * 100)
    text = '{"a":' * depth + "1" + "}" * depth
    with pytest.raises(LockfileRefusal) as refused:
        load_lockfile_json(text)
    assert refused.value.reason == "unparseable"
    assert refused.value.__cause__ is None
    assert refused.value.__suppress_context__


def test_a_finite_fractional_number_is_kept() -> None:
    """Only non-finite numbers are refused; a finite fraction is read as written."""
    assert load_lockfile_json('{"a": 1.5, "b": -2e3}') == {"a": 1.5, "b": -2000.0}
