# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — strict SARIF import parsing and whole-file limit tests
"""Verify that a SARIF file within every limit parses and one past any limit is refused whole."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.sarif_import_document import (
    MAX_NESTING,
    MAX_RESULTS_PER_RUN,
    MAX_RULES_PER_RUN,
    MAX_RUNS,
    MAX_SARIF_BYTES,
    SarifImportRefused,
    parse_sarif_document,
)

ROOT = Path(__file__).resolve().parents[1]
REAL_SARIF = ROOT / "tests/fixtures/sarif/canonical-states.sarif"


def _real() -> dict[str, Any]:
    """Return a fresh copy of a real SARIF 2.1.0 file that RigorFoundry exported."""
    loaded: dict[str, Any] = json.loads(REAL_SARIF.read_text(encoding="utf-8"))
    return loaded


def _bytes(document: object) -> bytes:
    """Return compact JSON bytes of one document."""
    return json.dumps(document, separators=(",", ":")).encode()


def _refusal(payload: bytes) -> str:
    """Return the reason code with which a payload is refused."""
    with pytest.raises(SarifImportRefused) as refused:
        parse_sarif_document(payload)
    return refused.value.reason


def test_a_real_sarif_file_parses_with_its_runs() -> None:
    """The real exported file is within every limit and keeps its single run."""
    parsed = parse_sarif_document(REAL_SARIF.read_bytes())
    assert parsed.document == _real()
    assert parsed.runs == tuple(_real()["runs"])


def test_the_byte_limit_admits_its_boundary_and_refuses_one_more() -> None:
    """Whitespace padding to exactly the limit parses, and one byte more is refused."""
    payload = _bytes(_real())
    exact = payload + b" " * (MAX_SARIF_BYTES - len(payload))
    assert len(parse_sarif_document(exact).runs) == 1
    assert _refusal(exact + b" ") == "too-large"


def _nested(depth: int) -> dict[str, Any]:
    """Return the real document whose first result's properties nest to ``depth`` in total."""
    document = _real()
    inner: dict[str, Any] = {}
    # The document, runs, run, results, result and properties already account for 6 levels.
    for _ in range(depth - 6):
        inner = {"next": inner}
    document["runs"][0]["results"][0]["properties"] = inner
    return document


def test_the_nesting_limit_admits_its_boundary_and_refuses_one_more() -> None:
    """A document nested to the limit parses, and one level more is refused."""
    assert parse_sarif_document(_bytes(_nested(MAX_NESTING))).runs
    assert _refusal(_bytes(_nested(MAX_NESTING + 1))) == "too-deep"


def _with(field: str, count: int) -> dict[str, Any]:
    """Return the real document with ``count`` runs, results or rules."""
    document = _real()
    run = document["runs"][0]
    if field == "runs":
        document["runs"] = [copy.deepcopy(run) for _ in range(count)]
    elif field == "results":
        run["results"] = [{} for _ in range(count)]
    elif field == "rules":
        run["tool"]["driver"]["rules"] = [{"id": f"r{index}"} for index in range(count)]
    else:
        # The driver holds one rule and two extensions hold the rest, as CodeQL lays them out.
        run["tool"]["driver"]["rules"] = [{"id": "d"}]
        half = (count - 1) // 2
        run["tool"]["extensions"] = [
            {"name": "queries", "rules": [{"id": f"q{index}"} for index in range(half)]},
            {"name": "more", "rules": [{"id": f"m{index}"} for index in range(count - 1 - half)]},
        ]
    return document


@pytest.mark.parametrize(
    ("field", "limit", "reason"),
    [
        ("runs", MAX_RUNS, "too-many-runs"),
        ("results", MAX_RESULTS_PER_RUN, "too-many-results"),
        ("rules", MAX_RULES_PER_RUN, "too-many-rules"),
        ("extension rules", MAX_RULES_PER_RUN, "too-many-rules"),
    ],
)
def test_each_count_limit_admits_its_boundary_and_refuses_one_more(
    field: str, limit: int, reason: str
) -> None:
    """Runs, results per run and rules per run each pass at the limit and refuse past it.

    Parameters
    ----------
    field : str
        The counted field.
    limit : int
        Its whole-file limit.
    reason : str
        The refusal reason one item past the limit.
    """
    assert parse_sarif_document(_bytes(_with(field, limit))).runs
    assert _refusal(_bytes(_with(field, limit + 1))) == reason


def _version_2_0(document: dict[str, Any]) -> None:
    """Declare SARIF 2.0."""
    document["version"] = "2.0.0"


def _version_release_candidate(document: dict[str, Any]) -> None:
    """Declare a pre-release spelling that only starts like 2.1.0."""
    document["version"] = "2.1.0-rtm.5"


def _version_short(document: dict[str, Any]) -> None:
    """Declare the two-part spelling 2.1."""
    document["version"] = "2.1"


def _runs_object(document: dict[str, Any]) -> None:
    """Replace the run list with an object."""
    document["runs"] = {}


def _run_without_driver(document: dict[str, Any]) -> None:
    """Remove the first run's tool driver."""
    del document["runs"][0]["tool"]["driver"]


def _results_object(document: dict[str, Any]) -> None:
    """Replace the first run's results with an object."""
    document["runs"][0]["results"] = {}


def _extensions_object(document: dict[str, Any]) -> None:
    """Replace the first run's tool extensions with an object."""
    document["runs"][0]["tool"]["extensions"] = {"rules": []}


def _extension_not_object(document: dict[str, Any]) -> None:
    """List a tool extension that is not an object."""
    document["runs"][0]["tool"]["extensions"] = ["codeql/python-queries"]


def _extension_rules_object(document: dict[str, Any]) -> None:
    """Give a tool extension rules that are not an array."""
    document["runs"][0]["tool"]["extensions"] = [{"name": "queries", "rules": {"id": "q"}}]


def _driver_without_name(document: dict[str, Any]) -> None:
    """Remove the tool driver's name."""
    del document["runs"][0]["tool"]["driver"]["name"]


def _extension_numeric_version(document: dict[str, Any]) -> None:
    """Give a tool extension a numeric semantic version."""
    document["runs"][0]["tool"]["extensions"] = [{"name": "queries", "semanticVersion": 1}]


def _driver_null_version(document: dict[str, Any]) -> None:
    """Give the tool driver an explicit null version."""
    document["runs"][0]["tool"]["driver"]["version"] = None


def _repeated_rule_id(document: dict[str, Any]) -> None:
    """Repeat one rule id within a single tool extension."""
    document["runs"][0]["tool"]["extensions"] = [
        {"name": "queries", "rules": [{"id": "py/x"}, {"name": "gap"}, {"id": "py/x"}]}
    ]


@pytest.mark.parametrize(
    ("alter", "reason"),
    [
        (_version_2_0, "not-sarif-2.1.0"),
        (_version_release_candidate, "not-sarif-2.1.0"),
        (_version_short, "not-sarif-2.1.0"),
        (_runs_object, "malformed-run"),
        (_run_without_driver, "malformed-run"),
        (_results_object, "malformed-run"),
        (_extensions_object, "malformed-run"),
        (_extension_not_object, "malformed-run"),
        (_extension_rules_object, "malformed-run"),
        (_driver_without_name, "malformed-run"),
        (_extension_numeric_version, "malformed-run"),
        (_driver_null_version, "malformed-run"),
        (_repeated_rule_id, "malformed-run"),
    ],
)
def test_a_document_that_is_not_sarif_2_1_0_is_refused(
    alter: Callable[[dict[str, Any]], None], reason: str
) -> None:
    """A wrong version or a malformed run is refused as a whole.

    Parameters
    ----------
    alter : Callable[[dict[str, Any]], None]
        Changes one structural fact of the real document.
    reason : str
        The expected refusal reason.
    """
    document = _real()
    alter(document)
    assert _refusal(_bytes(document)) == reason


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b'{"version": "2.1.0", "version": "2.1.0", "runs": []}', "duplicate-key"),
        (b'{"version": "2.1.0", "runs": [], "x": NaN}', "non-finite-number"),
        (b'{"version": "2.1.0", "runs": [], "x": Infinity}', "non-finite-number"),
        (b"\xff\xfe", "not-json"),
        (b'{"version": "2.1.0", "runs": [', "not-json"),
        (b"[]", "not-sarif-2.1.0"),
    ],
)
def test_a_file_that_is_not_strict_json_is_refused(payload: bytes, reason: str) -> None:
    """Duplicate keys, non-finite numbers, invalid UTF-8 and broken JSON are each refused.

    Parameters
    ----------
    payload : bytes
        The file bytes.
    reason : str
        The expected refusal reason.
    """
    assert _refusal(payload) == reason
    assert str(SarifImportRefused(reason, "x")) == f"{reason}: x"


def test_one_rule_id_may_appear_once_in_each_of_several_components() -> None:
    """The same rule id in the driver and in two extensions is accepted; only a repeat within one is not."""
    document = _real()
    tool = document["runs"][0]["tool"]
    first_id = tool["driver"]["rules"][0]["id"]
    tool["extensions"] = [
        {
            "name": "a",
            "version": "1",
            "rules": [{"id": first_id}, {"name": "gap"}, {"name": "gap"}],
        },
        {"name": "b", "rules": [{"id": first_id}]},
    ]
    assert parse_sarif_document(_bytes(document)).runs[0]["tool"]["extensions"][1]["name"] == "b"
