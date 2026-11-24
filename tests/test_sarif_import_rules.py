# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — imported SARIF rules per tool component, on real CodeQL output
"""Verify imported rules per tool component on real CodeQL Actions output and RigorFoundry's own."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.rules import RULES_BY_ID
from rigor_foundry.sarif_import_bounds import ResultSkipped
from rigor_foundry.sarif_import_document import parse_sarif_document
from rigor_foundry.sarif_import_records import ImportedCandidate, LocationMetadata, PreservedResult
from rigor_foundry.sarif_import_rules import (
    MAX_SHORT_DESCRIPTION_BYTES,
    MAX_TAG_BYTES,
    MAX_TAGS,
    ImportedRule,
    RunRules,
    ToolComponent,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sarif_import"
CODEQL_ONE_RESULT = FIXTURES / "codeql-2.26.0-actions-analysis-1496041210.sarif.gz"
CODEQL_NO_RESULT = FIXTURES / "codeql-2.27.2-actions-analysis-2237134604.sarif.gz"
CODEQL_DIGESTS = {
    CODEQL_ONE_RESULT: "212064146c3c44aec0737f5ddfbc7864c1f8819e9b1500c5f0596f2704928617",
    CODEQL_NO_RESULT: "7387a1b0bbcf793fef0f8a732b9a534163693324b142b10d9334b142791fcf67",
}
OWN_SARIF = ROOT / "tests/fixtures/sarif/canonical-states.sarif"
OWN = ToolComponent("own", None)
ANCHOR = TrackedBlobAnchor(
    path="src/pkg/runner.py", line_start=2, line_end=2, blob_oid="a" * 40, content_sha256="b" * 64
)
NO_DETAIL = LocationMetadata(None, None, None, None, False, None, None, False, 1)


def _codeql_run(path: Path) -> dict[str, Any]:
    """Return the only run of one real CodeQL Actions SARIF file, strictly parsed."""
    payload = gzip.decompress(path.read_bytes())
    assert hashlib.sha256(payload).hexdigest() == CODEQL_DIGESTS[path]
    (run,) = parse_sarif_document(payload).runs
    return run


def test_real_codeql_output_keeps_every_rule_in_its_query_pack() -> None:
    """Both real CodeQL files hold no driver rules and 43 rules in their query-pack extension."""
    for path, version in ((CODEQL_ONE_RESULT, "2.26.0"), (CODEQL_NO_RESULT, "2.27.2")):
        rules = RunRules.build("codeql", _codeql_run(path))
        assert rules.driver.component == ToolComponent("CodeQL", version)
        assert rules.driver.rules == ()
        pack = rules.extensions[0]
        assert pack.component.name == "codeql/python-queries"
        assert pack.component.version is not None and pack.component.version.count("+") == 1
        assert len(pack.rules) == 43 and all(rule is not None for rule in pack.rules)
        assert all(rule.tool_component == pack.component for rule in pack.rules if rule)
        assert not {rule.rule_id for rule in pack.rules if rule} & set(RULES_BY_ID)
        assert [len(extension.rules) for extension in rules.extensions[1:]] == [0, 0]


def test_the_real_codeql_result_resolves_through_its_tool_component() -> None:
    """The real result's ``rule.toolComponent.index`` names its query pack, not the driver."""
    run = _codeql_run(CODEQL_ONE_RESULT)
    rules = RunRules.build("codeql", run)
    (result,) = run["results"]
    preserved = PreservedResult.build("codeql", result, rules, run_index=0, result_index=0)
    assert preserved.rule_id == "ext:codeql:py/incomplete-url-substring-sanitization"
    assert (preserved.tool_component_index, preserved.rule_index) == (0, 13)
    assert preserved.tool_component == rules.extensions[0].component
    assert rules.resolve(0, 13).rule_id == preserved.rule_id
    assert (preserved.kind, preserved.level) == ("fail", "warning")
    assert preserved.to_dict()["tool_component"] == rules.extensions[0].component.to_dict()
    assert preserved.partial_fingerprints == result["partialFingerprints"]


@pytest.mark.parametrize(
    ("component", "reason"),
    [
        ({"index": 5}, "tool-component-out-of-range"),
        ({"index": -2}, "tool-component-out-of-range"),
        ({"name": "codeql/python-queries"}, "unresolvable-tool-component"),
        ({"index": -1, "guid": "x"}, "unresolvable-tool-component"),
        ({"index": True}, "malformed-rule-reference"),
        ({"index": "0"}, "malformed-rule-reference"),
        ("codeql/python-queries", "malformed-rule-reference"),
        ({"index": 1}, "rule-index-out-of-range"),
    ],
)
def test_a_tool_component_reference_that_names_no_pack_is_skipped(
    component: object, reason: str
) -> None:
    """An out-of-range, name-only, mistyped or empty-pack component reference is skipped.

    Parameters
    ----------
    component : object
        The result's ``rule.toolComponent``.
    reason : str
        The skip reason.
    """
    run = _codeql_run(CODEQL_ONE_RESULT)
    result = copy.deepcopy(run["results"][0])
    result["rule"]["toolComponent"] = component
    with pytest.raises(ResultSkipped) as skipped:
        PreservedResult.build(
            "codeql", result, RunRules.build("codeql", run), run_index=0, result_index=0
        )
    assert skipped.value.reason == reason


def test_a_driver_index_into_a_query_pack_only_producer_is_out_of_range() -> None:
    """Without its tool component, the real reference would wrongly point into the empty driver."""
    run = _codeql_run(CODEQL_ONE_RESULT)
    result = copy.deepcopy(run["results"][0])
    del result["rule"]["toolComponent"]
    with pytest.raises(ResultSkipped) as skipped:
        PreservedResult.build(
            "codeql", result, RunRules.build("codeql", run), run_index=0, result_index=0
        )
    assert skipped.value.reason == "rule-index-out-of-range"


def _two_packs(first: tuple[str, str], second: tuple[str, str]) -> dict[str, Any]:
    """Return a run whose two query packs each define the same rule id ``py/x``."""
    return {
        "tool": {
            "driver": {"name": "CodeQL", "semanticVersion": "2.27.2"},
            "extensions": [
                {"name": name, "semanticVersion": version, "rules": [{"id": "py/x"}]}
                for name, version in (first, second)
            ],
        },
        "results": [],
    }


def _candidate(run: dict[str, Any], position: int) -> ImportedCandidate:
    """Return the candidate of one ``py/x`` result that names the pack at ``position``."""
    result = {
        "ruleId": "py/x",
        "rule": {"id": "py/x", "index": 0, "toolComponent": {"index": position}},
        "message": {"text": "same finding"},
        "partialFingerprints": {"primaryLocationLineHash": "1:1"},
    }
    rules = RunRules.build("codeql", run)
    preserved = PreservedResult.build("codeql", result, rules, run_index=0, result_index=0)
    return ImportedCandidate.build("codeql", ANCHOR, preserved, NO_DETAIL)


def test_the_same_rule_id_in_two_packs_gives_distinct_ids_bound_to_name_and_version() -> None:
    """Same rule, anchor and message in two packs differ; the bare position never enters the id."""
    run = _two_packs(("pack/a", "1.0.0"), ("pack/b", "2.0.0"))
    assert parse_sarif_document(json.dumps({"version": "2.1.0", "runs": [run]}).encode()).runs
    first, second = _candidate(run, 0), _candidate(run, 1)
    assert first.result.rule_id == second.result.rule_id == "ext:codeql:py/x"
    assert first.candidate_id != second.candidate_id
    swapped = _two_packs(("pack/b", "2.0.0"), ("pack/a", "1.0.0"))
    assert _candidate(swapped, 1).candidate_id == first.candidate_id
    assert _candidate(swapped, 0).candidate_id == second.candidate_id
    newer = _two_packs(("pack/a", "1.0.1"), ("pack/b", "2.0.0"))
    assert _candidate(newer, 0).candidate_id != first.candidate_id


def test_a_component_version_prefers_semantic_version() -> None:
    """``semanticVersion`` wins over ``version``, which is used alone, and both may be absent."""
    assert ToolComponent.from_object(
        {"name": "t", "semanticVersion": "1.2.3", "version": "x"}
    ) == (ToolComponent("t", "1.2.3"))
    assert ToolComponent.from_object({"name": "t", "version": "x"}) == ToolComponent("t", "x")
    assert ToolComponent.from_object({"name": "t"}).to_dict() == {"name": "t", "version": None}


def test_entries_without_a_rule_id_are_gaps_that_skip_only_their_results() -> None:
    """A rule without an id or not an object keeps its position and skips results naming it."""
    run = {
        "tool": {"driver": {"name": "t", "rules": [{"name": "no id"}, "junk", {"id": "r"}]}},
        "results": [],
    }
    rules = RunRules.build("semgrep", run)
    assert rules.driver.rules[:2] == (None, None)
    assert rules.resolve(None, 2).rule_id == "ext:semgrep:r"
    for index in (0, 1):
        with pytest.raises(ResultSkipped) as skipped:
            rules.resolve(None, index)
        assert skipped.value.reason == "rule-without-id"


def test_a_real_own_rule_keeps_bounded_metadata_and_the_whole_rule_digest() -> None:
    """A rule of RigorFoundry's own export records its namespaced id, link, tags and digest."""
    (run,) = json.loads(OWN_SARIF.read_text(encoding="utf-8"))["runs"]
    rule = run["tool"]["driver"]["rules"][0]
    recorded = ImportedRule.build("semgrep", rule, 0, tool_component=OWN)
    assert recorded.rule_id == f"ext:semgrep:{rule['id']}"
    assert recorded.rule_id not in RULES_BY_ID
    assert recorded.help_uri == rule["helpUri"] and not recorded.help_uri_dropped
    assert recorded.short_description == rule["shortDescription"]["text"]
    assert recorded.tags == tuple(rule["properties"]["tags"]) and not recorded.tags_truncated
    assert len(recorded.rule_object_sha256) == 64
    record = recorded.to_dict()
    assert record["rule_index"] == 0 and record["tool_component_index"] is None
    assert record["tool_component"] == {"name": "own", "version": None}


def test_rule_metadata_past_its_bounds_is_cut_dropped_or_refused() -> None:
    """A long description is cut, a non-https link dropped, excess tags cut, no id refused."""
    rule: dict[str, Any] = {
        "id": "x",
        "shortDescription": {"text": "é" * MAX_SHORT_DESCRIPTION_BYTES},
        "helpUri": "http://example.invalid/rule",
        "properties": {"tags": [*["t"] * (MAX_TAGS + 1), "w" * (MAX_TAG_BYTES + 1)]},
        "defaultConfiguration": {"level": "warning"},
    }
    recorded = ImportedRule.build("codeql", rule, 3, tool_component=OWN, tool_component_index=2)
    assert recorded.short_description is not None
    assert len(recorded.short_description.encode()) <= MAX_SHORT_DESCRIPTION_BYTES
    assert recorded.short_description_truncated
    assert (recorded.help_uri, recorded.help_uri_dropped) == (None, True)
    assert recorded.tags == ("t",) * MAX_TAGS and recorded.tags_truncated
    assert recorded.default_level == "warning" and recorded.tool_component_index == 2
    bare = ImportedRule.build(
        "codeql", {"id": "y", "properties": {"tags": "solo"}}, 0, tool_component=OWN
    )
    assert (bare.tags, bare.tags_truncated, bare.help_uri_dropped) == ((), True, False)
    with pytest.raises(ResultSkipped) as skipped:
        ImportedRule.build("codeql", {"name": "unnamed"}, 0, tool_component=OWN)
    assert skipped.value.reason == "rule-without-id"
