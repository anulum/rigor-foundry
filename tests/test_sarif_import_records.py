# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded imported SARIF rule and result record tests
"""Verify that imported rules and results keep the producer's words, bounded, never judged."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from rigor_foundry.rules import RULES_BY_ID, rule_pack_digest
from rigor_foundry.sarif_import_records import (
    MAX_MESSAGE_BYTES,
    MAX_PROPERTIES_BYTES,
    MAX_SHORT_DESCRIPTION_BYTES,
    MAX_TAG_BYTES,
    MAX_TAGS,
    ImportedCandidate,
    ImportedRule,
    LocationMetadata,
    PreservedResult,
    ResultSkipped,
    anchor_from_record,
    imported_rule_id,
    require_producer_id,
)

ROOT = Path(__file__).resolve().parents[1]
REAL_SARIF = ROOT / "tests/fixtures/sarif/canonical-states.sarif"
ANCHOR = TrackedBlobAnchor(
    path="src/pkg/runner.py",
    line_start=2,
    line_end=2,
    blob_oid="a" * 40,
    content_sha256="b" * 64,
)
NO_DETAIL = LocationMetadata(None, None, None, None, False, None, None, False, 1)


def _run() -> dict[str, Any]:
    """Return the only run of a real SARIF file that RigorFoundry exported."""
    (run,) = json.loads(REAL_SARIF.read_text(encoding="utf-8"))["runs"]
    result: dict[str, Any] = run
    return result


def _rules() -> tuple[ImportedRule, ...]:
    """Return the real run's driver rules recorded under one producer namespace."""
    return tuple(
        ImportedRule.build("semgrep", rule, index)
        for index, rule in enumerate(_run()["tool"]["driver"]["rules"])
    )


def _preserved(result: dict[str, Any]) -> PreservedResult:
    """Record one result against the real run's rules."""
    return PreservedResult.build("semgrep", result, _rules(), run_index=0, result_index=0)


def test_a_real_rule_keeps_bounded_metadata_and_the_whole_rule_digest() -> None:
    """Every real rule records its namespaced id, help link, level, tags and object digest."""
    rule = _run()["tool"]["driver"]["rules"][0]
    recorded = ImportedRule.build("semgrep", rule, 0)
    assert recorded.rule_id == f"ext:semgrep:{rule['id']}"
    assert recorded.rule_id not in RULES_BY_ID
    assert recorded.help_uri == rule["helpUri"] and not recorded.help_uri_dropped
    assert recorded.short_description == rule["shortDescription"]["text"]
    assert recorded.tags == tuple(rule["properties"]["tags"]) and not recorded.tags_truncated
    assert len(recorded.rule_object_sha256) == 64
    assert recorded.to_dict()["rule_index"] == 0


def test_rule_metadata_past_its_bounds_is_cut_dropped_or_refused() -> None:
    """A long description is cut, a non-https link dropped, excess tags cut, no id refused."""
    rule: dict[str, Any] = {
        "id": "x",
        "shortDescription": {"text": "é" * MAX_SHORT_DESCRIPTION_BYTES},
        "helpUri": "http://example.invalid/rule",
        "properties": {"tags": [*["t"] * (MAX_TAGS + 1), "w" * (MAX_TAG_BYTES + 1)]},
        "defaultConfiguration": {"level": "warning"},
    }
    recorded = ImportedRule.build("codeql", rule, 3)
    assert recorded.short_description is not None
    assert len(recorded.short_description.encode()) <= MAX_SHORT_DESCRIPTION_BYTES
    assert recorded.short_description_truncated
    assert (recorded.help_uri, recorded.help_uri_dropped) == (None, True)
    assert recorded.tags == ("t",) * MAX_TAGS and recorded.tags_truncated
    assert recorded.default_level == "warning"
    bare = ImportedRule.build("codeql", {"id": "y", "properties": {"tags": "solo"}}, 0)
    assert (bare.tags, bare.tags_truncated, bare.help_uri_dropped) == ((), True, False)
    with pytest.raises(ResultSkipped) as skipped:
        ImportedRule.build("codeql", {"name": "unnamed"}, 0)
    assert skipped.value.reason == "rule-without-id"


def test_a_result_keeps_the_producers_words_verbatim_and_never_maps_them() -> None:
    """Level, kind, baseline state, suppressions and properties are kept as the producer wrote."""
    result = dict(_run()["results"][0])
    result.update(
        level="error",
        baselineState="new",
        suppressions=[{"status": "accepted", "kind": "inSource"}, {"kind": "external"}],
        partialFingerprints={"primaryLocationLineHash": "abc:1"},
    )
    preserved = _preserved(result)
    assert (preserved.level, preserved.kind, preserved.baseline_state) == ("error", "fail", "new")
    assert preserved.suppressions == (("accepted", "inSource"), (None, "external"))
    assert preserved.partial_fingerprints == {"primaryLocationLineHash": "abc:1"}
    assert preserved.rule_id == f"ext:semgrep:{result['ruleId']}"
    assert preserved.is_candidate_kind
    record = preserved.to_dict()
    assert not {"severity", "confidence", "category", "priority"} & set(record)
    assert record["result_object_sha256"] == preserved.result_object_sha256


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
def test_a_non_finding_kind_is_an_observation_not_a_candidate(kind: str) -> None:
    """Only fail, open and review results can become candidates.

    Parameters
    ----------
    kind : str
        A SARIF result kind that is not a finding.
    """
    preserved = _preserved({**_run()["results"][0], "kind": kind})
    assert not preserved.is_candidate_kind
    with pytest.raises(ValueError, match="is an observation, not a candidate"):
        ImportedCandidate.build("semgrep", ANCHOR, preserved, NO_DETAIL)


def test_a_long_message_and_large_properties_keep_their_digests() -> None:
    """The message is cut with the full text's digest, and oversized properties keep a digest."""
    text = "x" * (MAX_MESSAGE_BYTES + 5)
    bulky = {"blob": "y" * MAX_PROPERTIES_BYTES}
    preserved = _preserved(
        {**_run()["results"][0], "message": {"text": text}, "properties": bulky}
    )
    assert len(preserved.message_text) == MAX_MESSAGE_BYTES and preserved.message_truncated
    assert preserved.message_text_sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert preserved.properties is None and preserved.properties_truncated
    fitting = {"blob": "y" * (MAX_PROPERTIES_BYTES - 20)}
    kept = _preserved({**_run()["results"][0], "properties": fitting})
    assert kept.properties == fitting and not kept.properties_truncated


def test_a_result_names_its_rule_by_id_or_index_and_is_skipped_otherwise() -> None:
    """A rule index alone resolves; a missing, out-of-range or contradicting reference is skipped."""
    real = _run()["results"][0]
    assert _preserved(real).rule_index == real["ruleIndex"]
    base = {key: value for key, value in real.items() if key not in {"ruleId", "ruleIndex"}}
    for indexed in (
        {**base, "rule": {"index": 1}},
        {**base, "ruleIndex": 1},
        {**base, "ruleIndex": 1, "rule": {"index": 1}},
        {**base, "ruleIndex": -1, "rule": {"index": 1}},
        {**base, "ruleIndex": 1, "rule": {"index": -1}},
    ):
        by_index = _preserved(indexed)
        assert by_index.rule_id == _rules()[1].rule_id and by_index.rule_index == 1
    for result, reason in (
        (base, "result-without-rule"),
        ({**base, "ruleIndex": -1}, "result-without-rule"),
        ({**base, "rule": {"index": len(_rules())}}, "rule-index-out-of-range"),
        ({**base, "ruleId": "other", "rule": {"index": 0}}, "rule-id-index-mismatch"),
    ):
        with pytest.raises(ResultSkipped) as skipped:
            _preserved(result)
        assert skipped.value.reason == reason
    by_reference = _preserved({**base, "rule": {"id": _run()["results"][0]["ruleId"]}})
    assert by_reference.rule_id == _preserved(_run()["results"][0]).rule_id


def test_a_candidate_id_binds_partial_fingerprints_but_not_producer_fingerprints() -> None:
    """The id follows rule, anchor, message and partial fingerprints, and ignores ``fingerprints``."""
    result = _run()["results"][0]
    first = ImportedCandidate.build("semgrep", ANCHOR, _preserved(result), NO_DETAIL)
    same = ImportedCandidate.build(
        "semgrep",
        ANCHOR,
        _preserved({**result, "fingerprints": {"other/v9": "zzz"}}),
        NO_DETAIL,
    )
    moved = ImportedCandidate.build(
        "semgrep",
        ANCHOR,
        _preserved({**result, "partialFingerprints": {"hash": "1"}}),
        NO_DETAIL,
    )
    assert first.candidate_id == same.candidate_id != moved.candidate_id
    assert first.to_dict()["state"] == "unreviewed"
    assert anchor_from_record(first.to_dict()["anchor"]) == ANCHOR


def test_only_tracked_blob_anchors_and_valid_producers_are_accepted() -> None:
    """A repository-tree anchor, a bad producer slug and an empty rule id are each refused."""
    tree = RepositoryTreeAnchor(
        path=".", line_start=1, line_end=1, tree_oid="c" * 40, tracked_content_sha256="d" * 64
    )
    with pytest.raises(ValueError, match="only to a tracked blob"):
        anchor_from_record(tree.to_dict())
    for slug in ("CodeQL", "", "a" * 33, 7):
        with pytest.raises(ValueError, match="lower-case slug"):
            require_producer_id(slug)
    with pytest.raises(ValueError, match="needs the producer's rule id"):
        imported_rule_id("codeql", "")


def test_building_import_records_never_changes_the_rule_registry() -> None:
    """Importing rules and results leaves RULES and the rule-pack digest exactly as they were."""
    digest, registered = rule_pack_digest(), dict(RULES_BY_ID)
    rules = _rules()
    built = [
        ImportedCandidate.build("semgrep", ANCHOR, preserved, NO_DETAIL)
        for preserved in map(_preserved, _run()["results"])
        if preserved.is_candidate_kind
    ]
    assert built
    assert rule_pack_digest() == digest and dict(RULES_BY_ID) == registered
    assert not {rule.rule_id for rule in rules} & set(RULES_BY_ID)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"kind": 3}, "malformed-kind"),
        ({"kind": None}, "malformed-kind"),
        ({"kind": "bogus"}, "unknown-kind"),
        ({"level": 3}, "malformed-level"),
        ({"level": None}, "malformed-level"),
        ({"baselineState": None}, "malformed-baseline-state"),
        ({"suppressions": {"kind": "inSource"}}, "malformed-suppressions"),
        ({"suppressions": ["junk"]}, "malformed-suppressions"),
        ({"suppressions": [{"kind": None}]}, "malformed-suppressions"),
        ({"suppressions": [{"kind": "inSource", "status": 1}]}, "malformed-suppressions"),
        ({"partialFingerprints": ["a"]}, "malformed-fingerprints"),
        ({"fingerprints": None}, "malformed-fingerprints"),
        ({"properties": "tags"}, "malformed-properties"),
        ({"message": {"id": "default"}}, "missing-message"),
        ({"message": "text"}, "missing-message"),
        ({"rule": "x"}, "malformed-rule-reference"),
        ({"ruleIndex": "0"}, "malformed-rule-reference"),
        ({"ruleIndex": True}, "malformed-rule-reference"),
        ({"rule": {"index": False}}, "malformed-rule-reference"),
        ({"ruleIndex": 0, "rule": {"index": 1}}, "rule-index-mismatch"),
        ({"ruleId": 5}, "malformed-rule-id"),
        ({"ruleId": ""}, "malformed-rule-id"),
        ({"rule": {"id": ""}}, "malformed-rule-id"),
        ({"rule": {"id": "other"}}, "rule-id-mismatch"),
    ],
)
def test_a_malformed_or_unknown_kind_level_or_message_is_skipped(
    change: dict[str, object], reason: str
) -> None:
    """A present field of the wrong type, ``null`` included, or contradicting forms are skipped.

    Parameters
    ----------
    change : dict[str, object]
        Fields replacing those of a real result.
    reason : str
        The skip reason.
    """
    with pytest.raises(ResultSkipped) as skipped:
        _preserved({**_run()["results"][0], **change})
    assert skipped.value.reason == reason


def test_only_an_absent_kind_takes_the_sarif_default() -> None:
    """A result without a kind is SARIF's default ``fail``, and so a candidate kind."""
    result = {key: value for key, value in _run()["results"][0].items() if key != "kind"}
    preserved = _preserved(result)
    assert (preserved.kind, preserved.is_candidate_kind, preserved.level) == (
        "fail",
        True,
        result.get("level"),
    )
