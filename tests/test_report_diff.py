# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — content-addressed report-diff tests
"""Verify deterministic, fail-closed comparison of exact audit reports."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from repository_audit_git_repository import sample_git_provenance

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.candidate_anchor import Candidate, RepositoryTreeAnchor
from rigor_foundry.cli import main
from rigor_foundry.models import AuditPolicy, AuditReport
from rigor_foundry.report_diff import (
    REPORT_DIFF_SCHEMA_VERSION,
    CandidateAnchorChange,
    CandidateAnchorMatch,
    ReportDiff,
    ReportDiffCompatibility,
    compare_reports,
    read_report_for_diff,
)


def _anchor(path: str, marker: str) -> RepositoryTreeAnchor:
    """Return one exact repository-state anchor."""
    return RepositoryTreeAnchor(
        path=path,
        line_start=1,
        line_end=1,
        tree_oid=marker * 40,
        tracked_content_sha256=marker * 64,
    )


def _candidate(
    name: str,
    marker: str,
    *,
    evidence: str | None = None,
) -> Candidate:
    """Return one registered candidate with selectable semantics and anchor."""
    return Candidate.build(
        category="architecture",
        rule_id="AR001-first-party-import-cycle",
        anchor=_anchor(f"src/{name}.py", marker),
        symbol=name,
        evidence=evidence or f"cycle {name}",
        confidence="high",
        rationale=f"review {name}",
        verification=f"import {name}",
    )


def _report(
    candidates: tuple[Candidate, ...],
    *,
    marker: str,
    root: str = "/tmp/repository",
    branch: str = "main",
    policy: AuditPolicy | None = None,
) -> AuditReport:
    """Build a deterministic exact report."""
    return AuditReport.build(
        repository_root=root,
        head=marker * 40,
        head_tree=marker * 40,
        git_object_format="sha1",
        branch=branch,
        tracked_content_digest=marker * 64,
        dirty_paths=(),
        tracked_file_count=4,
        git_provenance=sample_git_provenance(),
        policy=policy or AuditPolicy(),
        candidates=candidates,
    )


def _rehash(report: AuditReport, **changes: object) -> AuditReport:
    """Return a deliberately version-divergent but internally hashed report fixture."""
    changed = replace(report, **changes)
    body = changed.to_dict()
    body.pop("report_digest")
    return replace(changed, report_digest=canonical_digest(body))


def test_diff_classifies_all_transitions_and_replays_deterministically() -> None:
    """Exact identity and semantic anchor identity produce four disjoint classes."""
    retained = _candidate("retained", "1")
    old_anchor = _candidate("moved", "1")
    new_anchor = _candidate("moved", "2")
    resolved = _candidate("resolved", "1")
    appeared = _candidate("appeared", "2")
    before = _report((resolved, old_anchor, retained), marker="1")
    after = _report((appeared, retained, new_anchor), marker="2")

    first = compare_reports(before, after)
    second = ReportDiff.build(before, after)

    assert first == second
    assert first.retained_candidate_ids == (retained.candidate_id,)
    assert first.appeared_candidate_ids == (appeared.candidate_id,)
    assert first.resolved_candidate_ids == (resolved.candidate_id,)
    assert first.anchor_changes == (
        CandidateAnchorChange(
            before_candidate_id=old_anchor.candidate_id,
            after_candidate_id=new_anchor.candidate_id,
            semantic_digest=first.anchor_changes[0].semantic_digest,
            match_basis="automatic",
            rationale="",
        ),
    )
    assert (
        ReportDiff.from_dict(
            json.loads(first.to_json()),
            before_report=before,
            after_report=after,
        )
        == first
    )
    assert len(first.diff_digest) == 64


def test_semantic_change_is_not_mislabelled_as_an_anchor_change() -> None:
    """Evidence drift remains one resolved plus one appeared candidate."""
    old = _candidate("signal", "1")
    changed = _candidate("signal", "2", evidence="different evidence")
    before = _report((old,), marker="1")
    after = _report((changed,), marker="2")

    diff = compare_reports(before, after)

    assert diff.anchor_changes == ()
    assert diff.resolved_candidate_ids == (old.candidate_id,)
    assert diff.appeared_candidate_ids == (changed.candidate_id,)


def test_parent_reports_are_reverified_and_duplicate_identities_fail() -> None:
    """Diff construction does not trust direct-constructed parent envelopes."""
    candidate = _candidate("signal", "1")
    report = _report((candidate,), marker="1")
    with pytest.raises(ValueError, match="report digest"):
        compare_reports(replace(report, report_digest="0" * 64), report)

    mismatched_policy = _rehash(report, policy_digest="0" * 64)
    with pytest.raises(ValueError, match="policy digest"):
        compare_reports(mismatched_policy, report)

    duplicate = _report((candidate, candidate), marker="1")
    with pytest.raises(ValueError, match="duplicate candidate"):
        compare_reports(duplicate, report)

    wrong_format = _rehash(
        report,
        git_object_format="sha256",
        head="1" * 64,
        head_tree="1" * 64,
    )
    with pytest.raises(ValueError, match="anchor object id length"):
        compare_reports(wrong_format, report)

    wrong_ignored_digest = _rehash(report, ignored_inventory_digest="0" * 64)
    with pytest.raises(ValueError, match="ignored inventory digest"):
        compare_reports(wrong_ignored_digest, report)


def test_ambiguous_anchor_changes_require_complete_explicit_pairing() -> None:
    """Duplicate semantic identities cannot be paired by ordering or chance."""
    old_one = _candidate("duplicate", "1")
    old_two = _candidate("duplicate", "2")
    new_one = _candidate("duplicate", "3")
    new_two = _candidate("duplicate", "4")
    before = _report((old_one, old_two), marker="1")
    after = _report((new_one, new_two), marker="4")

    with pytest.raises(ValueError, match="ambiguous anchor change"):
        compare_reports(before, after)

    matches = (
        CandidateAnchorMatch(old_one.candidate_id, new_two.candidate_id, "manual evidence A"),
        CandidateAnchorMatch(old_two.candidate_id, new_one.candidate_id, "manual evidence B"),
    )
    diff = compare_reports(before, after, anchor_matches=matches)
    assert {item.match_basis for item in diff.anchor_changes} == {"declared"}
    assert {item.rationale for item in diff.anchor_changes} == {
        "manual evidence A",
        "manual evidence B",
    }
    assert ReportDiff.from_dict(diff.to_dict(), before_report=before, after_report=after) == diff


@pytest.mark.parametrize(
    ("matches", "message"),
    [
        (
            lambda old, new: (
                CandidateAnchorMatch(old[0].candidate_id, new[0].candidate_id, "one"),
                CandidateAnchorMatch(old[0].candidate_id, new[1].candidate_id, "two"),
            ),
            "exactly once",
        ),
        (
            lambda old, new: (CandidateAnchorMatch("f" * 64, new[0].candidate_id, "unknown"),),
            "unmatched report candidates",
        ),
    ],
)
def test_declared_anchor_matches_reject_reuse_and_unknown_candidates(
    matches: object,
    message: str,
) -> None:
    """Explicit matching cannot introduce foreign or multiply-used identities."""
    old = (_candidate("duplicate", "1"), _candidate("duplicate", "2"))
    new = (_candidate("duplicate", "3"), _candidate("duplicate", "4"))
    before = _report(old, marker="1")
    after = _report(new, marker="4")
    match_factory = matches
    assert callable(match_factory)
    with pytest.raises(ValueError, match=message):
        compare_reports(before, after, anchor_matches=match_factory(old, new))


def test_declared_anchor_match_rejects_semantic_and_anchor_nonchanges() -> None:
    """A declaration cannot collapse changed semantics or retained identity."""
    old = _candidate("old", "1")
    unrelated = _candidate("new", "2")
    before = _report((old,), marker="1")
    after = _report((unrelated,), marker="2")
    with pytest.raises(ValueError, match="changes candidate semantics"):
        compare_reports(
            before,
            after,
            anchor_matches=(
                CandidateAnchorMatch(old.candidate_id, unrelated.candidate_id, "not equivalent"),
            ),
        )

    duplicate = replace(old, candidate_id="e" * 64)
    duplicate = replace(
        duplicate,
        candidate_id=canonical_digest(
            {
                "category": duplicate.category,
                "rule_id": duplicate.rule_id,
                "anchor": duplicate.anchor.to_dict(),
                "symbol": duplicate.symbol,
                "evidence": duplicate.evidence,
                "confidence": duplicate.confidence,
                "rationale": duplicate.rationale,
                "verification": duplicate.verification,
            }
        ),
    )
    assert duplicate.candidate_id == old.candidate_id
    with pytest.raises(ValueError, match="unmatched report candidates"):
        compare_reports(
            before,
            _report((duplicate,), marker="2"),
            anchor_matches=(
                CandidateAnchorMatch(old.candidate_id, duplicate.candidate_id, "same"),
            ),
        )


@pytest.mark.parametrize(
    ("after_changes", "declaration_field"),
    [
        ({"repository_root": "/tmp/other"}, "repository_change"),
        ({"branch": "release"}, "branch_change"),
        ({"policy": AuditPolicy(source_line_threshold=900)}, "policy_change"),
        (
            {"rule_pack_version": "historical/1.0", "rule_pack_digest": "a" * 64},
            "rule_pack_change",
        ),
        ({"scanner_version": "0.2.0"}, "scanner_change"),
    ],
)
def test_incompatible_inputs_require_exact_non_superfluous_declarations(
    after_changes: dict[str, object],
    declaration_field: str,
) -> None:
    """Every compatibility exception is both necessary and explicitly justified."""
    before = _report((), marker="1")
    if "policy" in after_changes:
        policy = after_changes["policy"]
        assert isinstance(policy, AuditPolicy)
        after = _report((), marker="2", policy=policy)
    else:
        after = _rehash(_report((), marker="2"), **after_changes)
    with pytest.raises(ValueError, match="declaration does not match"):
        compare_reports(before, after)

    values = {declaration_field: True, "justification": "operator-reviewed migration"}
    compatibility = ReportDiffCompatibility(**values)
    assert (
        compare_reports(before, after, compatibility=compatibility).compatibility == compatibility
    )

    unchanged = _report((), marker="2")
    with pytest.raises(ValueError, match="declaration does not match"):
        compare_reports(before, unchanged, compatibility=compatibility)


def test_compatibility_and_transition_records_are_strict() -> None:
    """Direct and serialised records reject wrong types, fields, and rationale shapes."""
    with pytest.raises(ValueError, match="must be booleans"):
        ReportDiffCompatibility(repository_change=cast(bool, 1))
    with pytest.raises(ValueError, match="non-empty"):
        ReportDiffCompatibility(repository_change=True)
    with pytest.raises(ValueError, match="requires a declared change"):
        ReportDiffCompatibility(justification="unneeded")
    with pytest.raises(ValueError, match="fields"):
        ReportDiffCompatibility.from_dict({})
    encoded = ReportDiffCompatibility().to_dict()
    encoded["branch_change"] = 1
    with pytest.raises(ValueError, match="boolean"):
        ReportDiffCompatibility.from_dict(encoded)

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        CandidateAnchorMatch("bad", "f" * 64, "reason")
    with pytest.raises(ValueError, match="non-empty"):
        CandidateAnchorMatch("e" * 64, "f" * 64, "")
    with pytest.raises(ValueError, match="fields"):
        CandidateAnchorMatch.from_dict({})
    with pytest.raises(ValueError, match="unsupported"):
        CandidateAnchorChange("e" * 64, "f" * 64, "a" * 64, cast(Any, "other"), "")
    with pytest.raises(ValueError, match="must not carry"):
        CandidateAnchorChange("e" * 64, "f" * 64, "a" * 64, "automatic", "reason")
    with pytest.raises(ValueError, match="non-empty"):
        CandidateAnchorChange("e" * 64, "f" * 64, "a" * 64, "declared", "")
    with pytest.raises(ValueError, match="fields"):
        CandidateAnchorChange.from_dict({})
    invalid_change = CandidateAnchorChange("e" * 64, "f" * 64, "a" * 64, "automatic", "").to_dict()
    invalid_change["match_basis"] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        CandidateAnchorChange.from_dict(invalid_change)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(schema_version="9"), "schema version"),
        (lambda value: value.update(diff_digest="0" * 64), "does not replay"),
        (lambda value: value.update(before_report_digest="bad"), "lowercase SHA-256"),
        (lambda value: value.update(retained_candidate_ids={}), "must be an array"),
        (lambda value: value.pop("appeared_candidate_ids"), "fields"),
        (lambda value: value.update(anchor_changes={}), "must be an array"),
    ],
)
def test_replay_rejects_tampering_and_schema_drift(
    mutation: object,
    message: str,
) -> None:
    """A stored diff must reproduce byte-for-byte from both exact parents."""
    candidate = _candidate("retained", "1")
    before = _report((candidate,), marker="1")
    after = _report((candidate,), marker="2")
    encoded = compare_reports(before, after).to_dict()
    mutator = mutation
    assert callable(mutator)
    mutator(encoded)
    with pytest.raises(ValueError, match=message):
        ReportDiff.from_dict(encoded, before_report=before, after_report=after)


def test_report_and_diff_file_boundaries_fail_closed(tmp_path: Path) -> None:
    """Unavailable history is an input error, never an empty historical report."""
    before = _report((), marker="1")
    after = _report((), marker="2")
    diff = compare_reports(before, after)
    path = tmp_path / "diff.json"
    path.write_text(diff.to_json(), encoding="utf-8")
    assert ReportDiff.from_path(path, before_report=before, after_report=after) == diff
    with pytest.raises(ValueError, match="cannot read report diff"):
        ReportDiff.from_path(tmp_path / "missing.json", before_report=before, after_report=after)
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read report diff"):
        ReportDiff.from_path(path, before_report=before, after_report=after)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("branch"), "fields"),
        (lambda value: value.update(schema_version="9"), "schema version"),
        (lambda value: value.update(candidates={}), "candidates must be an array"),
        (
            lambda value: value["policy"].update(
                ignored_inventory=[
                    {"evidence_id": "local", "path": ".local", "capture": "presence"}
                ]
            ),
            "does not match policy declarations",
        ),
        (lambda value: value.update(git_object_format="sha512"), "unsupported"),
        (lambda value: value.update(head="1"), "contradict object format"),
    ],
)
def test_historical_report_loader_rejects_schema_and_relationship_drift(
    tmp_path: Path,
    mutation: object,
    message: str,
) -> None:
    """The compatibility loader relaxes versions, not record integrity."""
    value = _report((), marker="1").to_dict()
    mutator = mutation
    assert callable(mutator)
    mutator(value)
    path = tmp_path / "historical.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        read_report_for_diff(path)


def test_cli_compares_a_declared_historical_rule_pack(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Historical rule-pack evidence is usable only with an exact declaration."""
    current = _report((), marker="2")
    historical = _rehash(
        _report((), marker="1"),
        rule_pack_version="rigor-foundry/historical",
        rule_pack_digest="a" * 64,
    )
    historical_path = tmp_path / "historical.json"
    current_path = tmp_path / "current.json"
    historical_path.write_text(historical.to_json(), encoding="utf-8")
    current_path.write_text(current.to_json(), encoding="utf-8")
    base = [
        "report-diff",
        "--before",
        str(historical_path),
        "--after",
        str(current_path),
    ]
    assert main(base) == 2
    assert "rule pack change declaration" in capsys.readouterr().err
    assert (
        main(
            [
                *base,
                "--declare-rule-pack-change",
                "--justification",
                "reviewed rule-pack migration",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["compatibility"]["rule_pack_change"] is True


def test_cli_emits_stdout_exclusive_output_and_declared_matches(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The real CLI loads both reports, mappings, and safe explicit output."""
    old = (_candidate("duplicate", "1"), _candidate("duplicate", "2"))
    new = (_candidate("duplicate", "3"), _candidate("duplicate", "4"))
    before = _report(old, marker="1")
    after = _report(new, marker="4")
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    matches_path = tmp_path / "matches.json"
    before_path.write_text(before.to_json(), encoding="utf-8")
    after_path.write_text(after.to_json(), encoding="utf-8")
    matches_path.write_text(
        json.dumps(
            {
                "schema_version": REPORT_DIFF_SCHEMA_VERSION,
                "matches": [
                    CandidateAnchorMatch(old[0].candidate_id, new[0].candidate_id, "A").to_dict(),
                    CandidateAnchorMatch(old[1].candidate_id, new[1].candidate_id, "B").to_dict(),
                ],
            }
        ),
        encoding="utf-8",
    )
    base = [
        "report-diff",
        "--before",
        str(before_path),
        "--after",
        str(after_path),
        "--anchor-matches",
        str(matches_path),
    ]
    assert main(base) == 0
    stdout = json.loads(capsys.readouterr().out)
    assert len(stdout["anchor_changes"]) == 2

    output = tmp_path / "result.json"
    assert main([*base, "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == stdout
    assert main([*base, "--output", str(output)]) == 2
    assert "already exists" in capsys.readouterr().err


def test_cli_rejects_unavailable_history_and_bad_match_documents(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing reports and malformed mapping files return the input-error status."""
    after = _report((), marker="2")
    after_path = tmp_path / "after.json"
    after_path.write_text(after.to_json(), encoding="utf-8")
    assert (
        main(
            ["report-diff", "--before", str(tmp_path / "missing.json"), "--after", str(after_path)]
        )
        == 2
    )
    assert "cannot read audit report" in capsys.readouterr().err

    before = _report((), marker="1")
    before_path = tmp_path / "before.json"
    before_path.write_text(before.to_json(), encoding="utf-8")
    matches = tmp_path / "matches.json"
    matches.write_text("{bad", encoding="utf-8")
    assert (
        main(
            [
                "report-diff",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
                "--anchor-matches",
                str(matches),
            ]
        )
        == 2
    )
    assert "cannot read anchor matches" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"schema_version": REPORT_DIFF_SCHEMA_VERSION}, "fields"),
        ({"schema_version": "9", "matches": []}, "schema version"),
        ({"schema_version": REPORT_DIFF_SCHEMA_VERSION, "matches": {}}, "must be an array"),
    ],
)
def test_cli_rejects_anchor_match_document_schema_drift(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    document: dict[str, object],
    message: str,
) -> None:
    """The optional mapping document is strict and versioned."""
    before = _report((), marker="1")
    after = _report((), marker="2")
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    matches_path = tmp_path / "matches.json"
    before_path.write_text(before.to_json(), encoding="utf-8")
    after_path.write_text(after.to_json(), encoding="utf-8")
    matches_path.write_text(json.dumps(document), encoding="utf-8")
    assert (
        main(
            [
                "report-diff",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
                "--anchor-matches",
                str(matches_path),
            ]
        )
        == 2
    )
    assert message in capsys.readouterr().err


def test_cli_without_match_document_uses_the_empty_mapping(tmp_path: Path) -> None:
    """The common unambiguous CLI path needs no auxiliary document."""
    before = _report((), marker="1")
    after = _report((), marker="2")
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(before.to_json(), encoding="utf-8")
    after_path.write_text(after.to_json(), encoding="utf-8")
    assert main(["report-diff", "--before", str(before_path), "--after", str(after_path)]) == 0
