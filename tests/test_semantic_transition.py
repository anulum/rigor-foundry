# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — semantic transition proposal tests
"""Exercise proposal parsing against public discovery replay and captured bytes."""

from __future__ import annotations

import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest
from discovery_source_support import limits as source_limits
from discovery_source_support import load_shard, records, snapshot, write_shard

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.discovery_progress import ProgressLimits, replay_discovery_progress
from rigor_foundry.discovery_source_validation import validate_discovery_sources
from rigor_foundry.semantic_transition import SemanticTransitionProposal, StatementReplacement

_HOST_SOURCE = b"first successor\nsecond successor\nthird successor\nfourth successor\n"
_HOST_QUESTION = b"owner question\n"
_HOST_REPLY = b"owner approval\n"


def _evidence(
    root: Path,
    *,
    receipt_digest: str | None = None,
) -> tuple[SemanticTransitionProposal, dict[str, object], bytes, bytes, bytes]:
    source = _HOST_SOURCE
    question = _HOST_QUESTION
    reply = _HOST_REPLY
    receipt_id = "owner-source"
    receipt_digest = receipt_digest or sha256(b"receipt bytes").hexdigest()
    records: list[dict[str, object]] = []
    replacements = []
    for line_number, line in enumerate(source.splitlines(keepends=True), start=1):
        predecessor = f"old-{line_number}"
        successor = f"new-{line_number}"
        records.extend(
            [
                {"candidate_id": predecessor, "source_receipt": None},
                {
                    "candidate_id": successor,
                    "source_receipt": receipt_id,
                    "semantic_status": "unreviewed",
                    "promotable": False,
                },
            ]
        )
        replacements.append(
            StatementReplacement.build(
                predecessor_id=predecessor,
                successor_id=successor,
                first_line=line_number,
                last_line=line_number,
                statement_digest=sha256(line).hexdigest(),
            )
        )
    base: dict[str, object] = {
        "records": records,
        "receipts": {receipt_id: {"receipt_digest": receipt_digest}},
    }
    (root / "base.json").write_text(json.dumps(base), encoding="utf-8")
    replay = replay_discovery_progress(
        root,
        "base.json",
        (),
        base_sha256=canonical_digest(base),
        limits=ProgressLimits(10000, 10000, 8, 1, 1),
    )
    proposal = SemanticTransitionProposal.build(
        parent_replay_digest=str(replay["state_sha256"]),
        proposal_source_digest=sha256(source).hexdigest(),
        owner_question_digest=sha256(question).hexdigest(),
        owner_reply_digest=sha256(reply).hexdigest(),
        source_receipt_id=receipt_id,
        source_receipt_digest=receipt_digest,
        replacements=tuple(replacements),
    )
    return proposal, replay, source, question, reply


def _snapshot_with_successors(root: Path) -> None:
    """Place all four proposal successors in real declared source shards."""
    manifest = snapshot(root)
    manifest["candidate_count"] = 4
    for index in (0, 1):
        shard = load_shard(root, index)
        original = shard["candidates"][0]
        first = deepcopy(original)
        second = deepcopy(original)
        first["candidate_id"] = f"new-{2 * index + 1}"
        second["candidate_id"] = f"new-{2 * index + 2}"
        shard["candidates"] = [first, second]
        records(manifest, "shards")[index]["candidates"] = 2
        write_shard(root, manifest, shard, index)


def test_declared_discovery_source_is_rechecked_without_authority(tmp_path: Path) -> None:
    """Tie a proposal receipt to actual declared captures, never promotion."""
    _snapshot_with_successors(tmp_path)
    budget = source_limits(tmp_path, candidates=4, spans=4)
    receipt = validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    proposal, replay, _, _, _ = _evidence(tmp_path, receipt_digest=str(receipt["receipt_digest"]))
    before = deepcopy(replay)
    assert proposal.matches_declared_discovery_source(
        replay_result=replay,
        source_root=tmp_path,
        manifest_name="manifest.json",
        limits=budget,
    )
    assert replay == before
    assert replay["promotable"] is False
    (tmp_path / "source0.txt").write_bytes(b"Changed\n")
    assert not proposal.matches_declared_discovery_source(
        replay_result=replay,
        source_root=tmp_path,
        manifest_name="manifest.json",
        limits=budget,
    )


def test_declared_discovery_source_refuses_crossed_replay(tmp_path: Path) -> None:
    """A real receipt cannot be substituted into another replay state."""
    _snapshot_with_successors(tmp_path)
    budget = source_limits(tmp_path, candidates=4, spans=4)
    receipt = validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    proposal, replay, _, _, _ = _evidence(tmp_path, receipt_digest=str(receipt["receipt_digest"]))
    crossed = deepcopy(replay)
    state = crossed["state"]
    assert isinstance(state, dict)
    receipts = state["receipts"]
    assert isinstance(receipts, dict)
    receipts["owner-source"]["receipt_digest"] = "0" * 64
    assert not proposal.matches_declared_discovery_source(
        replay_result=crossed,
        source_root=tmp_path,
        manifest_name="manifest.json",
        limits=budget,
    )


def test_declared_receipt_without_successor_membership_refuses(tmp_path: Path) -> None:
    """Even an exact receipt must name every proposed successor in its shard."""
    snapshot(tmp_path)
    budget = source_limits(tmp_path, candidates=4)
    receipt = validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    proposal, replay, _, _, _ = _evidence(tmp_path, receipt_digest=str(receipt["receipt_digest"]))
    assert not proposal.matches_declared_discovery_source(
        replay_result=replay,
        source_root=tmp_path,
        manifest_name="manifest.json",
        limits=budget,
    )


def _rebuild(
    proposal: SemanticTransitionProposal,
    *,
    replacements: tuple[StatementReplacement, ...] | None = None,
    source_digest: str | None = None,
    parent_digest: str | None = None,
) -> SemanticTransitionProposal:
    return SemanticTransitionProposal.build(
        parent_replay_digest=parent_digest or proposal.parent_replay_digest,
        proposal_source_digest=source_digest or proposal.proposal_source_digest,
        owner_question_digest=proposal.owner_question_digest,
        owner_reply_digest=proposal.owner_reply_digest,
        source_receipt_id=proposal.source_receipt_id,
        source_receipt_digest=proposal.source_receipt_digest,
        replacements=proposal.replacements if replacements is None else replacements,
    )


def test_exact_captured_replay_is_observed_without_policy_promotion(tmp_path: Path) -> None:
    """Match immutable four-link evidence without changing discovery state."""
    proposal, replay, source, question, reply = _evidence(tmp_path)
    before = deepcopy(replay)
    parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
    assert parsed == proposal
    assert parsed.matches_captured_evidence(
        replay_result=replay,
        proposal_source=source,
        owner_question=question,
        owner_reply=reply,
    )
    assert replay == before
    assert replay["promotable"] is False
    assert "accepted" not in parsed.to_dict()


@pytest.mark.parametrize(
    "case",
    [
        "stale-parent",
        "promoted-replay",
        "missing-predecessor",
        "crossed-successor",
        "old-rebound",
        "new-unbound",
        "new-reviewed",
        "new-promoted",
        "revoked-receipt",
        "changed-source",
        "changed-question",
        "changed-reply",
        "missing-linefeed",
        "duplicate-id",
        "wrong-state-digest",
        "missing-record-array",
        "wrong-statement-hash",
        "missing-receipt",
        "non-json-state",
    ],
)
def test_changed_evidence_refuses(tmp_path: Path, case: str) -> None:
    """Refuse stale, crossed, promoted and changed source/evidence paths."""
    proposal, replay, source, question, reply = _evidence(tmp_path)
    replay = deepcopy(replay)
    state = replay["state"]
    assert isinstance(state, dict)
    records = state["records"]
    assert isinstance(records, list)
    if case == "stale-parent":
        replay["state_sha256"] = "0" * 64
    elif case == "promoted-replay":
        replay["promotable"] = True
    elif case == "missing-predecessor":
        records.pop(0)
    elif case == "crossed-successor":
        records[1]["candidate_id"] = "new-2"
    elif case == "old-rebound":
        records[0]["source_receipt"] = "owner-source"
    elif case == "new-unbound":
        records[1]["source_receipt"] = None
    elif case == "new-reviewed":
        records[1]["semantic_status"] = "accepted"
    elif case == "new-promoted":
        records[1]["promotable"] = True
    elif case == "revoked-receipt":
        receipts = state["receipts"]
        assert isinstance(receipts, dict)
        receipts["owner-source"]["receipt_digest"] = "0" * 64
    elif case == "changed-source":
        source = source.replace(b"first", b"other")
    elif case == "changed-question":
        question = b"different question\n"
    elif case == "changed-reply":
        reply = b"different reply\n"
    elif case == "missing-linefeed":
        source = source.rstrip(b"\n")
        proposal = _rebuild(proposal, source_digest=sha256(source).hexdigest())
    elif case == "duplicate-id":
        records[2]["candidate_id"] = "old-1"
    elif case == "wrong-state-digest":
        records[7]["unrelated"] = "changed without replay"
    elif case == "missing-record-array":
        state["records"] = {}
    elif case == "wrong-statement-hash":
        first = proposal.replacements[0]
        changed = StatementReplacement.build(
            predecessor_id=first.predecessor_id,
            successor_id=first.successor_id,
            first_line=first.first_line,
            last_line=first.last_line,
            statement_digest="0" * 64,
        )
        proposal = _rebuild(proposal, replacements=(changed, *proposal.replacements[1:]))
    elif case == "missing-receipt":
        receipts = state["receipts"]
        assert isinstance(receipts, dict)
        receipts.pop("owner-source")
    elif case == "non-json-state":
        state["unserialisable"] = object()
    if case in {
        "missing-predecessor",
        "crossed-successor",
        "old-rebound",
        "new-unbound",
        "new-reviewed",
        "new-promoted",
        "revoked-receipt",
        "duplicate-id",
        "missing-record-array",
        "missing-receipt",
    }:
        digest = canonical_digest(state)
        replay["state_sha256"] = digest
        proposal = _rebuild(proposal, parent_digest=digest)
    assert not proposal.matches_captured_evidence(
        replay_result=replay,
        proposal_source=source,
        owner_question=question,
        owner_reply=reply,
    )


@pytest.mark.parametrize(
    "case",
    [
        "extra-field",
        "missing-field",
        "wrong-schema",
        "wrong-digest",
        "empty-replacements",
        "duplicate-predecessor",
        "duplicate-successor",
        "replacement-cycle",
        "overlapping-spans",
        "unordered-spans",
        "wrong-replacement-digest",
        "boolean-line",
        "non-array-replacements",
        "same-identity",
    ],
)
def test_malformed_proposal_refuses(tmp_path: Path, case: str) -> None:
    """Reject invalid wire shapes and identity/span ambiguity at parse time."""
    proposal, _, _, _, _ = _evidence(tmp_path)
    wire = proposal.to_dict()
    replacements = wire["replacements"]
    assert isinstance(replacements, list)
    if case == "extra-field":
        wire["accepted"] = True
    elif case == "missing-field":
        wire.pop("owner_reply_digest")
    elif case == "wrong-schema":
        wire["schema_version"] = "active"
    elif case == "wrong-digest":
        wire["proposal_digest"] = "0" * 64
    elif case == "empty-replacements":
        wire["replacements"] = []
    elif case == "duplicate-predecessor":
        replacements[1] = {**replacements[1], "predecessor_id": "old-1"}
    elif case == "duplicate-successor":
        replacements[1] = {**replacements[1], "successor_id": "new-1"}
    elif case == "replacement-cycle":
        replacements[1] = {**replacements[1], "successor_id": "old-1"}
    elif case == "overlapping-spans":
        replacements[1] = {**replacements[1], "first_line": 1}
    elif case == "unordered-spans":
        replacements.reverse()
    elif case == "wrong-replacement-digest":
        replacements[0] = {**replacements[0], "replacement_digest": "0" * 64}
    elif case == "boolean-line":
        replacements[0] = {**replacements[0], "first_line": True}
    elif case == "non-array-replacements":
        wire["replacements"] = {}
    elif case == "same-identity":
        replacements[0] = {**replacements[0], "successor_id": "old-1"}
    with pytest.raises(ValueError):
        SemanticTransitionProposal.from_dict(wire)


@pytest.mark.parametrize("case", ["duplicate-predecessor", "duplicate-successor", "cycle", "span"])
def test_structurally_valid_links_still_refuse_ambiguous_transition(
    tmp_path: Path, case: str
) -> None:
    """Reject ambiguity even when every replacement has a valid own digest."""
    proposal, _, _, _, _ = _evidence(tmp_path)
    first, second, *rest = proposal.replacements
    if case == "duplicate-predecessor":
        second = StatementReplacement.build(
            predecessor_id=first.predecessor_id,
            successor_id=second.successor_id,
            first_line=second.first_line,
            last_line=second.last_line,
            statement_digest=second.statement_digest,
        )
    elif case == "duplicate-successor":
        second = StatementReplacement.build(
            predecessor_id=second.predecessor_id,
            successor_id=first.successor_id,
            first_line=second.first_line,
            last_line=second.last_line,
            statement_digest=second.statement_digest,
        )
    elif case == "cycle":
        second = StatementReplacement.build(
            predecessor_id=second.predecessor_id,
            successor_id=first.predecessor_id,
            first_line=second.first_line,
            last_line=second.last_line,
            statement_digest=second.statement_digest,
        )
    else:
        second = StatementReplacement.build(
            predecessor_id=second.predecessor_id,
            successor_id=second.successor_id,
            first_line=first.first_line,
            last_line=second.last_line,
            statement_digest=second.statement_digest,
        )
    with pytest.raises(ValueError):
        _rebuild(proposal, replacements=(first, second, *rest))
