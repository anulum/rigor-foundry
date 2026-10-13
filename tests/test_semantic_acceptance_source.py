# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — accepted semantic source tests
"""Exercise exact source spans and successor mapping through the public verifier."""

from __future__ import annotations

from hashlib import sha256

import pytest
from test_semantic_transition_acceptance_v2 import _body

from rigor_foundry.semantic_acceptance_source import match_accepted_semantic_source
from rigor_foundry.semantic_transition import SemanticTransitionProposal, StatementReplacement
from rigor_foundry.semantic_transition_acceptance_v2 import SemanticAcceptanceBodyV2


def _fixture() -> tuple[SemanticTransitionProposal, SemanticAcceptanceBodyV2, bytes]:
    """Build a four-link proposal over one realistic LF-terminated source."""
    clauses = [
        b"Overlay constraints cannot grant publication.\n",
        b"Resolve instruction scope before combining independent constraints.\n",
        b"A selected tool cannot enlarge an approved effect or target.\n",
        b"Runtime availability does not establish permission.\n",
    ]
    source = b"\n".join(clauses)
    replacements = tuple(
        StatementReplacement.build(
            predecessor_id=f"old-{index}",
            successor_id=f"new-{index}",
            first_line=2 * index + 1,
            last_line=2 * index + 1,
            statement_digest=sha256(clause).hexdigest(),
        )
        for index, clause in enumerate(clauses)
    )
    proposal = SemanticTransitionProposal.build(
        parent_replay_digest="d" * 64,
        proposal_source_digest=sha256(source).hexdigest(),
        owner_question_digest="1" * 64,
        owner_reply_digest="2" * 64,
        source_receipt_id="fixture-source-receipt",
        source_receipt_digest="3" * 64,
        replacements=replacements,
    )
    body = {
        **_body(),
        "proposal_digest": proposal.proposal_digest,
        "parent_replay_digest": proposal.parent_replay_digest,
        "normative_source_sha256": sha256(source).hexdigest(),
        "statement_sha256": [item.statement_digest for item in replacements],
        "replacements": [
            {
                "predecessor_id": item.predecessor_id,
                "successor_id": item.successor_id,
                "statement_sha256": item.statement_digest,
            }
            for item in replacements
        ],
    }
    return proposal, SemanticAcceptanceBodyV2.from_dict(body), source


def test_exact_four_source_spans_match_without_granting_guard() -> None:
    """An exact statement relation produces only a non-admissible proof."""
    proposal, acceptance, source = _fixture()
    proof = match_accepted_semantic_source(proposal, acceptance, normative_source=source)
    assert proof["proposal_digest"] == proposal.proposal_digest
    assert proof["normative_source_sha256"] == sha256(source).hexdigest()
    assert proof["guard_admissible"] is False


def test_crossed_successor_with_valid_source_hashes_refuses() -> None:
    """A valid statement digest cannot license a different replacement link."""
    proposal, acceptance, source = _fixture()
    body = acceptance.to_dict()
    links = body["replacements"]
    assert isinstance(links, list)
    crossed = [dict(item) for item in links]
    crossed[0]["successor_id"], crossed[1]["successor_id"] = (
        crossed[1]["successor_id"],
        crossed[0]["successor_id"],
    )
    with pytest.raises(PermissionError, match="differs from proposal"):
        match_accepted_semantic_source(
            proposal,
            SemanticAcceptanceBodyV2.from_dict({**body, "replacements": crossed}),
            normative_source=source,
        )


@pytest.mark.parametrize(
    ("source_change", "error"),
    [
        (b"wrong source\n", "statement differs"),
        (b"missing-final-LF", "LF-terminated"),
        (b"Windows\r\n", "line endings differ"),
    ],
)
def test_changed_or_noncanonical_source_refuses(source_change: bytes, error: str) -> None:
    """A changed source cannot borrow the accepted statement and file hashes."""
    proposal, acceptance, source = _fixture()
    changed = (
        source[:-1]
        if error == "LF-terminated"
        else source.replace(b"Overlay constraints cannot grant publication.\n", source_change)
    )
    with pytest.raises((ValueError, PermissionError), match=error):
        match_accepted_semantic_source(proposal, acceptance, normative_source=changed)


@pytest.mark.parametrize("fault", ["missing-link", "span-outside-source"])
def test_incomplete_or_unavailable_source_span_refuses(fault: str) -> None:
    """A replay with fewer links or an unreadable span cannot be accepted."""
    proposal, acceptance, source = _fixture()
    replacements = proposal.replacements
    if fault == "missing-link":
        replacements = replacements[:3]
    else:
        last = replacements[3]
        replacements = (
            *replacements[:3],
            StatementReplacement.build(
                predecessor_id=last.predecessor_id,
                successor_id=last.successor_id,
                first_line=99,
                last_line=99,
                statement_digest=last.statement_digest,
            ),
        )
    altered = SemanticTransitionProposal.build(
        parent_replay_digest=proposal.parent_replay_digest,
        proposal_source_digest=proposal.proposal_source_digest,
        owner_question_digest=proposal.owner_question_digest,
        owner_reply_digest=proposal.owner_reply_digest,
        source_receipt_id=proposal.source_receipt_id,
        source_receipt_digest=proposal.source_receipt_digest,
        replacements=replacements,
    )
    with pytest.raises(ValueError, match=r"four proposal links|outside the selected file"):
        match_accepted_semantic_source(altered, acceptance, normative_source=source)
