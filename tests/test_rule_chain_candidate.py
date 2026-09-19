# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only rule-chain candidate tests
"""Exercise the public joined source, review, pack and profile API."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from test_rule_chain_pack_v2 import _clause, _host_source, _pack
from test_rule_chain_pack_v2 import _roles as pack_roles
from test_rule_chain_profile_v2 import _profile
from test_semantic_review_host import _fixture as review_fixture
from test_semantic_review_host import _verifier as review_verifier
from test_semantic_transition import _HOST_QUESTION, _HOST_REPLY, _HOST_SOURCE

from rigor_foundry.pack_source_host import HostPackSourceVerifier
from rigor_foundry.rule_chain_candidate import (
    RuleChainCandidateReport,
    inspect_rule_chain_candidate,
)
from rigor_foundry.rule_chain_pack_v2 import StandardPackV2
from rigor_foundry.rule_chain_profile_v2 import ProjectProfileV2
from rigor_foundry.semantic_review_host import HostSemanticReviewVerifier
from rigor_foundry.semantic_transition import SemanticTransitionProposal
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2TrustRoles

_NOW = datetime(2026, 9, 19, tzinfo=UTC)


def _candidate(
    root: Path,
    *,
    crossed_statement: bool = False,
    crossed_transition: bool = False,
) -> tuple[
    SemanticTransitionProposal,
    bytes,
    HostSemanticReviewVerifier,
    StandardPackV2,
    ProjectProfileV2,
    RuleChainV2TrustRoles,
]:
    proposal, artifact, review_state, _ = review_fixture(root)
    verifier = review_verifier(review_state)
    review = verifier.verify(
        proposal,
        proposal_artifact=artifact,
        proposal_source=_HOST_SOURCE,
        owner_question=_HOST_QUESTION,
        owner_reply=_HOST_REPLY,
    )
    accepted = str(review["acceptance_digest"])
    transition = "2" * 64 if crossed_transition else accepted
    replacement = proposal.replacements[0]
    clause = _clause(
        successor_id=replacement.successor_id,
        statement_digest="4" * 64 if crossed_statement else replacement.statement_digest,
        source_receipt_digest=proposal.source_receipt_digest,
        transition_digest=transition,
    )
    pack = _pack(transition=transition, clauses=(clause,))
    profile = _profile(pack=pack)
    pack_trust = pack_roles()
    roles = RuleChainV2TrustRoles.build(
        pack_issuers=pack_trust.pack_issuers,
        project_selectors=pack_trust.project_selectors,
        lock_resolvers=pack_trust.lock_resolvers,
        semantic_reviewers=review_state.roles.semantic_reviewers,
    )
    return proposal, artifact, verifier, pack, profile, roles


def _inspect(
    candidate: tuple[
        SemanticTransitionProposal,
        bytes,
        HostSemanticReviewVerifier,
        StandardPackV2,
        ProjectProfileV2,
        RuleChainV2TrustRoles,
    ],
    source_verifier: HostPackSourceVerifier,
) -> RuleChainCandidateReport:
    proposal, artifact, verifier, pack, profile, roles = candidate
    return inspect_rule_chain_candidate(
        proposal=proposal,
        proposal_artifact=artifact,
        proposal_source=_HOST_SOURCE,
        owner_question=_HOST_QUESTION,
        owner_reply=_HOST_REPLY,
        review_verifier=verifier,
        packs=(pack,),
        profile=profile,
        source_verifiers={pack.pack_id: source_verifier},
        roles=roles,
        expected_project_id=profile.project_id,
        expected_scope_digest=profile.selector_scope_digest,
        now=_NOW,
    )


def test_public_candidate_pipeline_joins_real_files_and_signed_objects(tmp_path: Path) -> None:
    """A complete fixture chain produces only a read-only report."""
    candidate = _candidate(tmp_path)
    with _host_source() as source:
        report = _inspect(candidate, source)
        assert _inspect(candidate, source) == report
    assert report.proposal_digest == candidate[0].proposal_digest
    assert report.profile_digest == candidate[4].profile_digest
    assert report.pack_digests == (candidate[3].pack_digest,)
    assert report.clause_digests == (candidate[3].authority_clauses[0].clause_digest,)
    assert len(report.report_digest) == 64
    assert report.guard_admissible is False


@pytest.mark.parametrize("fault", ["statement", "transition", "source", "review-policy"])
def test_crossed_candidate_dependency_refuses(tmp_path: Path, fault: str) -> None:
    """A signed but crossed clause, transition, source or reviewer cannot join."""
    candidate = _candidate(
        tmp_path,
        crossed_statement=fault == "statement",
        crossed_transition=fault == "transition",
    )
    if fault == "review-policy":
        proposal, artifact, verifier, pack, profile, roles = candidate
        candidate = (
            proposal,
            artifact,
            verifier,
            pack,
            profile,
            replace(roles, semantic_reviewers=pack_roles().semantic_reviewers),
        )
    source_bytes = b"crossed source" if fault == "source" else b"retained core standard source\n"
    with _host_source(source_bytes=source_bytes) as source, pytest.raises(PermissionError):
        _inspect(candidate, source)


def test_caller_cannot_supply_an_unrecognised_review_provider(tmp_path: Path) -> None:
    """An arbitrary provider object is not a host semantic-review verifier."""
    proposal, artifact, _, pack, profile, roles = _candidate(tmp_path)
    candidate = (
        proposal,
        artifact,
        cast(HostSemanticReviewVerifier, object()),
        pack,
        profile,
        roles,
    )
    with _host_source() as source, pytest.raises(PermissionError, match="verifier is required"):
        _inspect(candidate, source)
