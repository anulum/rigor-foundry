# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only rule-chain candidate verification
"""Join selected source, semantic review, pack and profile evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from .model_primitives import require_digest, require_identifier
from .models import canonical_digest
from .pack_source_host import HostPackSourceVerifier
from .rule_chain_pack_v2 import AuthorityClauseV2, StandardPackV2
from .rule_chain_profile_v2 import ProjectProfileV2
from .semantic_review_host import HostSemanticReviewVerifier
from .semantic_transition import SemanticTransitionProposal
from .signed_rule_chain_v2 import RuleChainV2TrustRoles

RULE_CHAIN_CANDIDATE_REPORT_SCHEMA_VERSION = "rule-chain-candidate-report.v1"


@dataclass(frozen=True)
class RuleChainCandidateReport:
    """Exact read-only verification result, never an effective-rule lock."""

    proposal_digest: str
    acceptance_digest: str
    profile_digest: str
    pack_digests: tuple[str, ...]
    clause_digests: tuple[str, ...]
    reviewer_policy_digest: str
    report_digest: str

    @property
    def guard_admissible(self) -> bool:
        """Refuse effect authority from a candidate inspection."""
        return False


def inspect_rule_chain_candidate(
    *,
    proposal: SemanticTransitionProposal,
    proposal_artifact: bytes,
    proposal_source: bytes,
    owner_question: bytes,
    owner_reply: bytes,
    review_verifier: HostSemanticReviewVerifier,
    packs: tuple[StandardPackV2, ...],
    profile: ProjectProfileV2,
    source_verifiers: Mapping[str, HostPackSourceVerifier],
    roles: RuleChainV2TrustRoles,
    expected_project_id: str,
    expected_scope_digest: str,
    now: datetime,
) -> RuleChainCandidateReport:
    """Verify a proposed signed selection without selecting or granting it.

    All verifiers and trust roles must come from a trusted read-only host
    composition, not from an effect request. The resulting report cannot be
    supplied as an effective profile lock or a dispatch permit. Source changes,
    reviewer revocation and grant/current-state changes require new proofs.

    Parameters
    ----------
    proposal : SemanticTransitionProposal
        Exact source-bound replacement proposal.
    proposal_artifact : bytes
        Retained serialisation selected by the review host.
    proposal_source, owner_question, owner_reply : bytes
        Exact captures checked against discovery and native records.
    review_verifier : HostSemanticReviewVerifier
        Host-selected independent review and source verifier.
    packs : tuple[StandardPackV2, ...]
        Signed packs selected by the project profile.
    profile : ProjectProfileV2
        Signed project choice of pack, authority and freshness IDs.
    source_verifiers : Mapping[str, HostPackSourceVerifier]
        Host-held retained-object verifier keyed by exact pack ID.
    roles : RuleChainV2TrustRoles
        Role-separated trust policies for this candidate.
    expected_project_id : str
        Host-selected project identity.
    expected_scope_digest : str
        Host-selected scope selector digest.
    now : datetime
        Current UTC evaluation instant for signing-key lifecycle checks.

    Returns
    -------
    RuleChainCandidateReport
        Digest-bound, non-admissible read-only inspection result.

    Raises
    ------
    PermissionError
        If the selected host review, signature, source or profile differs.
    ValueError
        If the proposal or its clause relation is malformed.
    """
    parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
    selected = ProjectProfileV2.from_dict(profile.to_dict())
    exact_packs = tuple(StandardPackV2.from_dict(pack.to_dict()) for pack in packs)
    if not isinstance(review_verifier, HostSemanticReviewVerifier):
        raise PermissionError("host semantic review verifier is required")
    RuleChainV2TrustRoles.build(
        pack_issuers=roles.pack_issuers,
        project_selectors=roles.project_selectors,
        lock_resolvers=roles.lock_resolvers,
        semantic_reviewers=roles.semantic_reviewers,
    )
    review = review_verifier.verify(
        parsed,
        proposal_artifact=proposal_artifact,
        proposal_source=proposal_source,
        owner_question=owner_question,
        owner_reply=owner_reply,
    )
    acceptance = require_digest(review.get("acceptance_digest"), "candidate.acceptance_digest")
    reviewer_policy = require_digest(
        review.get("reviewer_policy_digest"), "candidate.reviewer_policy_digest"
    )
    if (
        review.get("assertion_class") != "reviewed-transition-dependency-only"
        or review.get("guard_admissible") is not False
        or review.get("proposal_digest") != parsed.proposal_digest
        or reviewer_policy != roles.semantic_reviewers.policy_digest
        or any(pack.transition_digest != acceptance for pack in exact_packs)
    ):
        raise PermissionError("candidate review and signed packs do not share one transition")
    if not selected.verify_structural_selection(
        packs=exact_packs,
        roles=roles,
        source_verifiers=source_verifiers,
        expected_project_id=require_identifier(expected_project_id, "candidate.project_id"),
        expected_scope_digest=require_digest(expected_scope_digest, "candidate.scope_digest"),
        now=now,
    ):
        raise PermissionError("candidate profile or retained pack sources are unverified")
    clauses = {
        clause.clause_id: clause for pack in exact_packs for clause in pack.authority_clauses
    }
    chosen: tuple[AuthorityClauseV2, ...] = tuple(
        clauses[clause_id] for clause_id in selected.authority_clause_ids
    )
    if any(
        clause.transition_digest != acceptance or not clause.matches_proposal_source(parsed)
        for clause in chosen
    ):
        raise PermissionError("candidate authority clause differs from reviewed source")
    body: dict[str, object] = {
        "schema_version": RULE_CHAIN_CANDIDATE_REPORT_SCHEMA_VERSION,
        "proposal_digest": parsed.proposal_digest,
        "acceptance_digest": acceptance,
        "profile_digest": selected.profile_digest,
        "pack_digests": [pack.pack_digest for pack in exact_packs],
        "clause_digests": [clause.clause_digest for clause in chosen],
        "reviewer_policy_digest": reviewer_policy,
        "guard_admissible": False,
    }
    return RuleChainCandidateReport(
        proposal_digest=parsed.proposal_digest,
        acceptance_digest=acceptance,
        profile_digest=selected.profile_digest,
        pack_digests=tuple(pack.pack_digest for pack in exact_packs),
        clause_digests=tuple(clause.clause_digest for clause in chosen),
        reviewer_policy_digest=reviewer_policy,
        report_digest=canonical_digest(body),
    )
