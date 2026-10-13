# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 four-successor signed chain inspection
"""Join v2 CLEAR, four exact clauses and signed pack/profile without admission."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from .model_primitives import require_digest, require_identifier
from .models import canonical_digest
from .pack_source_host import HostPackSourceVerifier
from .rule_chain_pack_v2 import AuthorityClauseV2, StandardPackV2
from .rule_chain_profile_v2 import ProjectProfileV2
from .semantic_acceptance_host_v2 import HostSemanticAcceptanceVerifierV2
from .semantic_transition import SemanticTransitionProposal
from .signed_rule_chain_v2 import RuleChainV2TrustRoles

RULE_CHAIN_CANDIDATE_V2_SCHEMA: Final = "rule-chain-candidate-report.v2"


@dataclass(frozen=True)
class RuleChainCandidateReportV2:
    """Read-only four-successor inspection result, never a selected lock.

    Attributes
    ----------
    proposal_digest : str
        Exact four-replacement proposal digest.
    acceptance_digest : str
        Verified reviewer-signed acceptance envelope digest.
    profile_digest : str
        Structurally verified project profile digest.
    pack_digests : tuple[str, ...]
        Selected signed pack digests, in selection order.
    successor_clause_digests : tuple[str, ...]
        Four exact selected successor clause digests, in proposal order.
    reviewer_policy_digest : str
        Complete selected reviewer identity policy digest.
    source_relation_digest : str
        Verified exact proposal-to-source relation digest.
    ratification_proof_digest : str
        Selected native full-text ratification dependency digest.
    report_digest : str
        Canonical digest of the complete inspection report.
    """

    proposal_digest: str
    acceptance_digest: str
    profile_digest: str
    pack_digests: tuple[str, ...]
    successor_clause_digests: tuple[str, ...]
    reviewer_policy_digest: str
    source_relation_digest: str
    ratification_proof_digest: str
    report_digest: str

    @property
    def guard_admissible(self) -> bool:
        """Keep candidate reports outside the execution authority boundary.

        Returns
        -------
        bool
            Always false; inspection cannot grant a permit or dispatch an effect.
        """
        return False


def inspect_rule_chain_candidate_v2(
    *,
    proposal: SemanticTransitionProposal,
    proposal_artifact: bytes,
    proposal_source: bytes,
    original_owner_question: bytes,
    original_owner_reply: bytes,
    normative_source: bytes,
    ratification_manifest: bytes,
    ratification_question: bytes,
    ratification_reply: bytes,
    findings: bytes,
    acceptance_verifier: HostSemanticAcceptanceVerifierV2,
    packs: tuple[StandardPackV2, ...],
    profile: ProjectProfileV2,
    source_verifiers: Mapping[str, HostPackSourceVerifier],
    roles: RuleChainV2TrustRoles,
    expected_project_id: str,
    expected_scope_digest: str,
    now: datetime,
) -> RuleChainCandidateReportV2:
    """Verify the four accepted replacements through signed pack and profile APIs.

    Parameters
    ----------
    proposal : SemanticTransitionProposal
        Exact unchanged four-successor proposal.
    proposal_artifact : bytes
        Bounded bytes that parse to the same proposal.
    proposal_source : bytes
        Exact original proposal source capture.
    original_owner_question : bytes
        Exact source-selection owner question capture.
    original_owner_reply : bytes
        Exact source-selection owner reply capture.
    normative_source : bytes
        Exact LF-terminated source containing the selected statement spans.
    ratification_manifest : bytes
        Exact native full-text ratification manifest.
    ratification_question : bytes
        Selected full-text owner question capture.
    ratification_reply : bytes
        Selected exact owner reply capture.
    findings : bytes
        Exact retained independent-review findings bytes.
    acceptance_verifier : HostSemanticAcceptanceVerifierV2
        Host-selected acceptance verifier whose leased policy and source selection are independently
        protected.
    packs : tuple[StandardPackV2, ...]
        Exact signed packs linked to this acceptance.
    profile : ProjectProfileV2
        Signed project selection of those pack objects.
    source_verifiers : Mapping[str, HostPackSourceVerifier]
        Host-owned retained-object source verifier for every pack ID.
    roles : RuleChainV2TrustRoles
        Five independent enrolled signing-role policies.
    expected_project_id : str
        Protected selected project identity.
    expected_scope_digest : str
        Protected selector-scope precondition.
    now : datetime
        Current timezone-aware UTC supplied by the trusted host.

    Returns
    -------
    RuleChainCandidateReportV2
        Non-admissible report binding all four successors and the source dependencies.

    Raises
    ------
    ValueError
        A parsed object, digest, identifier or source capture is malformed.
    PermissionError
        A signature, role, selection, source proof or exact replacement relation differs.
    OSError
        A required retained or native source cannot be safely read.

    Notes
    -----
    A provider supplied by an untrusted caller has no enrollment or selection authority. This API
    supplies no signer, lock selection, grant, permit or dispatch.
    """
    parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
    selected = ProjectProfileV2.from_dict(profile.to_dict())
    exact_packs = tuple(StandardPackV2.from_dict(pack.to_dict()) for pack in packs)
    if not isinstance(acceptance_verifier, HostSemanticAcceptanceVerifierV2):
        raise PermissionError("v2 semantic acceptance host verifier is required")
    RuleChainV2TrustRoles.build(
        pack_issuers=roles.pack_issuers,
        project_selectors=roles.project_selectors,
        lock_resolvers=roles.lock_resolvers,
        semantic_authors=roles.semantic_authors,
        semantic_reviewers=roles.semantic_reviewers,
    )
    review = acceptance_verifier.verify(
        parsed,
        proposal_artifact=proposal_artifact,
        proposal_source=proposal_source,
        original_owner_question=original_owner_question,
        original_owner_reply=original_owner_reply,
        normative_source=normative_source,
        ratification_manifest=ratification_manifest,
        ratification_question=ratification_question,
        ratification_reply=ratification_reply,
        findings=findings,
    )
    acceptance = require_digest(review.get("acceptance_digest"), "candidate.acceptance_digest")
    reviewer_policy = require_digest(
        review.get("reviewer_policy_digest"), "candidate.reviewer_policy_digest"
    )
    reviewer_trust = require_digest(
        review.get("reviewer_trust_policy_digest"), "candidate.reviewer_trust_policy_digest"
    )
    if (
        review.get("assertion_class") != "accepted-transition-dependency-only"
        or review.get("guard_admissible") is not False
        or review.get("proposal_digest") != parsed.proposal_digest
        or reviewer_trust != roles.semantic_reviewers.policy_digest
        or not exact_packs
        or any(pack.transition_digest != acceptance for pack in exact_packs)
    ):
        raise PermissionError("v2 acceptance and signed packs do not share one transition")
    clause_ids = [clause.clause_id for pack in exact_packs for clause in pack.authority_clauses]
    freshness_ids = [
        policy.policy_id for pack in exact_packs for policy in pack.freshness_policies
    ]
    if len(set(clause_ids)) != len(clause_ids) or len(set(freshness_ids)) != len(freshness_ids):
        raise PermissionError("v2 selected packs repeat a clause or freshness policy ID")
    if not selected.verify_structural_selection(
        packs=exact_packs,
        roles=roles,
        source_verifiers=source_verifiers,
        expected_project_id=require_identifier(expected_project_id, "candidate.project_id"),
        expected_scope_digest=require_digest(expected_scope_digest, "candidate.scope_digest"),
        now=now,
    ):
        raise PermissionError("v2 profile or retained pack sources are unverified")
    clauses = {
        clause.clause_id: clause for pack in exact_packs for clause in pack.authority_clauses
    }
    chosen: tuple[AuthorityClauseV2, ...] = tuple(
        clauses[clause_id] for clause_id in selected.authority_clause_ids
    )
    successor_ids = {item.successor_id for item in parsed.replacements}
    linked = tuple(clause for clause in chosen if clause.successor_id in successor_ids)
    if (
        len(linked) != 4
        or {clause.successor_id for clause in linked} != successor_ids
        or any(
            clause.transition_digest != acceptance or not clause.matches_proposal_source(parsed)
            for clause in linked
        )
    ):
        raise PermissionError("v2 profile omits or crosses a reviewed successor clause")
    source_relation = require_digest(
        review.get("source_relation_digest"), "candidate.source_relation_digest"
    )
    ratification = require_digest(
        review.get("ratification_proof_digest"), "candidate.ratification_proof_digest"
    )
    body: dict[str, object] = {
        "schema_version": RULE_CHAIN_CANDIDATE_V2_SCHEMA,
        "proposal_digest": parsed.proposal_digest,
        "acceptance_digest": acceptance,
        "profile_digest": selected.profile_digest,
        "pack_digests": [pack.pack_digest for pack in exact_packs],
        "successor_clause_digests": [clause.clause_digest for clause in linked],
        "reviewer_policy_digest": reviewer_policy,
        "source_relation_digest": source_relation,
        "ratification_proof_digest": ratification,
        "guard_admissible": False,
    }
    return RuleChainCandidateReportV2(
        proposal_digest=parsed.proposal_digest,
        acceptance_digest=acceptance,
        profile_digest=selected.profile_digest,
        pack_digests=tuple(pack.pack_digest for pack in exact_packs),
        successor_clause_digests=tuple(clause.clause_digest for clause in linked),
        reviewer_policy_digest=reviewer_policy,
        source_relation_digest=source_relation,
        ratification_proof_digest=ratification,
        report_digest=canonical_digest(body),
    )
