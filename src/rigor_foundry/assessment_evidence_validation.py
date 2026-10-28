# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared original assessment evidence predicates
"""Reuse exact original numeric evidence and signed-review semantics without a profile lock."""

from __future__ import annotations

from datetime import datetime

from .control_assessment import EvidenceReference
from .effective_profile import AdapterLock
from .review_attestation import ReviewDecision, ReviewerAttestation
from .standard_pack import EvidenceContract
from .trust import VerificationTrustStore


def validate_original_evidence_bindings(
    *,
    domain: str,
    adapters: tuple[AdapterLock, ...],
    evidence: tuple[EvidenceReference, ...],
) -> None:
    """Require exact original locked-adapter identity and coverage of the control domain.

    Parameters
    ----------
    domain : str
        Original validated control domain, without a renamed or inferred domain.
    adapters : tuple[AdapterLock, ...]
        Actual original adapter cohort supplied by the consuming selected owner.
    evidence : tuple[EvidenceReference, ...]
        Original validated legacy evidence references. Selection, complete source
        custody and child parsing remain the consuming owner's responsibility.

    Raises
    ------
    ValueError
        An evidence adapter is absent, ambiguous, has another original digest
        or does not cover the control domain.
    """
    for item in evidence:
        matches = tuple(adapter for adapter in adapters if adapter.adapter_id == item.adapter_id)
        if len(matches) != 1 or matches[0].adapter_digest != item.adapter_digest:
            raise ValueError("assessment evidence does not bind an exact locked adapter")
        if domain not in matches[0].domains:
            raise ValueError("assessment evidence adapter does not cover the control domain")


def validate_original_pass_evidence(
    *,
    contract: EvidenceContract,
    missing_adapter_ids: tuple[str, ...],
    instant: datetime,
    evidence: tuple[EvidenceReference, ...],
) -> None:
    """Preserve the original positive numeric freshness and complete adapter/type requirements.

    Parameters
    ----------
    contract : EvidenceContract
        Actual validated original contract, including its positive numeric age
        bound and complete declared evidence-type and adapter sets.
    missing_adapter_ids : tuple[str, ...]
        Original unresolved adapter identities from the selected control.
    instant : datetime
        Actual timezone-aware assessment instant.
    evidence : tuple[EvidenceReference, ...]
        Original validated references. Every item must be fresh; an unrelated
        fresh item cannot hide an expired or future observation.

    Raises
    ------
    ValueError
        Adapters are missing, evidence is empty/not fresh or original required
        adapter/type coverage is incomplete. This supplies no review or gate verdict.
    """
    if missing_adapter_ids:
        raise ValueError("control with missing evidence adapters cannot pass")
    fresh = tuple(item for item in evidence if item.fresh_at(instant, contract.freshness_seconds))
    if len(fresh) != len(evidence) or not fresh:
        raise ValueError("pass requires only fresh, non-empty evidence")
    missing_adapters = set(contract.required_adapters).difference(
        item.adapter_id for item in fresh
    )
    missing_types = set(contract.evidence_types).difference(item.evidence_type for item in fresh)
    if missing_adapters or missing_types:
        raise ValueError("pass evidence does not satisfy adapter and type coverage")


def validate_original_reviewers(
    *,
    contract: EvidenceContract,
    instant: datetime,
    reviews: tuple[ReviewerAttestation, ...],
    assessor: str,
    decision: ReviewDecision,
    review_body_digest: str,
    review_trust_store: VerificationTrustStore | None,
) -> None:
    """Preserve exact signed-body, identity/key independence and original reviewer-count semantics.

    Parameters
    ----------
    contract : EvidenceContract
        Actual original validated contract with a positive independent-review count.
    instant : datetime
        Timezone-aware instant for the unchanged review validity check.
    reviews : tuple[ReviewerAttestation, ...]
        Original complete Ed25519 attestations; asserted status does not qualify.
    assessor : str
        Original case-sensitive identity excluded from independent approval.
    decision : ReviewDecision
        Exact original assessment decision covered by every counted attestation.
    review_body_digest : str
        Actual independently derived assessment body being reviewed.
    review_trust_store : VerificationTrustStore or None
        Explicit original public-key trust selection; no default store is invented.

    Raises
    ------
    ValueError
        An explicit trust store is absent or the original contract lacks enough
        distinct verified reviewer IDs, key IDs and public-key bytes.
    """
    if review_trust_store is None:
        raise ValueError("verified independent reviewers require an explicit trust store")
    verified = tuple(
        item
        for item in reviews
        if item.reviewer_id != assessor
        and item.verified_at(instant, decision, review_body_digest, review_trust_store)
    )
    key_ids = {item.key_id for item in verified}
    reviewer_ids = {item.reviewer_id for item in verified}
    public_key_by_id = {item.key_id: item.public_key_hex for item in review_trust_store.keys}
    public_keys = {public_key_by_id[item.key_id] for item in verified}
    required = contract.minimum_independent_reviewers
    if len(key_ids) < required or len(reviewer_ids) < required or len(public_keys) < required:
        raise ValueError(
            "assessment lacks enough distinct verified independent reviewers and keys"
        )
