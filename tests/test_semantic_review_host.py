# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected semantic review tests
"""Exercise exact source/review composition with synthetic signing keys only."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import public_key_hex, sign_message
from test_semantic_source_host import _fixture as source_fixture
from test_semantic_source_host import _verifier as source_verifier
from test_semantic_transition import _HOST_QUESTION, _HOST_REPLY, _HOST_SOURCE

from rigor_foundry.models import canonical_digest
from rigor_foundry.semantic_review_host import (
    HostSemanticReviewSelection,
    HostSemanticReviewState,
    HostSemanticReviewVerifier,
)
from rigor_foundry.semantic_transition import SemanticTransitionProposal
from rigor_foundry.semantic_transition_review import (
    SEMANTIC_REVIEW_DOMAIN,
    ReviewVerdict,
    SemanticTransitionReview,
)
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2TrustRoles
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_NOW = datetime(2026, 9, 19, tzinfo=UTC)
_SIGNED_AT = "2026-09-18T00:00:00Z"
_AUTHOR = "fixture-author"
_REVIEWER = "fixture-independent-reviewer"
_KEY = "fixture-reviewer-key"


def _policy(key_id: str, *, revoked_at: str = "") -> OfflineTrustPolicy:
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id)),
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
                revoked_at=revoked_at,
            ),
        )
    )


def _roles(*, revoked_at: str = "") -> RuleChainV2TrustRoles:
    return RuleChainV2TrustRoles.build(
        pack_issuers=_policy("fixture-pack-key"),
        project_selectors=_policy("fixture-selector-key"),
        lock_resolvers=_policy("fixture-resolver-key"),
        semantic_reviewers=_policy(_KEY, revoked_at=revoked_at),
    )


def _review(
    proposal: SemanticTransitionProposal,
    *,
    artifact_digest: str,
    source_digest: str,
    verdict: ReviewVerdict = "clear",
) -> SemanticTransitionReview:
    arguments = {
        "proposal_digest": proposal.proposal_digest,
        "proposal_artifact_digest": artifact_digest,
        "source_verification_digest": source_digest,
        "parent_replay_digest": proposal.parent_replay_digest,
        "author_id": _AUTHOR,
        "reviewer_id": _REVIEWER,
        "reviewer_key_id": _KEY,
        "verdict": verdict,
        "findings_digest": "f" * 64,
        "reviewed_at": _SIGNED_AT,
    }
    payload = SemanticTransitionReview.payload(**arguments)
    signature = sign_message(_KEY, SEMANTIC_REVIEW_DOMAIN, canonical_digest(payload))
    return SemanticTransitionReview.build(**arguments, signature_hex=signature)


def _fixture(
    root: Path,
    *,
    verdict: ReviewVerdict = "clear",
    reviewer_revoked_at: str = "",
) -> tuple[SemanticTransitionProposal, bytes, HostSemanticReviewState, Path]:
    proposal, source_state, native_path = source_fixture(root)
    source = source_verifier(source_state)
    source_proof = source.verify(
        proposal,
        proposal_source=_HOST_SOURCE,
        owner_question=_HOST_QUESTION,
        owner_reply=_HOST_REPLY,
    )
    artifact = json.dumps(proposal.to_dict(), sort_keys=True).encode()
    artifact_digest = sha256(artifact).hexdigest()
    review = _review(
        proposal,
        artifact_digest=artifact_digest,
        source_digest=str(source_proof["source_verification_digest"]),
        verdict=verdict,
    )
    roles = _roles(revoked_at=reviewer_revoked_at)
    selected = HostSemanticReviewSelection.build(
        proposal_digest=proposal.proposal_digest,
        proposal_artifact_digest=artifact_digest,
        source_selection_digest=source_state.selected.selection_digest,
        review_digest=review.review_digest,
        author_id=_AUTHOR,
        reviewer_id=_REVIEWER,
        reviewer_key_id=_KEY,
        reviewer_policy_digest=roles.semantic_reviewers.policy_digest,
    )
    state = HostSemanticReviewState(
        selected, selected.selection_digest, frozenset(), source, review, roles
    )
    return proposal, artifact, state, native_path


def _verifier(
    state: HostSemanticReviewState, *, now: datetime = _NOW
) -> HostSemanticReviewVerifier:
    @contextmanager
    def lease() -> Iterator[HostSemanticReviewState]:
        yield state

    return HostSemanticReviewVerifier(lease, lambda: now)


def _verify(
    verifier: HostSemanticReviewVerifier,
    proposal: SemanticTransitionProposal,
    artifact: bytes,
) -> dict[str, object]:
    return verifier.verify(
        proposal,
        proposal_artifact=artifact,
        proposal_source=_HOST_SOURCE,
        owner_question=_HOST_QUESTION,
        owner_reply=_HOST_REPLY,
    )


def test_synthetic_independent_clear_yields_only_transition_dependency(tmp_path: Path) -> None:
    """A signed fixture CLEAR is a dependency, never a Guard grant."""
    proposal, artifact, state, _ = _fixture(tmp_path)
    proof = _verify(_verifier(state), proposal, artifact)
    assert proof["proposal_digest"] == proposal.proposal_digest
    assert proof["review_digest"] == state.review.review_digest
    assert proof["source_verification_digest"] == state.review.source_verification_digest
    assert proof["guard_admissible"] is False
    assert proof["acceptance_digest"] == canonical_digest(
        {
            "schema_version": "accepted-semantic-transition.v1",
            "proposal_digest": proposal.proposal_digest,
            "review_digest": state.review.review_digest,
            "source_verification_digest": state.review.source_verification_digest,
        }
    )


def test_valid_but_different_proposal_artifact_refuses(tmp_path: Path) -> None:
    """A parseable proposal for another replay cannot borrow this review."""
    proposal, _, state, _ = _fixture(tmp_path)
    other = SemanticTransitionProposal.build(
        parent_replay_digest="0" * 64,
        proposal_source_digest=proposal.proposal_source_digest,
        owner_question_digest=proposal.owner_question_digest,
        owner_reply_digest=proposal.owner_reply_digest,
        source_receipt_id=proposal.source_receipt_id,
        source_receipt_digest=proposal.source_receipt_digest,
        replacements=proposal.replacements,
    )
    artifact = json.dumps(other.to_dict(), sort_keys=True).encode()
    with pytest.raises(ValueError, match="artifact differs"):
        _verify(_verifier(state), proposal, artifact)


def test_valid_but_crossed_source_selection_refuses(tmp_path: Path) -> None:
    """A well-formed review selection cannot borrow another source proof."""
    proposal, artifact, state, _ = _fixture(tmp_path)
    selected = HostSemanticReviewSelection.build(
        proposal_digest=state.selected.proposal_digest,
        proposal_artifact_digest=state.selected.proposal_artifact_digest,
        source_selection_digest="0" * 64,
        review_digest=state.selected.review_digest,
        author_id=state.selected.author_id,
        reviewer_id=state.selected.reviewer_id,
        reviewer_key_id=state.selected.reviewer_key_id,
        reviewer_policy_digest=state.selected.reviewer_policy_digest,
    )
    crossed = replace(
        state, selected=selected, expected_selection_digest=selected.selection_digest
    )
    with pytest.raises(ValueError, match="source proof differs"):
        _verify(_verifier(crossed), proposal, artifact)


@pytest.mark.parametrize(
    "fault",
    ["artifact", "selection", "revoked", "review", "policy", "source", "state"],
)
def test_changed_or_missing_host_review_refuses(tmp_path: Path, fault: str) -> None:
    """No caller-substituted artifact, reviewer or source can yield acceptance."""
    proposal, artifact, state, native_path = _fixture(tmp_path)
    if fault == "artifact":
        artifact = artifact + b" "
    elif fault == "selection":
        state = replace(state, expected_selection_digest="0" * 64)
    elif fault == "revoked":
        state = replace(
            state, revoked_selection_digests=frozenset({state.selected.selection_digest})
        )
    elif fault == "review":
        state = replace(state, review=replace(state.review, signature_hex="0" * 128))
    elif fault == "policy":
        state = replace(state, roles=_roles(revoked_at="2026-09-18T12:00:00Z"))
    elif fault == "source":
        native_path.write_bytes(native_path.read_bytes() + b"{}\n")
    else:
        state = cast(HostSemanticReviewState, object())
    with pytest.raises((ValueError, PermissionError)):
        _verify(_verifier(state), proposal, artifact)


@pytest.mark.parametrize("fault", ["objection", "revoked-key", "future-clock"])
def test_signed_but_ineligible_clear_refuses(tmp_path: Path, fault: str) -> None:
    """A real signature does not bypass verdict, key lifecycle or time."""
    kwargs: dict[str, object] = {}
    now = _NOW
    if fault == "objection":
        kwargs["verdict"] = "changes-requested"
    elif fault == "revoked-key":
        kwargs["reviewer_revoked_at"] = "2026-09-18T12:00:00Z"
    else:
        now = datetime(2026, 9, 17, tzinfo=UTC)
    proposal, artifact, state, _ = _fixture(tmp_path, **kwargs)
    with pytest.raises(PermissionError, match="CLEAR is absent"):
        _verify(_verifier(state, now=now), proposal, artifact)


def test_host_cannot_suppress_review_failure(tmp_path: Path) -> None:
    """A swallowed nested failure cannot produce an implicit accepted result."""
    proposal, artifact, state, native_path = _fixture(tmp_path)
    native_path.write_bytes(native_path.read_bytes() + b"{}\n")

    @contextmanager
    def suppressing_state() -> Iterator[HostSemanticReviewState]:
        with suppress(ValueError):
            yield state

    with pytest.raises(PermissionError, match="suppressed verification failure"):
        _verify(HostSemanticReviewVerifier(suppressing_state, lambda: _NOW), proposal, artifact)
