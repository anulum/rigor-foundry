# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected v2 semantic CLEAR host tests
"""Exercise the full public review dependency with real file and signature reads."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_semantic_ratification_source import _fixture as ratification_fixture
from test_semantic_source_host import _fixture as source_fixture
from test_semantic_source_host import _verifier as source_verifier
from test_semantic_transition import _HOST_QUESTION, _HOST_REPLY, _HOST_SOURCE
from test_semantic_transition_acceptance_v2 import _AUTHOR, _KEY, _body, _policy

from rigor_foundry.discovery_receipt_host import (
    HostDiscoveryReceiptSelection,
    HostDiscoveryReceiptState,
)
from rigor_foundry.semantic_acceptance_host_v2 import (
    HostSemanticAcceptanceSelectionV2,
    HostSemanticAcceptanceStateV2,
    HostSemanticAcceptanceVerifierV2,
)
from rigor_foundry.semantic_acceptance_policy import ProposalAuthorAttribution
from rigor_foundry.semantic_acceptance_source import match_accepted_semantic_source
from rigor_foundry.semantic_source_host import HostSemanticSourceState, HostSemanticSourceVerifier
from rigor_foundry.semantic_transition import SemanticTransitionProposal
from rigor_foundry.semantic_transition_acceptance_v2 import (
    ACCEPTANCE_DOMAIN,
    SemanticAcceptanceBodyV2,
    SignedSemanticAcceptanceV2,
)

_NOW = datetime(2026, 9, 23, 0, 30, tzinfo=UTC)
_FINDINGS = b"CEO independent semantic CLEAR for four exact successor links.\n"


def _fixture(
    root: Path,
) -> tuple[SemanticTransitionProposal, bytes, HostSemanticAcceptanceStateV2, dict[str, object]]:
    """Build the proposal, two native transcripts and one signed v2 acceptance."""
    source_root = root / "discovery"
    source_root.mkdir()
    proposal, source_state, _ = source_fixture(source_root)
    source = source_verifier(source_state)
    source_proof = source.verify(
        proposal,
        proposal_source=_HOST_SOURCE,
        owner_question=_HOST_QUESTION,
        owner_reply=_HOST_REPLY,
    )
    with source_state.discovery_verifier.state() as discovery_state:
        assert isinstance(discovery_state, HostDiscoveryReceiptState)
        discovery = discovery_state.selected
    artifact = json.dumps(proposal.to_dict(), sort_keys=True).encode()
    artifact_hash = sha256(artifact).hexdigest()
    author = ProposalAuthorAttribution.build(
        proposal_digest=proposal.proposal_digest,
        proposal_artifact_sha256=artifact_hash,
        author_id=_AUTHOR,
        evidence_sha256="c" * 64,
        attested_by="owner",
        attested_at="2026-09-23T00:00:00Z",
    )
    ratification_root = root / "ratification"
    ratification_root.mkdir()
    ratification = ratification_fixture(ratification_root)
    body = _body()
    body.update(
        proposal_digest=proposal.proposal_digest,
        proposal_artifact_sha256=artifact_hash,
        parent_replay_digest=proposal.parent_replay_digest,
        source_verification_digest=source_proof["source_verification_digest"],
        discovery_source_selection_digest=discovery.selection_digest,
        source_limits=asdict(discovery.source_limits),
        normative_source_sha256=sha256(_HOST_SOURCE).hexdigest(),
        statement_sha256=[item.statement_digest for item in proposal.replacements],
        replacements=[
            {
                "predecessor_id": item.predecessor_id,
                "successor_id": item.successor_id,
                "statement_sha256": item.statement_digest,
            }
            for item in proposal.replacements
        ],
        author_attribution_digest=author.attribution_digest,
        owner_ratification_manifest_sha256=ratification["expected_manifest_sha256"],
        owner_question_sha256=ratification["expected_question_sha256"],
        owner_reply_sha256=ratification["expected_reply_sha256"],
        findings_sha256=sha256(_FINDINGS).hexdigest(),
    )
    signed_body = SemanticAcceptanceBodyV2.from_dict(body)
    signed = SignedSemanticAcceptanceV2.build(
        body=signed_body,
        signature_hex=sign_message(_KEY, ACCEPTANCE_DOMAIN, signed_body.payload_digest),
    )
    policy = _policy()
    findings_path = root / "CEO_REVIEW.md"
    findings_path.write_bytes(_FINDINGS)
    selected = HostSemanticAcceptanceSelectionV2.build(
        proposal_digest=proposal.proposal_digest,
        proposal_artifact_sha256=artifact_hash,
        source_selection_digest=source_state.selected.selection_digest,
        discovery_source_selection_digest=discovery.selection_digest,
        acceptance_digest=signed.acceptance_digest,
        reviewer_policy_digest=policy.policy_digest,
        reviewer_id=str(body["reviewer_id"]),
        author_attribution_digest=author.attribution_digest,
        ratification_manifest_sha256=str(ratification["expected_manifest_sha256"]),
        normative_source_sha256=sha256(_HOST_SOURCE).hexdigest(),
        findings_record_path=findings_path,
    )
    state = HostSemanticAcceptanceStateV2(
        selected=selected,
        expected_selection_digest=selected.selection_digest,
        revoked_digests=frozenset(),
        revoked_key_ids=frozenset(),
        source_verifier=source,
        discovery_selection=discovery,
        acceptance=signed,
        reviewer_policy=policy,
        author_attribution=author,
        ratification_transcript_path=ratification["transcript_path"],
    )
    inputs: dict[str, object] = {
        "proposal_artifact": artifact,
        "proposal_source": _HOST_SOURCE,
        "original_owner_question": _HOST_QUESTION,
        "original_owner_reply": _HOST_REPLY,
        "normative_source": _HOST_SOURCE,
        "ratification_manifest": ratification["manifest_bytes"],
        "ratification_question": ratification["question_capture"],
        "ratification_reply": ratification["reply_capture"],
        "findings": _FINDINGS,
    }
    return proposal, artifact, state, inputs


def _host(state: HostSemanticAcceptanceStateV2) -> HostSemanticAcceptanceVerifierV2:
    """Expose one stable synthetic host lease for the public verifier."""

    @contextmanager
    def lease() -> Iterator[HostSemanticAcceptanceStateV2]:
        yield state

    return HostSemanticAcceptanceVerifierV2(lease, lambda: _NOW)


def _verify(
    proposal: SemanticTransitionProposal,
    state: HostSemanticAcceptanceStateV2,
    inputs: dict[str, object],
) -> dict[str, object]:
    """Call the public host boundary with exact fixture bytes."""
    return _host(state).verify(
        proposal,
        proposal_artifact=cast(bytes, inputs["proposal_artifact"]),
        proposal_source=cast(bytes, inputs["proposal_source"]),
        original_owner_question=cast(bytes, inputs["original_owner_question"]),
        original_owner_reply=cast(bytes, inputs["original_owner_reply"]),
        normative_source=cast(bytes, inputs["normative_source"]),
        ratification_manifest=cast(bytes, inputs["ratification_manifest"]),
        ratification_question=cast(bytes, inputs["ratification_question"]),
        ratification_reply=cast(bytes, inputs["ratification_reply"]),
        findings=cast(bytes, inputs["findings"]),
    )


def test_signed_clear_with_selected_native_and_source_proofs_is_dependency_only(
    tmp_path: Path,
) -> None:
    """Real Ed25519 and two native transcripts yield only a read-only dependency."""
    proposal, _, state, inputs = _fixture(tmp_path)
    proof = _verify(proposal, state, inputs)
    assert proof == _verify(proposal, state, inputs)
    assert proof["acceptance_digest"] == state.acceptance.acceptance_digest
    assert proof["guard_admissible"] is False


@pytest.mark.parametrize(
    ("fault", "match"),
    [
        ("revoked-acceptance", "host selection"),
        ("revoked-key", "signed semantic CLEAR"),
        ("changed-findings", "findings record differs"),
        ("changed-ratification", "capture differs"),
        ("changed-source", "statement differs"),
        ("changed-signature", "envelope digest differs"),
        ("crossed-discovery", "discovery source differs"),
        ("crossed-host-selection", "host selection"),
    ],
)
def test_crossed_or_revoked_semantic_dependency_refuses(
    tmp_path: Path, fault: str, match: str
) -> None:
    """One wrong signed or selected dependency cannot borrow another CLEAR."""
    proposal, _, state, inputs = _fixture(tmp_path)
    if fault == "revoked-acceptance":
        state = replace(state, revoked_digests=frozenset({state.acceptance.acceptance_digest}))
    elif fault == "revoked-key":
        state = replace(state, revoked_key_ids=frozenset({_KEY}))
    elif fault == "changed-findings":
        inputs["findings"] = b"changed findings\n"
    elif fault == "changed-ratification":
        inputs["ratification_reply"] = b"Changed reply\n"
    elif fault == "changed-source":
        inputs["normative_source"] = b"changed source\n"
    elif fault == "changed-signature":
        state = replace(state, acceptance=replace(state.acceptance, signature_hex="0" * 128))
    elif fault == "crossed-discovery":
        state = replace(
            state, discovery_selection=replace(state.discovery_selection, receipt_digest="0" * 64)
        )
    else:
        state = replace(state, selected=replace(state.selected, acceptance_digest="0" * 64))
    with pytest.raises((ValueError, PermissionError), match=match):
        _verify(proposal, state, inputs)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("proposal_artifact", b"", "proposal artifact differs"),
        ("proposal_artifact", b"{}", "proposal fields do not match"),
        ("findings", b"", "findings are not bounded"),
        ("findings", b"x" * (1024 * 1024 + 1), "findings are not bounded"),
        ("findings", "not bytes", "findings are not bounded"),
    ],
)
def test_bounded_exact_artifact_and_findings_are_required(
    tmp_path: Path, field: str, value: object, match: str
) -> None:
    """Review cannot bind missing proposal bytes or an unbounded findings file."""
    proposal, _, state, inputs = _fixture(tmp_path)
    inputs[field] = value
    with pytest.raises(ValueError, match=match):
        _verify(proposal, state, inputs)


def test_valid_but_different_proposal_artifact_refuses(tmp_path: Path) -> None:
    """A parseable second proposal cannot borrow the selected review."""
    proposal, _, state, inputs = _fixture(tmp_path)
    other = SemanticTransitionProposal.build(
        parent_replay_digest=proposal.parent_replay_digest,
        proposal_source_digest=proposal.proposal_source_digest,
        owner_question_digest="0" * 64,
        owner_reply_digest=proposal.owner_reply_digest,
        source_receipt_id=proposal.source_receipt_id,
        source_receipt_digest=proposal.source_receipt_digest,
        replacements=proposal.replacements,
    )
    inputs["proposal_artifact"] = json.dumps(other.to_dict(), sort_keys=True).encode()
    with pytest.raises(ValueError, match="proposal artifact differs"):
        _verify(proposal, state, inputs)


def test_unavailable_host_state_refuses(tmp_path: Path) -> None:
    """A provider returning an unrelated object cannot select a review."""
    proposal, _, _, inputs = _fixture(tmp_path)

    @contextmanager
    def wrong_lease() -> Iterator[HostSemanticAcceptanceStateV2]:
        yield cast(HostSemanticAcceptanceStateV2, object())

    verifier = HostSemanticAcceptanceVerifierV2(wrong_lease, lambda: _NOW)
    with pytest.raises(PermissionError, match="host state is unavailable"):
        verifier.verify(
            proposal,
            proposal_artifact=cast(bytes, inputs["proposal_artifact"]),
            proposal_source=cast(bytes, inputs["proposal_source"]),
            original_owner_question=cast(bytes, inputs["original_owner_question"]),
            original_owner_reply=cast(bytes, inputs["original_owner_reply"]),
            normative_source=cast(bytes, inputs["normative_source"]),
            ratification_manifest=cast(bytes, inputs["ratification_manifest"]),
            ratification_question=cast(bytes, inputs["ratification_question"]),
            ratification_reply=cast(bytes, inputs["ratification_reply"]),
            findings=cast(bytes, inputs["findings"]),
        )


def test_selected_source_proof_cannot_borrow_a_different_source_selection(
    tmp_path: Path,
) -> None:
    """The protected final choice must match the nested source verifier's choice."""
    proposal, _, state, inputs = _fixture(tmp_path)
    prior = state.selected
    selected = HostSemanticAcceptanceSelectionV2.build(
        proposal_digest=prior.proposal_digest,
        proposal_artifact_sha256=prior.proposal_artifact_sha256,
        source_selection_digest="0" * 64,
        discovery_source_selection_digest=prior.discovery_source_selection_digest,
        acceptance_digest=prior.acceptance_digest,
        reviewer_policy_digest=prior.reviewer_policy_digest,
        reviewer_id=prior.reviewer_id,
        author_attribution_digest=prior.author_attribution_digest,
        ratification_manifest_sha256=prior.ratification_manifest_sha256,
        normative_source_sha256=prior.normative_source_sha256,
        findings_record_path=prior.findings_record_path,
    )
    crossed = replace(
        state, selected=selected, expected_selection_digest=selected.selection_digest
    )
    with pytest.raises(PermissionError, match="source proof differs"):
        _verify(proposal, crossed, inputs)


def test_valid_signed_discovery_snapshot_cannot_cross_the_leased_source(tmp_path: Path) -> None:
    """A valid second budget snapshot must belong to the actual verified source lease."""
    proposal, _, state, inputs = _fixture(tmp_path)
    prior = state.discovery_selection
    different = HostDiscoveryReceiptSelection.build(
        lineage_root=prior.lineage_root,
        base_name=prior.base_name,
        transaction_names=prior.transaction_names,
        base_sha256=prior.base_sha256,
        base_metadata_fields=prior.base_metadata_fields,
        progress_limits=prior.progress_limits,
        replay_digest=prior.replay_digest,
        source_root=prior.source_root,
        manifest_name=prior.manifest_name,
        source_limits=replace(prior.source_limits, file_bytes=prior.source_limits.file_bytes + 1),
        receipt_id=prior.receipt_id,
        receipt_digest=prior.receipt_digest,
        proposal_digest=prior.proposal_digest,
    )
    assert different.selection_digest != prior.selection_digest
    body = state.acceptance.body.to_dict()
    body["discovery_source_selection_digest"] = different.selection_digest
    body["source_limits"] = asdict(different.source_limits)
    checked = SemanticAcceptanceBodyV2.from_dict(body)
    signed = SignedSemanticAcceptanceV2.build(
        body=checked, signature_hex=sign_message(_KEY, ACCEPTANCE_DOMAIN, checked.payload_digest)
    )
    assert signed.verify_signature(
        policy=state.reviewer_policy, author=state.author_attribution, now=_NOW
    )
    selected = replace(
        state.selected,
        discovery_source_selection_digest=different.selection_digest,
        acceptance_digest=signed.acceptance_digest,
    )
    selected = HostSemanticAcceptanceSelectionV2.build(
        proposal_digest=selected.proposal_digest,
        proposal_artifact_sha256=selected.proposal_artifact_sha256,
        source_selection_digest=selected.source_selection_digest,
        discovery_source_selection_digest=selected.discovery_source_selection_digest,
        acceptance_digest=selected.acceptance_digest,
        reviewer_policy_digest=selected.reviewer_policy_digest,
        reviewer_id=selected.reviewer_id,
        author_attribution_digest=selected.author_attribution_digest,
        ratification_manifest_sha256=selected.ratification_manifest_sha256,
        normative_source_sha256=selected.normative_source_sha256,
        findings_record_path=selected.findings_record_path,
    )
    crossed = replace(
        state,
        selected=selected,
        expected_selection_digest=selected.selection_digest,
        discovery_selection=different,
        acceptance=signed,
    )
    with pytest.raises(
        PermissionError, match="discovery source differs from semantic source lease"
    ):
        _verify(proposal, crossed, inputs)


def test_source_provider_cannot_suppress_an_invalid_leased_state(tmp_path: Path) -> None:
    """Suppressing a nested state failure cannot turn absence into a source proof."""
    proposal, _, state, inputs = _fixture(tmp_path)

    @contextmanager
    def invalid_source_lease() -> Iterator[HostSemanticSourceState]:
        """Return malformed provider data and suppress its downstream refusal."""
        with suppress(PermissionError):
            yield cast(HostSemanticSourceState, object())

    changed = replace(state, source_verifier=HostSemanticSourceVerifier(invalid_source_lease))
    with pytest.raises(PermissionError, match="semantic source proof differs"):
        _verify(proposal, changed, inputs)


def test_findings_record_requires_protected_exact_file(tmp_path: Path) -> None:
    """A caller's matching bytes cannot replace the host-selected CEO record."""
    proposal, _, state, inputs = _fixture(tmp_path)
    state.selected.findings_record_path.write_bytes(b"changed retained review\n")
    with pytest.raises(PermissionError, match="findings record differs"):
        _verify(proposal, state, inputs)
    selected = state.selected
    with pytest.raises(ValueError, match="findings path"):
        HostSemanticAcceptanceSelectionV2.build(
            proposal_digest=selected.proposal_digest,
            proposal_artifact_sha256=selected.proposal_artifact_sha256,
            source_selection_digest=selected.source_selection_digest,
            discovery_source_selection_digest=selected.discovery_source_selection_digest,
            acceptance_digest=selected.acceptance_digest,
            reviewer_policy_digest=selected.reviewer_policy_digest,
            reviewer_id=selected.reviewer_id,
            author_attribution_digest=selected.author_attribution_digest,
            ratification_manifest_sha256=selected.ratification_manifest_sha256,
            normative_source_sha256=selected.normative_source_sha256,
            findings_record_path=Path("relative-review.md"),
        )


def test_dependency_cannot_promote_guard_and_suppressed_failure_refuses(tmp_path: Path) -> None:
    """Real signed inputs cannot grant Guard admission or hide a source failure.

    match_accepted_semantic_source and verify_full_text_ratification_source
    return literal False for guard_admissible on every successful path. The
    host's promoted-dependency guard cannot be reached by unchanged functions
    and public inputs. No replacement verifier manufactures True here; that
    guard remains uncovered. The nearest real boundary rejects an attempted
    admission field in the signed body and keeps the verified chain read-only.
    """
    proposal, _, state, inputs = _fixture(tmp_path)
    source_proof = match_accepted_semantic_source(
        proposal, state.acceptance.body, normative_source=cast(bytes, inputs["normative_source"])
    )
    assert source_proof["guard_admissible"] is False
    with pytest.raises(ValueError, match="fields"):
        SemanticAcceptanceBodyV2.from_dict(
            {**state.acceptance.body.to_dict(), "guard_admissible": True}
        )
    assert _verify(proposal, state, inputs)["guard_admissible"] is False

    @contextmanager
    def swallowing_lease() -> Iterator[HostSemanticAcceptanceStateV2]:
        """Suppress an inner source mismatch to exercise the outer refusal."""
        with suppress(PermissionError):
            yield state

    inputs["normative_source"] = b"changed source\n"
    verifier = HostSemanticAcceptanceVerifierV2(swallowing_lease, lambda: _NOW)
    with pytest.raises(PermissionError, match="suppressed failure"):
        verifier.verify(
            proposal,
            proposal_artifact=cast(bytes, inputs["proposal_artifact"]),
            proposal_source=cast(bytes, inputs["proposal_source"]),
            original_owner_question=cast(bytes, inputs["original_owner_question"]),
            original_owner_reply=cast(bytes, inputs["original_owner_reply"]),
            normative_source=cast(bytes, inputs["normative_source"]),
            ratification_manifest=cast(bytes, inputs["ratification_manifest"]),
            ratification_question=cast(bytes, inputs["ratification_question"]),
            ratification_reply=cast(bytes, inputs["ratification_reply"]),
            findings=cast(bytes, inputs["findings"]),
        )
