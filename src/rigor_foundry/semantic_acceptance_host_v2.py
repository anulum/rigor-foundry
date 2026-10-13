# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected v2 semantic acceptance dependency
"""Compose signed CLEAR and exact source proofs under one protected host lease."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Final

from .discovery_receipt_host import HostDiscoveryReceiptSelection
from .discovery_source_schema import parse_json
from .model_primitives import require_digest, require_identifier
from .models import canonical_digest
from .semantic_acceptance_policy import ProposalAuthorAttribution, ReviewerIdentityPolicy
from .semantic_acceptance_source import match_accepted_semantic_source
from .semantic_ratification_source import verify_full_text_ratification_source
from .semantic_source_host import HostSemanticSourceState, HostSemanticSourceVerifier
from .semantic_transition import SemanticTransitionProposal
from .semantic_transition_acceptance_v2 import SignedSemanticAcceptanceV2
from .source_capture import read_source_payload

HOST_ACCEPTANCE_SELECTION_SCHEMA: Final = "host-semantic-acceptance-selection.v2"
HOST_ACCEPTANCE_PROOF_SCHEMA: Final = "host-semantic-acceptance-verification.v2"
_MAX_PROPOSAL_ARTIFACT: Final = 1024 * 1024
_MAX_FINDINGS: Final = 1024 * 1024


@dataclass(frozen=True)
class HostSemanticAcceptanceSelectionV2:
    """Integrity-bound host choice of proposal, review and source objects.

    Attributes
    ----------
    proposal_digest : str
        Selected proposal digest.
    proposal_artifact_sha256 : str
        Hash of the exact selected proposal artifact.
    source_selection_digest : str
        Selected existing semantic-source lease digest.
    discovery_source_selection_digest : str
        Selected nested discovery receipt generation digest.
    acceptance_digest : str
        Selected signed reviewer acceptance envelope digest.
    reviewer_policy_digest : str
        Complete selected reviewer policy digest.
    reviewer_id : str
        Expected reviewer identity from that selected policy.
    author_attribution_digest : str
        Selected author-attribution integrity digest.
    ratification_manifest_sha256 : str
        Exact selected native full-text ratification manifest hash.
    normative_source_sha256 : str
        Hash of exact source bytes containing the four successor statements.
    findings_record_path : Path
        Absolute selected path to retained independent review findings.
    selection_digest : str
        Canonical digest binding all selected fields and the findings path.

    Notes
    -----
    The record is data. The host must protect its selection and the sources from agent replacement.
    """

    proposal_digest: str
    proposal_artifact_sha256: str
    source_selection_digest: str
    discovery_source_selection_digest: str
    acceptance_digest: str
    reviewer_policy_digest: str
    reviewer_id: str
    author_attribution_digest: str
    ratification_manifest_sha256: str
    normative_source_sha256: str
    findings_record_path: Path
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        proposal_digest: str,
        proposal_artifact_sha256: str,
        source_selection_digest: str,
        discovery_source_selection_digest: str,
        acceptance_digest: str,
        reviewer_policy_digest: str,
        reviewer_id: str,
        author_attribution_digest: str,
        ratification_manifest_sha256: str,
        normative_source_sha256: str,
        findings_record_path: Path,
    ) -> HostSemanticAcceptanceSelectionV2:
        """Recompute the complete host selection digest without signing a review.

        Parameters
        ----------
        proposal_digest : str
            Exact selected proposal digest.
        proposal_artifact_sha256 : str
            Hash of the selected serialized proposal bytes.
        source_selection_digest : str
            Expected existing semantic-source selection digest.
        discovery_source_selection_digest : str
            Expected discovery selection bound by that same source lease.
        acceptance_digest : str
            Selected signed reviewer acceptance envelope digest.
        reviewer_policy_digest : str
            Complete selected reviewer identity policy digest.
        reviewer_id : str
            Exact selected reviewer identity.
        author_attribution_digest : str
            Selected owner or host author-attribution digest.
        ratification_manifest_sha256 : str
            Hash of the selected native ratification manifest.
        normative_source_sha256 : str
            Hash of the selected full normative source bytes.
        findings_record_path : Path
            Absolute path with no parent traversal to selected retained findings.

        Returns
        -------
        HostSemanticAcceptanceSelectionV2
            Validated selection record with a digest over every choice.

        Raises
        ------
        ValueError
            A digest, identity or findings path is malformed.
        """
        if (
            not isinstance(findings_record_path, Path)
            or not findings_record_path.is_absolute()
            or ".." in findings_record_path.parts
        ):
            raise ValueError("acceptance findings path must be absolute and untraversed")
        values = {
            "proposal_digest": proposal_digest,
            "proposal_artifact_sha256": proposal_artifact_sha256,
            "source_selection_digest": source_selection_digest,
            "discovery_source_selection_digest": discovery_source_selection_digest,
            "acceptance_digest": acceptance_digest,
            "reviewer_policy_digest": reviewer_policy_digest,
            "author_attribution_digest": author_attribution_digest,
            "ratification_manifest_sha256": ratification_manifest_sha256,
            "normative_source_sha256": normative_source_sha256,
        }
        checked = {
            name: require_digest(value, f"acceptance host.{name}")
            for name, value in values.items()
        }
        identity = require_identifier(reviewer_id, "acceptance host.reviewer_id")
        return cls(
            **checked,
            reviewer_id=identity,
            findings_record_path=findings_record_path,
            selection_digest=canonical_digest(
                {
                    "schema_version": HOST_ACCEPTANCE_SELECTION_SCHEMA,
                    **checked,
                    "reviewer_id": identity,
                    "findings_record_path": str(findings_record_path),
                }
            ),
        )


@dataclass(frozen=True)
class HostSemanticAcceptanceStateV2:
    """Consistent selected evidence and revocation data under one host lease.

    Attributes
    ----------
    selected : HostSemanticAcceptanceSelectionV2
        Protected selection of every expected source and acceptance object.
    expected_selection_digest : str
        Protected precondition for the exact selection record.
    revoked_digests : frozenset[str]
        Protected snapshot of revoked artifact digests.
    revoked_key_ids : frozenset[str]
        Protected snapshot of revoked reviewer key identifiers.
    source_verifier : HostSemanticSourceVerifier
        Host verifier for the exact selected semantic source and discovery lease.
    discovery_selection : HostDiscoveryReceiptSelection
        Exact protected discovery receipt selection and budgets.
    acceptance : SignedSemanticAcceptanceV2
        Exact selected signed reviewer acceptance.
    reviewer_policy : ReviewerIdentityPolicy
        Selected reviewer keys, identities and lifecycle policy.
    author_attribution : ProposalAuthorAttribution
        Selected owner or host attestation of proposal authorship.
    ratification_transcript_path : Path
        Protected path to the original selected native ratification source.

    Notes
    -----
    The state provider must hold every selected record and revocation snapshot consistent throughout
    verification; a caller-created state grants no trust.
    """

    selected: HostSemanticAcceptanceSelectionV2
    expected_selection_digest: str
    revoked_digests: frozenset[str]
    revoked_key_ids: frozenset[str]
    source_verifier: HostSemanticSourceVerifier
    discovery_selection: HostDiscoveryReceiptSelection
    acceptance: SignedSemanticAcceptanceV2
    reviewer_policy: ReviewerIdentityPolicy
    author_attribution: ProposalAuthorAttribution
    ratification_transcript_path: Path


@dataclass(frozen=True)
class HostSemanticAcceptanceVerifierV2:
    """Verify accepted dependencies inside a protected state lease.

    Attributes
    ----------
    state : Callable[[], AbstractContextManager[HostSemanticAcceptanceStateV2]]
        Host callable yielding the pinned acceptance state in a context manager.
    clock : Callable[[], datetime]
        Host callable supplying current timezone-aware UTC for reviewer lifecycle checks.

    Notes
    -----
    Production composition must protect all selected records and revocation data from agent writes.
    Fixture state providers do not establish protected custody.
    """

    state: Callable[[], AbstractContextManager[HostSemanticAcceptanceStateV2]]
    clock: Callable[[], datetime]

    def verify(
        self,
        proposal: SemanticTransitionProposal,
        *,
        proposal_artifact: bytes,
        proposal_source: bytes,
        original_owner_question: bytes,
        original_owner_reply: bytes,
        normative_source: bytes,
        ratification_manifest: bytes,
        ratification_question: bytes,
        ratification_reply: bytes,
        findings: bytes,
    ) -> dict[str, object]:
        """Recheck signed acceptance and every selected source dependency.

        Parameters
        ----------
        proposal : SemanticTransitionProposal
            Exact unchanged four-successor proposal.
        proposal_artifact : bytes
            Bounded serialized artifact that parses to the same proposal.
        proposal_source : bytes
            Exact original proposal source capture.
        original_owner_question : bytes
            Selected source-selection owner question capture.
        original_owner_reply : bytes
            Selected source-selection owner reply capture.
        normative_source : bytes
            Exact LF-terminated source containing the selected statement spans.
        ratification_manifest : bytes
            Selected full-text native ratification manifest.
        ratification_question : bytes
            Exact selected full-text owner question capture.
        ratification_reply : bytes
            Exact selected owner reply capture.
        findings : bytes
            Bounded exact retained independent-review findings bytes.

        Returns
        -------
        dict[str, object]
            Digest-bound accepted-transition dependency with guard_admissible false, binding the
            selected source, reviewer policy, ratification and acceptance.

        Raises
        ------
        ValueError
            Input wire, selected records, capture data, budgets or native lineage are malformed.
        PermissionError
            A selection, revocation, nested discovery pin, source, signature, identity or ratification
            differs.
        OSError
            A selected retained or native source cannot be safely read.
        RuntimeError
            The state context suppresses a failure and no verified result remains.

        Notes
        -----
        The original semantic-source verifier runs on the same held source state whose selected
        discovery digest was compared. The returned proof cannot select a pack or authorize an effect.
        """
        parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
        if (
            not isinstance(proposal_artifact, bytes)
            or not 0 < len(proposal_artifact) <= _MAX_PROPOSAL_ARTIFACT
            or SemanticTransitionProposal.from_dict(parse_json(proposal_artifact)) != parsed
        ):
            raise ValueError("acceptance proposal artifact differs")
        if not isinstance(findings, bytes) or not 0 < len(findings) <= _MAX_FINDINGS:
            raise ValueError("acceptance findings are not bounded bytes")
        artifact_hash = sha256(proposal_artifact).hexdigest()
        result: dict[str, object] | None = None
        with self.state() as current:
            if not isinstance(current, HostSemanticAcceptanceStateV2):
                raise PermissionError("semantic acceptance host state is unavailable")
            selected = current.selected
            checked = HostSemanticAcceptanceSelectionV2.build(
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
            expected = require_digest(
                current.expected_selection_digest, "acceptance host.expected_selection_digest"
            )
            revoked = frozenset(
                require_digest(value, "acceptance host.revoked_digest")
                for value in current.revoked_digests
            )
            if (
                checked != selected
                or checked.selection_digest != expected
                or bool(
                    revoked.intersection(
                        {
                            expected,
                            checked.proposal_digest,
                            checked.acceptance_digest,
                            checked.reviewer_policy_digest,
                            checked.author_attribution_digest,
                            checked.source_selection_digest,
                            checked.discovery_source_selection_digest,
                        }
                    )
                )
                or parsed.proposal_digest != checked.proposal_digest
                or artifact_hash != checked.proposal_artifact_sha256
                or not isinstance(current.source_verifier, HostSemanticSourceVerifier)
                or not isinstance(current.discovery_selection, HostDiscoveryReceiptSelection)
                or not isinstance(current.acceptance, SignedSemanticAcceptanceV2)
                or not isinstance(current.reviewer_policy, ReviewerIdentityPolicy)
                or not isinstance(current.author_attribution, ProposalAuthorAttribution)
                or not isinstance(current.ratification_transcript_path, Path)
            ):
                raise PermissionError("semantic acceptance differs from host selection")
            discovery = current.discovery_selection
            rebuilt_discovery = HostDiscoveryReceiptSelection.build(
                lineage_root=discovery.lineage_root,
                base_name=discovery.base_name,
                transaction_names=discovery.transaction_names,
                base_sha256=discovery.base_sha256,
                base_metadata_fields=discovery.base_metadata_fields,
                progress_limits=discovery.progress_limits,
                replay_digest=discovery.replay_digest,
                source_root=discovery.source_root,
                manifest_name=discovery.manifest_name,
                source_limits=discovery.source_limits,
                receipt_id=discovery.receipt_id,
                receipt_digest=discovery.receipt_digest,
                proposal_digest=discovery.proposal_digest,
            )
            if (
                rebuilt_discovery != discovery
                or discovery.selection_digest != checked.discovery_source_selection_digest
                or discovery.proposal_digest != checked.proposal_digest
            ):
                raise PermissionError("discovery source differs from host selection")
            source: dict[str, object] | None = None
            with current.source_verifier.state() as source_state:
                if (
                    not isinstance(source_state, HostSemanticSourceState)
                    or source_state.selected.discovery_selection_digest
                    != checked.discovery_source_selection_digest
                ):
                    raise PermissionError("discovery source differs from semantic source lease")
                source = HostSemanticSourceVerifier(lambda: nullcontext(source_state)).verify(
                    parsed,
                    proposal_source=proposal_source,
                    owner_question=original_owner_question,
                    owner_reply=original_owner_reply,
                )
            if (
                source is None
                or source.get("assertion_class") != "selected-semantic-source-integrity-only"
                or source.get("promotable") is not False
                or source.get("selection_digest") != checked.source_selection_digest
            ):
                raise PermissionError("semantic source proof differs from host selection")
            retained_findings = read_source_payload(
                checked.findings_record_path, maximum_bytes=_MAX_FINDINGS
            )
            if retained_findings != findings:
                raise PermissionError("acceptance findings record differs from host selection")
            signed = SignedSemanticAcceptanceV2.from_dict(current.acceptance.to_dict())
            policy = ReviewerIdentityPolicy.from_dict(current.reviewer_policy.to_dict())
            author = ProposalAuthorAttribution.from_dict(current.author_attribution.to_dict())
            body = signed.body.to_dict()
            reviewer_key_id = require_identifier(
                body["reviewer_key_id"], "acceptance.reviewer_key_id"
            )
            if (
                signed != current.acceptance
                or signed.acceptance_digest != checked.acceptance_digest
                or policy != current.reviewer_policy
                or policy.policy_digest != checked.reviewer_policy_digest
                or author != current.author_attribution
                or author.attribution_digest != checked.author_attribution_digest
                or reviewer_key_id in current.revoked_key_ids
                or body["reviewer_id"] != checked.reviewer_id
                or body["proposal_digest"] != checked.proposal_digest
                or body["proposal_artifact_sha256"] != artifact_hash
                or body["parent_replay_digest"] != parsed.parent_replay_digest
                or body["source_verification_digest"] != source.get("source_verification_digest")
                or body["discovery_source_selection_digest"]
                != checked.discovery_source_selection_digest
                or body["source_limits"] != asdict(discovery.source_limits)
                or body["normative_source_sha256"] != checked.normative_source_sha256
                or body["owner_ratification_manifest_sha256"]
                != checked.ratification_manifest_sha256
                or body["findings_sha256"] != sha256(findings).hexdigest()
                or not signed.verify_signature(policy=policy, author=author, now=self.clock())
            ):
                raise PermissionError("signed semantic CLEAR is absent or inactive")
            span = match_accepted_semantic_source(
                parsed, signed.body, normative_source=normative_source
            )
            ratification = verify_full_text_ratification_source(
                manifest_bytes=ratification_manifest,
                question_capture=ratification_question,
                reply_capture=ratification_reply,
                transcript_path=current.ratification_transcript_path,
                expected_manifest_sha256=str(body["owner_ratification_manifest_sha256"]),
                expected_question_sha256=str(body["owner_question_sha256"]),
                expected_reply_sha256=str(body["owner_reply_sha256"]),
            )
            if (
                span.get("guard_admissible") is not False
                or ratification.get("guard_admissible") is not False
            ):
                raise PermissionError("semantic evidence was promoted by a dependency")
            result = {
                "schema_version": HOST_ACCEPTANCE_PROOF_SCHEMA,
                "assertion_class": "accepted-transition-dependency-only",
                "guard_admissible": False,
                "selection_digest": expected,
                "proposal_digest": parsed.proposal_digest,
                "source_verification_digest": source["source_verification_digest"],
                "source_relation_digest": span["proof_digest"],
                "ratification_proof_digest": ratification["proof_digest"],
                "acceptance_digest": signed.acceptance_digest,
                "reviewer_policy_digest": policy.policy_digest,
                "reviewer_trust_policy_digest": policy.trust_policy.policy_digest,
            }
        if result is None:
            raise PermissionError("semantic acceptance host state suppressed failure")
        return result
