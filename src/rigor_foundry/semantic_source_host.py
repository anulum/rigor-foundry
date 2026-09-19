# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected semantic source composition
"""Compose exact discovery and native-source integrity under one host choice."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from .discovery_receipt_host import HostDiscoveryReceiptVerifier
from .model_primitives import require_digest
from .models import canonical_digest
from .native_source_host import HostNativeSourceVerifier
from .semantic_transition import SemanticTransitionProposal

HOST_SEMANTIC_SOURCE_SELECTION_SCHEMA_VERSION = "host-semantic-source-selection.v1"
HOST_SEMANTIC_SOURCE_VERIFICATION_SCHEMA_VERSION = "host-semantic-source-verification.v1"


@dataclass(frozen=True)
class HostSemanticSourceSelection:
    """Exact proposal and two independent source pins selected by the host."""

    proposal_digest: str
    discovery_selection_digest: str
    native_pin_digest: str
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        proposal_digest: str,
        discovery_selection_digest: str,
        native_pin_digest: str,
    ) -> HostSemanticSourceSelection:
        """Bind all three dependencies without asserting semantic acceptance."""
        proposal = require_digest(proposal_digest, "semantic source.proposal_digest")
        discovery = require_digest(
            discovery_selection_digest, "semantic source.discovery_selection_digest"
        )
        native = require_digest(native_pin_digest, "semantic source.native_pin_digest")
        body: dict[str, object] = {
            "schema_version": HOST_SEMANTIC_SOURCE_SELECTION_SCHEMA_VERSION,
            "proposal_digest": proposal,
            "discovery_selection_digest": discovery,
            "native_pin_digest": native,
        }
        return cls(proposal, discovery, native, canonical_digest(body))


@dataclass(frozen=True)
class HostSemanticSourceState:
    """One consistent host lease over selected pins, verifiers and revocations."""

    selected: HostSemanticSourceSelection
    expected_selection_digest: str
    revoked_selection_digests: frozenset[str]
    discovery_verifier: HostDiscoveryReceiptVerifier
    native_verifier: HostNativeSourceVerifier


@dataclass(frozen=True)
class HostSemanticSourceVerifier:
    """Require both source classes; neither alone can verify owner provenance.

    Production must supply a protected host-held state provider that keeps
    selections and revocations stable across both nested source reads. A
    test-injected provider proves protocol behavior, not trusted enrollment.
    """

    state: Callable[[], AbstractContextManager[HostSemanticSourceState]]

    def verify(
        self,
        proposal: SemanticTransitionProposal,
        *,
        proposal_source: bytes,
        owner_question: bytes,
        owner_reply: bytes,
    ) -> dict[str, object]:
        """Return one non-promotable source proof for an exact transition."""
        parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
        proof: dict[str, object] | None = None
        with self.state() as current:
            if not isinstance(current, HostSemanticSourceState):
                raise PermissionError("semantic source host state is unavailable")
            selected = current.selected
            checked = HostSemanticSourceSelection.build(
                proposal_digest=selected.proposal_digest,
                discovery_selection_digest=selected.discovery_selection_digest,
                native_pin_digest=selected.native_pin_digest,
            )
            expected = require_digest(
                current.expected_selection_digest, "semantic source.expected_selection_digest"
            )
            revoked = frozenset(
                require_digest(value, "semantic source.revoked_selection_digest")
                for value in current.revoked_selection_digests
            )
            if (
                checked != selected
                or checked.selection_digest != expected
                or expected in revoked
                or parsed.proposal_digest != checked.proposal_digest
                or not isinstance(current.discovery_verifier, HostDiscoveryReceiptVerifier)
                or not isinstance(current.native_verifier, HostNativeSourceVerifier)
            ):
                raise PermissionError("semantic source differs from host selection")
            discovery = current.discovery_verifier.verify(
                parsed,
                proposal_source=proposal_source,
                owner_question=owner_question,
                owner_reply=owner_reply,
            )
            native = current.native_verifier.verify(
                question_capture=owner_question,
                reply_capture=owner_reply,
            )
            if (
                discovery.get("selection_digest") != checked.discovery_selection_digest
                or discovery.get("assertion_class") != "selected-discovery-integrity-only"
                or discovery.get("promotable") is not False
                or native.get("pin_digest") != checked.native_pin_digest
                or native.get("assertion_class") != "host-pinned-native-integrity-only"
                or native.get("promotable") is not False
                or native.get("question_capture_digest") != parsed.owner_question_digest
                or native.get("reply_capture_digest") != parsed.owner_reply_digest
            ):
                raise ValueError("semantic source proofs do not match the host selection")
            body: dict[str, object] = {
                "schema_version": HOST_SEMANTIC_SOURCE_VERIFICATION_SCHEMA_VERSION,
                "assertion_class": "selected-semantic-source-integrity-only",
                "promotable": False,
                "selection_digest": expected,
                "proposal_digest": parsed.proposal_digest,
                "discovery_verification_digest": require_digest(
                    discovery.get("verification_digest"), "semantic source.discovery_proof"
                ),
                "native_source_verification_digest": require_digest(
                    native.get("source_verification_digest"), "semantic source.native_proof"
                ),
            }
            proof = {**body, "source_verification_digest": canonical_digest(body)}
        if proof is None:
            raise PermissionError("semantic source host state suppressed verification failure")
        return proof
