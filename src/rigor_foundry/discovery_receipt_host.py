# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected discovery receipt
"""Recheck one host-selected replay and source receipt without policy promotion."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from pathlib import Path

from .discovery_progress import ProgressLimits, replay_discovery_lineage
from .discovery_source_schema import DiscoveryLimits, capture_name
from .model_primitives import require_digest, require_identifier
from .models import canonical_digest
from .semantic_transition import SemanticTransitionProposal


@dataclass(frozen=True)
class HostDiscoveryReceiptSelection:
    """Exact files, limits, replay state, receipt and proposal chosen by a host."""

    lineage_root: Path
    base_name: str
    transaction_names: tuple[str, ...]
    base_sha256: str
    base_metadata_fields: tuple[str, ...]
    progress_limits: ProgressLimits
    replay_digest: str
    source_root: Path
    manifest_name: str
    source_limits: DiscoveryLimits
    receipt_id: str
    receipt_digest: str
    proposal_digest: str
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        lineage_root: Path,
        base_name: str,
        transaction_names: tuple[str, ...],
        base_sha256: str,
        base_metadata_fields: tuple[str, ...],
        progress_limits: ProgressLimits,
        replay_digest: str,
        source_root: Path,
        manifest_name: str,
        source_limits: DiscoveryLimits,
        receipt_id: str,
        receipt_digest: str,
        proposal_digest: str,
    ) -> HostDiscoveryReceiptSelection:
        """Bind the complete host selection, including both resource budgets."""
        for root in (lineage_root, source_root):
            if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
                raise ValueError("discovery host root must be absolute and untraversed")
        if not isinstance(transaction_names, tuple) or not isinstance(base_metadata_fields, tuple):
            raise ValueError("discovery host names must be tuples")
        transactions = tuple(capture_name(name) for name in transaction_names)
        metadata = tuple(
            require_identifier(name, "base metadata field") for name in base_metadata_fields
        )
        if len(set(transactions)) != len(transactions) or len(set(metadata)) != len(metadata):
            raise ValueError("discovery host names must be unique")
        if not isinstance(progress_limits, ProgressLimits) or not isinstance(
            source_limits, DiscoveryLimits
        ):
            raise ValueError("discovery host limits are required")
        progress = ProgressLimits(**asdict(progress_limits))
        source = DiscoveryLimits(**asdict(source_limits))
        base = capture_name(base_name)
        manifest = capture_name(manifest_name)
        base_digest = require_digest(base_sha256, "discovery host.base_sha256")
        replay = require_digest(replay_digest, "discovery host.replay_digest")
        receipt = require_digest(receipt_digest, "discovery host.receipt_digest")
        proposal = require_digest(proposal_digest, "discovery host.proposal_digest")
        identity = require_identifier(receipt_id, "discovery host.receipt_id")
        body: dict[str, object] = {
            "schema_version": "host-discovery-receipt-selection.v1",
            "lineage_root": str(lineage_root),
            "base_name": base,
            "transaction_names": list(transactions),
            "base_sha256": base_digest,
            "base_metadata_fields": list(metadata),
            "progress_limits": asdict(progress),
            "replay_digest": replay,
            "source_root": str(source_root),
            "manifest_name": manifest,
            "source_limits": asdict(source),
            "receipt_id": identity,
            "receipt_digest": receipt,
            "proposal_digest": proposal,
        }
        return cls(
            lineage_root,
            base,
            transactions,
            base_digest,
            metadata,
            progress,
            replay,
            source_root,
            manifest,
            source,
            identity,
            receipt,
            proposal,
            canonical_digest(body),
        )


@dataclass(frozen=True)
class HostDiscoveryReceiptState:
    """Selection and revocations held stable during the two read-only checks."""

    selected: HostDiscoveryReceiptSelection
    expected_selection_digest: str
    revoked_selection_digests: frozenset[str]


@dataclass(frozen=True)
class HostDiscoveryReceiptVerifier:
    """Require a trusted host lease; a proposal cannot choose files or budgets.

    The provider is test-injectable, but production must compose it from protected
    host state. Filesystem-wide atomicity, source freshness, semantic CLEAR and
    Guard admission are not established here.
    """

    state: Callable[[], AbstractContextManager[HostDiscoveryReceiptState]]

    def verify(
        self,
        proposal: SemanticTransitionProposal,
        *,
        proposal_source: bytes,
        owner_question: bytes,
        owner_reply: bytes,
    ) -> dict[str, object]:
        """Check selected replay, source receipt and exact proposal/owner bytes.

        Native provenance of the owner captures and semantic entailment still
        require distinct host proofs and independent review.
        """
        parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
        proof: dict[str, object] | None = None
        with self.state() as current:
            if not isinstance(current, HostDiscoveryReceiptState):
                raise PermissionError("discovery host state is unavailable")
            selected = current.selected
            checked = HostDiscoveryReceiptSelection.build(
                lineage_root=selected.lineage_root,
                base_name=selected.base_name,
                transaction_names=selected.transaction_names,
                base_sha256=selected.base_sha256,
                base_metadata_fields=selected.base_metadata_fields,
                progress_limits=selected.progress_limits,
                replay_digest=selected.replay_digest,
                source_root=selected.source_root,
                manifest_name=selected.manifest_name,
                source_limits=selected.source_limits,
                receipt_id=selected.receipt_id,
                receipt_digest=selected.receipt_digest,
                proposal_digest=selected.proposal_digest,
            )
            expected = require_digest(
                current.expected_selection_digest, "discovery host selection"
            )
            revoked = frozenset(
                require_digest(value, "revoked discovery host selection")
                for value in current.revoked_selection_digests
            )
            if (
                checked != selected
                or checked.selection_digest != expected
                or expected in revoked
                or parsed.proposal_digest != checked.proposal_digest
                or parsed.parent_replay_digest != checked.replay_digest
                or parsed.source_receipt_id != checked.receipt_id
                or parsed.source_receipt_digest != checked.receipt_digest
            ):
                raise PermissionError("proposal differs from host discovery selection")
            replay = replay_discovery_lineage(
                checked.lineage_root,
                checked.base_name,
                checked.transaction_names,
                base_sha256=checked.base_sha256,
                limits=checked.progress_limits,
                base_metadata_fields=checked.base_metadata_fields,
            )
            if (
                replay.get("state_sha256") != checked.replay_digest
                or replay.get("promotable") is not False
                or not parsed.matches_declared_discovery_source(
                    replay_result=replay,
                    source_root=checked.source_root,
                    manifest_name=checked.manifest_name,
                    limits=checked.source_limits,
                )
                or not parsed.matches_captured_evidence(
                    replay_result=replay,
                    proposal_source=proposal_source,
                    owner_question=owner_question,
                    owner_reply=owner_reply,
                )
            ):
                raise ValueError("host discovery replay or captured evidence differs")
            body: dict[str, object] = {
                "schema_version": "host-discovery-receipt-verification.v2",
                "assertion_class": "selected-discovery-integrity-only",
                "promotable": False,
                "selection_digest": expected,
                "proposal_digest": checked.proposal_digest,
                "replay_digest": checked.replay_digest,
                "receipt_id": checked.receipt_id,
                "receipt_digest": checked.receipt_digest,
                "proposal_source_digest": parsed.proposal_source_digest,
                "owner_question_digest": parsed.owner_question_digest,
                "owner_reply_digest": parsed.owner_reply_digest,
            }
            proof = {**body, "verification_digest": canonical_digest(body)}
        if proof is None:
            raise PermissionError("discovery host state suppressed verification failure")
        return proof
