# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected original source cohort
"""Join retained original metadata and payloads through their actual source owners."""

from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from .audit_primitives import canonical_digest
from .context_source_lease import RetainedContextSource
from .control_assessment import Classification
from .discovery_source_receipt import DiscoverySourceReceipt1
from .discovery_source_schema import DiscoveryLimits, capture_name, exact_object, parse_json
from .discovery_source_validation import validate_discovery_sources
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at
from .model_primitives import require_identifier
from .native_source_host import HostNativeSourceVerifier
from .native_source_pin import NativeSourcePin
from .policy_read_budget import PolicyReadBudget1
from .policy_source_records import PolicySourceRecord1
from .retained_policy_source import RetainedPolicySource
from .source_capture import SourceCapture
from .source_universe import SourceDisposition, SourceReadState


@dataclass(frozen=True)
class DiscoverySourceSelection:
    """Actual discovery root/manifest/budgets selected by an already-authorized host.

    No request-wire parser installs this selection. Its root grants no new
    access; the host must already own the complete original snapshot's domain.
    """

    root: Path
    manifest_name: str
    limits: DiscoveryLimits

    def __post_init__(self) -> None:
        """Require explicit absolute original roots and actual bounded limit models."""
        if (
            not isinstance(self.root, Path)
            or not self.root.is_absolute()
            or ".." in self.root.parts
        ):
            raise ValueError("discovery source selection requires an absolute untraversed root")
        capture_name(self.manifest_name)
        if type(self.limits) is not DiscoveryLimits:
            raise ValueError("actual discovery limits are required")
        DiscoveryLimits(**asdict(self.limits))

    def verify(
        self,
        *,
        source_id: str,
        source: RetainedPolicySource,
        receipt: DiscoverySourceReceipt1,
        budget: PolicyReadBudget1,
    ) -> str:
        """Re-run the original validator and bind an exact retained source to its manifest.

        Parameters
        ----------
        source_id : str
            Exact original source identity selected by host composition.
        source : RetainedPolicySource
            Actual held raw bytes, selected independently of opaque locators.
        receipt : DiscoverySourceReceipt1
            Original closed metadata receipt to compare with fresh validator output.
        budget : PolicyReadBudget1
            Explicit processing limits, without rewriting the original receipt.

        Returns
        -------
        str
            Original fresh receipt digest after actual complete snapshot verification.

        Raises
        ------
        ValueError, OSError, StableReadError
            If original bytes, limits, source selection or original receipt differs.

        Notes
        -----
        The universe owner must check all declared read states before calling;
        a protected member holds this complete discovery cohort unread.
        """
        self.__post_init__()
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        bound = PolicyReadBudget1.from_dict(budget.to_dict())
        if (
            type(source) is not RetainedPolicySource
            or type(receipt) is not DiscoverySourceReceipt1
        ):
            raise ValueError("actual original discovery source and receipt are required")
        if (
            self.limits.total_bytes > bound.max_total_source_bytes
            or self.limits.file_bytes > bound.max_source_bytes
            or self.limits.sources > bound.max_sources
            or self.limits.shards + self.limits.candidates + self.limits.spans
            > bound.max_references
        ):
            raise ValueError("original discovery processing limits exceed the policy budget")
        original = receipt.to_dict()
        directory = open_directory_no_follow(self.root)
        try:
            read = read_stable_regular_file_at(
                directory,
                self.manifest_name,
                self.manifest_name,
                buffer_limit=bound.max_document_bytes,
                maximum_bytes=bound.max_document_bytes,
                require_single_link=True,
            )
        finally:
            os.close(directory)
        raw = cast(bytes, read.payload)
        if hashlib.sha256(raw).hexdigest() != receipt.manifest_sha256:
            raise ValueError(
                "actual discovery manifest differs from the selected original receipt"
            )
        manifest = exact_object(
            parse_json(raw), "schema_version status sources shards candidate_count"
        )
        rows = cast(list[dict[str, object]], manifest["sources"])
        row = next((row for row in rows if row["source_id"] == source_id), None)
        if row is None:
            raise ValueError("selected source is absent from the original discovery manifest")
        payload = source.read()
        if (
            source.path != self.root / cast(str, row["capture"])
            or len(payload) != row["bytes"]
            or hashlib.sha256(payload).hexdigest() != row["sha256"]
        ):
            raise ValueError("retained bytes differ from their original discovery source binding")
        if (
            validate_discovery_sources(self.root, self.manifest_name, limits=self.limits)
            != original
        ):
            raise ValueError("actual discovery snapshot changed during source binding")
        return receipt.receipt_digest


@dataclass(frozen=True)
class PolicySourceRead:
    """One actual selected source read; it confers no semantic acceptance or effects."""

    record: PolicySourceRecord1
    payload: bytes | None
    verification_digest: str
    snapshot_id: str


@dataclass(frozen=True)
class PolicySourceSelection:
    """Immutable host composition for a complete universe row and actual source owners.

    The metadata and optional payload lifetimes belong to the host. A held row
    has no raw/native/discovery reader and never opens bytes merely to fill it.
    """

    source_id: str
    metadata: RetainedContextSource
    classification: Classification
    locator: str
    read_state: SourceReadState
    disposition: SourceDisposition
    disposition_decision: str | None
    payload: RetainedPolicySource | None
    native_verifier: HostNativeSourceVerifier | None
    question_capture: bytes | None
    reply_capture: bytes | None
    discovery: DiscoverySourceSelection | None

    def __post_init__(self) -> None:
        """Require actual retained sources and explicit verified/held source composition."""
        require_identifier(self.source_id, "selected source identity")
        if type(self.metadata) is not RetainedContextSource:
            raise ValueError("actual retained original source metadata is required")
        if self.read_state not in {"verified", "unread", "unavailable", "protected"}:
            raise ValueError("unsupported selected source read state")
        if self.read_state == "verified":
            if type(self.payload) is not RetainedPolicySource:
                raise ValueError("verified source requires actual retained original bytes")
        elif any(
            item is not None
            for item in (
                self.payload,
                self.native_verifier,
                self.question_capture,
                self.reply_capture,
                self.discovery,
            )
        ):
            raise ValueError("held source must not install raw, native or discovery readers")

    def read(self, *, budget: PolicyReadBudget1) -> PolicySourceRead:
        """Revalidate original metadata and, when selected, its actual byte/native owner.

        Parameters
        ----------
        budget : PolicyReadBudget1
            Explicit source processing limits.

        Returns
        -------
        PolicySourceRead
            Same original record, optional actual bytes and independent observation identity.

        Raises
        ------
        ValueError, OSError, StableReadError, PermissionError
            If retained sources, original owner, host pin or declared selection differs.

        Notes
        -----
        Caller-held metadata never supplies native issuer or source access authority.
        Discovery verification reads the entire original selected snapshot; the
        universe owner first refuses any mixed held/verified discovery cohort.
        """
        self.__post_init__()
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        bound = PolicyReadBudget1.from_dict(budget.to_dict())
        record = self.metadata.read()
        if type(record) is not PolicySourceRecord1:
            raise ValueError("selected metadata is not an original policy source record")
        original = record.record
        if isinstance(original, NativeSourcePin) and self.source_id != original.source_id:
            raise ValueError("selected native source identity differs from its original pin")
        if isinstance(original, DiscoverySourceReceipt1) and self.source_id not in dict(
            original.sources
        ):
            raise ValueError(
                "selected discovery source identity is absent from its original receipt"
            )
        payload = None if self.payload is None else self.payload.read()
        verification = record.reference()["object_digest"]
        if payload is not None:
            if len(payload) > bound.max_source_bytes:
                raise ValueError("selected raw source exceeds the processing byte budget")
            if isinstance(original, SourceCapture):
                if any(
                    item is not None
                    for item in (
                        self.native_verifier,
                        self.question_capture,
                        self.reply_capture,
                        self.discovery,
                    )
                ):
                    raise ValueError("capture source cannot borrow a native or discovery owner")
                if (len(payload), hashlib.sha256(payload).hexdigest()) != (
                    original.payload_size,
                    original.payload_digest,
                ):
                    raise ValueError("retained payload differs from its original HTTPS capture")
            elif isinstance(original, NativeSourcePin):
                if (
                    type(self.native_verifier) is not HostNativeSourceVerifier
                    or type(self.question_capture) is not bytes
                    or type(self.reply_capture) is not bytes
                    or self.discovery is not None
                ):
                    raise ValueError(
                        "native source requires its actual host verifier and captures"
                    )
                proof = self.native_verifier.verify(
                    question_capture=self.question_capture, reply_capture=self.reply_capture
                )
                if (
                    proof["pin_digest"] != original.pin_digest
                    or proof["file_digest"] != hashlib.sha256(payload).hexdigest()
                    or cast(RetainedPolicySource, self.payload).path
                    != original.root / original.filename
                ):
                    raise ValueError(
                        "native host source differs from the selected original payload"
                    )
                verification = proof["source_verification_digest"]
            else:
                if type(self.discovery) is not DiscoverySourceSelection or any(
                    item is not None
                    for item in (self.native_verifier, self.question_capture, self.reply_capture)
                ):
                    raise ValueError(
                        "discovery source requires its actual original snapshot owner"
                    )
                verification = self.discovery.verify(
                    source_id=self.source_id,
                    source=cast(RetainedPolicySource, self.payload),
                    receipt=original,
                    budget=bound,
                )
        self.metadata.read()
        snapshot = canonical_digest(
            {
                "metadata": self.metadata.snapshot_id,
                "payload": None if self.payload is None else self.payload.snapshot_id,
                "source_id": self.source_id,
            }
        )
        return PolicySourceRead(record, payload, cast(str, verification), snapshot)
