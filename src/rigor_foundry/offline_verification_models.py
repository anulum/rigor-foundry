# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification protocol records
"""Define strict records for ubiquitous offline evidence verification."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Literal, cast

from .campaign_identity import InferenceIdentity, ModelWitness, collapse_model_witnesses
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import AuditReport, ReviewRecord, canonical_digest, require_mapping, require_string
from .review_attestation import ReviewerAttestation
from .standard_pack import StandardPack
from .trust import ED25519_ALGORITHM, ED25519_SIGNATURE_HEX_LENGTH, require_lower_hex

OFFLINE_VERIFICATION_SCHEMA_VERSION = "1.0"
DETACHED_EVIDENCE_SIGNATURE_SCHEMA_VERSION = "1.0"
MODEL_ALIAS_EVIDENCE_SCHEMA_VERSION = "1.0"
REVIEW_EVIDENCE_SCHEMA_VERSION = "1.0"

ArtifactKind = Literal["audit-report", "review", "standard-pack", "model-aliases"]
Availability = Literal["available", "unavailable"]
VerificationStatus = Literal["verified", "invalid", "stale", "unavailable"]

AUDIT_REPORT_SIGNATURE_DOMAIN = "rigor-foundry.audit-report.v1"
MODEL_ALIASES_SIGNATURE_DOMAIN = "rigor-foundry.model-aliases.v1"
EVIDENCE_SIGNATURE_DOMAINS = MappingProxyType(
    {
        "audit-report": AUDIT_REPORT_SIGNATURE_DOMAIN,
        "model-aliases": MODEL_ALIASES_SIGNATURE_DOMAIN,
    }
)

_ARTIFACT_KINDS = frozenset({"audit-report", "review", "standard-pack", "model-aliases"})


def _artifact_kind(value: object, field: str = "evidence.kind") -> ArtifactKind:
    """Return one supported evidence kind."""
    kind = require_string(value, field)
    if kind not in _ARTIFACT_KINDS:
        raise ValueError(f"{field} is unsupported")
    return cast(ArtifactKind, kind)


@dataclass(frozen=True)
class DetachedEvidenceSignature:
    """Time-bounded signature over one exact report or model-alias record."""

    artifact_kind: ArtifactKind
    algorithm: str
    signature_domain: str
    key_id: str
    artifact_digest: str
    signed_at: str
    expires_at: str
    signed_payload_digest: str
    signature_hex: str
    signature_digest: str
    envelope_digest: str

    @staticmethod
    def payload_digest(
        *,
        artifact_kind: ArtifactKind,
        key_id: str,
        artifact_digest: str,
        signed_at: str,
        expires_at: str,
        algorithm: str = ED25519_ALGORITHM,
    ) -> str:
        """Return the canonical payload digest for external Ed25519 signing."""
        return canonical_digest(
            DetachedEvidenceSignature._payload(
                artifact_kind=artifact_kind,
                algorithm=algorithm,
                key_id=key_id,
                artifact_digest=artifact_digest,
                signed_at=signed_at,
                expires_at=expires_at,
            )
        )

    @staticmethod
    def _payload(
        *,
        artifact_kind: ArtifactKind,
        algorithm: str,
        key_id: str,
        artifact_digest: str,
        signed_at: str,
        expires_at: str,
    ) -> dict[str, str]:
        """Validate and return the complete signed payload."""
        kind = _artifact_kind(artifact_kind, "evidence signature.artifact_kind")
        if kind not in EVIDENCE_SIGNATURE_DOMAINS:
            raise ValueError("detached evidence signatures support reports and model aliases")
        if algorithm != ED25519_ALGORITHM:
            raise ValueError("evidence signature.algorithm must be ed25519")
        start = require_utc_timestamp(signed_at, "evidence signature.signed_at")
        end = require_utc_timestamp(expires_at, "evidence signature.expires_at")
        if parse_utc_timestamp(end, "evidence signature.expires_at") <= parse_utc_timestamp(
            start,
            "evidence signature.signed_at",
        ):
            raise ValueError("evidence signature.expires_at must follow signed_at")
        return {
            "schema_version": DETACHED_EVIDENCE_SIGNATURE_SCHEMA_VERSION,
            "artifact_kind": kind,
            "algorithm": algorithm,
            "signature_domain": EVIDENCE_SIGNATURE_DOMAINS[kind],
            "key_id": require_identifier(key_id, "evidence signature.key_id"),
            "artifact_digest": require_digest(
                artifact_digest,
                "evidence signature.artifact_digest",
            ),
            "signed_at": start,
            "expires_at": end,
        }

    @classmethod
    def build(
        cls,
        *,
        artifact_kind: ArtifactKind,
        key_id: str,
        artifact_digest: str,
        signed_at: str,
        expires_at: str,
        signature_hex: str,
        signature_domain: str,
        algorithm: str = ED25519_ALGORITHM,
    ) -> DetachedEvidenceSignature:
        """Build a strict detached evidence-signature envelope."""
        payload = cls._payload(
            artifact_kind=artifact_kind,
            algorithm=algorithm,
            key_id=key_id,
            artifact_digest=artifact_digest,
            signed_at=signed_at,
            expires_at=expires_at,
        )
        if signature_domain != payload["signature_domain"]:
            raise ValueError("evidence signature has the wrong protocol domain")
        signature = require_lower_hex(
            signature_hex,
            "evidence signature.signature_hex",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
        signed_payload_digest = canonical_digest(payload)
        signature_digest = sha256(bytes.fromhex(signature)).hexdigest()
        body: dict[str, object] = {
            **payload,
            "signed_payload_digest": signed_payload_digest,
            "signature_hex": signature,
            "signature_digest": signature_digest,
        }
        return cls(
            artifact_kind=cast(ArtifactKind, payload["artifact_kind"]),
            algorithm=algorithm,
            signature_domain=payload["signature_domain"],
            key_id=payload["key_id"],
            artifact_digest=payload["artifact_digest"],
            signed_at=payload["signed_at"],
            expires_at=payload["expires_at"],
            signed_payload_digest=signed_payload_digest,
            signature_hex=signature,
            signature_digest=signature_digest,
            envelope_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise the complete detached signature envelope."""
        return {
            "schema_version": DETACHED_EVIDENCE_SIGNATURE_SCHEMA_VERSION,
            "artifact_kind": self.artifact_kind,
            "algorithm": self.algorithm,
            "signature_domain": self.signature_domain,
            "key_id": self.key_id,
            "artifact_digest": self.artifact_digest,
            "signed_at": self.signed_at,
            "expires_at": self.expires_at,
            "signed_payload_digest": self.signed_payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
            "envelope_digest": self.envelope_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> DetachedEvidenceSignature:
        """Parse and integrity-check one detached signature envelope."""
        data = require_mapping(value, "evidence signature")
        expected = {
            "schema_version",
            "artifact_kind",
            "algorithm",
            "signature_domain",
            "key_id",
            "artifact_digest",
            "signed_at",
            "expires_at",
            "signed_payload_digest",
            "signature_hex",
            "signature_digest",
            "envelope_digest",
        }
        if set(data) != expected:
            raise ValueError("evidence signature fields do not match the schema")
        if data.get("schema_version") != DETACHED_EVIDENCE_SIGNATURE_SCHEMA_VERSION:
            raise ValueError("unsupported detached evidence-signature schema version")
        signature = cls.build(
            artifact_kind=_artifact_kind(data.get("artifact_kind")),
            algorithm=require_string(data.get("algorithm"), "evidence signature.algorithm"),
            signature_domain=require_string(
                data.get("signature_domain"),
                "evidence signature.signature_domain",
            ),
            key_id=require_identifier(data.get("key_id"), "evidence signature.key_id"),
            artifact_digest=require_digest(
                data.get("artifact_digest"),
                "evidence signature.artifact_digest",
            ),
            signed_at=require_string(data.get("signed_at"), "evidence signature.signed_at"),
            expires_at=require_string(
                data.get("expires_at"),
                "evidence signature.expires_at",
            ),
            signature_hex=require_string(
                data.get("signature_hex"),
                "evidence signature.signature_hex",
            ),
        )
        for field in (
            "signed_payload_digest",
            "signature_digest",
            "envelope_digest",
        ):
            if data.get(field) != getattr(signature, field):
                raise ValueError(f"evidence signature {field} does not match its content")
        return signature


@dataclass(frozen=True)
class ModelAliasEvidence:
    """Content-addressed model identities and their true collapsed witnesses."""

    runs: tuple[tuple[str, InferenceIdentity], ...]
    witnesses: tuple[ModelWitness, ...]
    alias_digest: str

    @classmethod
    def build(
        cls,
        runs: tuple[tuple[str, InferenceIdentity], ...],
    ) -> ModelAliasEvidence:
        """Build the deterministic alias-collapse evidence for named runs."""
        rebuilt = tuple(
            (
                require_identifier(run_id, "model aliases.run_id"),
                InferenceIdentity.from_dict(identity.to_dict()),
            )
            for run_id, identity in runs
        )
        ordered = tuple(sorted(rebuilt, key=lambda item: item[0]))
        witnesses = collapse_model_witnesses(ordered)
        body: dict[str, object] = {
            "schema_version": MODEL_ALIAS_EVIDENCE_SCHEMA_VERSION,
            "runs": [
                {"run_id": run_id, "identity": identity.to_dict()} for run_id, identity in ordered
            ],
            "witnesses": [item.to_dict() for item in witnesses],
        }
        return cls(runs=ordered, witnesses=witnesses, alias_digest=canonical_digest(body))

    def to_dict(self) -> dict[str, object]:
        """Serialise identities and the exact correlation closure."""
        return {
            "schema_version": MODEL_ALIAS_EVIDENCE_SCHEMA_VERSION,
            "runs": [
                {"run_id": run_id, "identity": identity.to_dict()}
                for run_id, identity in self.runs
            ],
            "witnesses": [item.to_dict() for item in self.witnesses],
            "alias_digest": self.alias_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ModelAliasEvidence:
        """Parse and recompute model-family and exact-model alias collapse."""
        data = require_mapping(value, "model aliases")
        if set(data) != {"schema_version", "runs", "witnesses", "alias_digest"}:
            raise ValueError("model-alias evidence fields do not match the schema")
        if data.get("schema_version") != MODEL_ALIAS_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported model-alias evidence schema version")
        raw_runs = data.get("runs")
        raw_witnesses = data.get("witnesses")
        if not isinstance(raw_runs, list) or not isinstance(raw_witnesses, list):
            raise ValueError("model aliases runs and witnesses must be arrays")
        runs: list[tuple[str, InferenceIdentity]] = []
        for index, item in enumerate(raw_runs):
            record = require_mapping(item, f"model aliases.runs[{index}]")
            if set(record) != {"run_id", "identity"}:
                raise ValueError("model alias run fields do not match the schema")
            runs.append(
                (
                    require_identifier(record.get("run_id"), "model aliases.run_id"),
                    InferenceIdentity.from_dict(record.get("identity")),
                )
            )
        evidence = cls.build(tuple(runs))
        if raw_runs != evidence.to_dict()["runs"]:
            raise ValueError("model-alias runs must be sorted and canonical")
        recorded_witnesses = tuple(ModelWitness.from_dict(item) for item in raw_witnesses)
        if recorded_witnesses != evidence.witnesses:
            raise ValueError("model-alias witnesses do not match the collapsed identities")
        if require_digest(data.get("alias_digest"), "model aliases.alias_digest") != (
            evidence.alias_digest
        ):
            raise ValueError("model-alias digest does not match its content")
        return evidence


@dataclass(frozen=True)
class ReviewEvidence:
    """One review record paired with its detached reviewer attestation."""

    review: ReviewRecord
    attestation: ReviewerAttestation
    evidence_digest: str

    @classmethod
    def build(
        cls,
        *,
        review: ReviewRecord,
        attestation: ReviewerAttestation,
    ) -> ReviewEvidence:
        """Build a content-addressed review/attestation pair."""
        rebuilt_review = ReviewRecord.from_dict(review.to_dict())
        rebuilt_attestation = ReviewerAttestation.from_dict(attestation.to_dict())
        fields: dict[str, object] = {
            "schema_version": REVIEW_EVIDENCE_SCHEMA_VERSION,
            "review": rebuilt_review.to_dict(),
            "attestation": rebuilt_attestation.to_dict(),
        }
        return cls(
            review=rebuilt_review,
            attestation=rebuilt_attestation,
            evidence_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete review evidence pair."""
        return {
            "schema_version": REVIEW_EVIDENCE_SCHEMA_VERSION,
            "review": self.review.to_dict(),
            "attestation": self.attestation.to_dict(),
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ReviewEvidence:
        """Parse and integrity-check one review evidence pair."""
        data = require_mapping(value, "review evidence")
        if set(data) != {"schema_version", "review", "attestation", "evidence_digest"}:
            raise ValueError("review evidence fields do not match the schema")
        if data.get("schema_version") != REVIEW_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported review-evidence schema version")
        review = ReviewRecord.from_dict(data.get("review"))
        if data.get("review") != review.to_dict():
            raise ValueError("review evidence review document must be canonical")
        evidence = cls.build(
            review=review,
            attestation=ReviewerAttestation.from_dict(data.get("attestation")),
        )
        if require_digest(data.get("evidence_digest"), "review evidence.evidence_digest") != (
            evidence.evidence_digest
        ):
            raise ValueError("review-evidence digest does not match its content")
        return evidence


EvidenceDocument = AuditReport | ReviewEvidence | StandardPack | ModelAliasEvidence


def _document_kind(document: EvidenceDocument) -> ArtifactKind:
    """Return the protocol kind for one typed evidence document."""
    if isinstance(document, AuditReport):
        return "audit-report"
    if isinstance(document, ReviewEvidence):
        return "review"
    if isinstance(document, StandardPack):
        return "standard-pack"
    return "model-aliases"


def _document_digest(document: EvidenceDocument) -> str:
    """Return one typed document's canonical identity."""
    if isinstance(document, AuditReport):
        return document.report_digest
    if isinstance(document, ReviewEvidence):
        return document.evidence_digest
    if isinstance(document, StandardPack):
        return document.pack_digest
    return document.alias_digest


def _document_dict(document: EvidenceDocument) -> dict[str, object]:
    """Serialise one typed evidence document."""
    return document.to_dict()


@dataclass(frozen=True)
class EvidenceEntry:
    """One available signed document or one explicit unavailable identity."""

    evidence_id: str
    kind: ArtifactKind
    availability: Availability
    document: EvidenceDocument | None
    signature: DetachedEvidenceSignature | None
    expected_digest: str
    reason: str
    entry_digest: str

    @classmethod
    def available(
        cls,
        evidence_id: str,
        document: EvidenceDocument,
        *,
        signature: DetachedEvidenceSignature | None = None,
    ) -> EvidenceEntry:
        """Build an available evidence entry with its exact document identity."""
        kind = _document_kind(document)
        rebuilt = _parse_document(kind, _document_dict(document))
        digest = _document_digest(rebuilt)
        if kind in EVIDENCE_SIGNATURE_DOMAINS:
            if signature is None:
                raise ValueError(f"{kind} evidence requires a detached signature")
            rebuilt_signature = DetachedEvidenceSignature.from_dict(signature.to_dict())
        else:
            if signature is not None:
                raise ValueError(f"{kind} evidence uses its native signature record")
            rebuilt_signature = None
        fields: dict[str, object] = {
            "evidence_id": require_identifier(evidence_id, "evidence.evidence_id"),
            "kind": kind,
            "availability": "available",
            "document": _document_dict(rebuilt),
            "signature": (rebuilt_signature.to_dict() if rebuilt_signature is not None else None),
            "expected_digest": digest,
            "reason": "",
        }
        return cls(
            evidence_id=cast(str, fields["evidence_id"]),
            kind=kind,
            availability="available",
            document=rebuilt,
            signature=rebuilt_signature,
            expected_digest=digest,
            reason="",
            entry_digest=canonical_digest(fields),
        )

    @classmethod
    def unavailable(
        cls,
        evidence_id: str,
        kind: ArtifactKind,
        *,
        expected_digest: str,
        reason: str,
    ) -> EvidenceEntry:
        """Build an explicit unavailable-evidence record without inventing bytes."""
        parsed_reason = require_string(reason, "evidence.reason")
        fields: dict[str, object] = {
            "evidence_id": require_identifier(evidence_id, "evidence.evidence_id"),
            "kind": _artifact_kind(kind),
            "availability": "unavailable",
            "document": None,
            "signature": None,
            "expected_digest": require_digest(expected_digest, "evidence.expected_digest"),
            "reason": parsed_reason,
        }
        return cls(
            evidence_id=cast(str, fields["evidence_id"]),
            kind=cast(ArtifactKind, fields["kind"]),
            availability="unavailable",
            document=None,
            signature=None,
            expected_digest=cast(str, fields["expected_digest"]),
            reason=parsed_reason,
            entry_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one strict available or unavailable evidence entry."""
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "availability": self.availability,
            "document": _document_dict(self.document) if self.document is not None else None,
            "signature": self.signature.to_dict() if self.signature is not None else None,
            "expected_digest": self.expected_digest,
            "reason": self.reason,
            "entry_digest": self.entry_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EvidenceEntry:
        """Parse and integrity-check one evidence entry."""
        data = require_mapping(value, "evidence")
        expected = {
            "evidence_id",
            "kind",
            "availability",
            "document",
            "signature",
            "expected_digest",
            "reason",
            "entry_digest",
        }
        if set(data) != expected:
            raise ValueError("evidence entry fields do not match the schema")
        evidence_id = require_identifier(data.get("evidence_id"), "evidence.evidence_id")
        kind = _artifact_kind(data.get("kind"))
        availability = require_string(data.get("availability"), "evidence.availability")
        if availability == "available":
            document = _parse_document(kind, data.get("document"))
            raw_signature = data.get("signature")
            signature = (
                DetachedEvidenceSignature.from_dict(raw_signature)
                if raw_signature is not None
                else None
            )
            entry = cls.available(evidence_id, document, signature=signature)
        elif availability == "unavailable":
            if data.get("document") is not None or data.get("signature") is not None:
                raise ValueError("unavailable evidence cannot contain document or signature data")
            entry = cls.unavailable(
                evidence_id,
                kind,
                expected_digest=require_digest(
                    data.get("expected_digest"),
                    "evidence.expected_digest",
                ),
                reason=require_string(data.get("reason"), "evidence.reason"),
            )
        else:
            raise ValueError("evidence.availability is unsupported")
        if data.get("expected_digest") != entry.expected_digest:
            raise ValueError("evidence expected digest does not match the document")
        if data.get("entry_digest") != entry.entry_digest:
            raise ValueError("evidence entry digest does not match its content")
        return entry


def _parse_document(kind: ArtifactKind, value: object) -> EvidenceDocument:
    """Parse one document through its production protocol model."""
    if kind == "audit-report":
        return AuditReport.from_dict(value)
    if kind == "review":
        return ReviewEvidence.from_dict(value)
    if kind == "standard-pack":
        return StandardPack.from_dict(value)
    return ModelAliasEvidence.from_dict(value)


@dataclass(frozen=True)
class VerificationBundle:
    """Deterministic set of evidence identities supplied to ``rigor verify``."""

    entries: tuple[EvidenceEntry, ...]
    bundle_digest: str

    @classmethod
    def build(cls, entries: tuple[EvidenceEntry, ...]) -> VerificationBundle:
        """Build a non-empty bundle with unique deterministic evidence IDs."""
        if not entries:
            raise ValueError("verification bundle must contain at least one evidence entry")
        rebuilt = tuple(EvidenceEntry.from_dict(item.to_dict()) for item in entries)
        identifiers = tuple(item.evidence_id for item in rebuilt)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("verification bundle evidence identifiers must be unique")
        ordered = tuple(sorted(rebuilt, key=lambda item: item.evidence_id))
        fields: dict[str, object] = {
            "schema_version": OFFLINE_VERIFICATION_SCHEMA_VERSION,
            "entries": [item.to_dict() for item in ordered],
        }
        return cls(entries=ordered, bundle_digest=canonical_digest(fields))

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete verification input bundle."""
        return {
            "schema_version": OFFLINE_VERIFICATION_SCHEMA_VERSION,
            "entries": [item.to_dict() for item in self.entries],
            "bundle_digest": self.bundle_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationBundle:
        """Parse and integrity-check one verification input bundle."""
        data = require_mapping(value, "verification bundle")
        if set(data) != {"schema_version", "entries", "bundle_digest"}:
            raise ValueError("verification bundle fields do not match the schema")
        if data.get("schema_version") != OFFLINE_VERIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported verification-bundle schema version")
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, list):
            raise ValueError("verification bundle.entries must be an array")
        entries = tuple(EvidenceEntry.from_dict(item) for item in raw_entries)
        if tuple(item.evidence_id for item in entries) != tuple(
            sorted(item.evidence_id for item in entries)
        ):
            raise ValueError("verification bundle entries must be sorted by evidence_id")
        bundle = cls.build(entries)
        if require_digest(data.get("bundle_digest"), "verification bundle.bundle_digest") != (
            bundle.bundle_digest
        ):
            raise ValueError("verification-bundle digest does not match its content")
        return bundle
