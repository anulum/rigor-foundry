# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original policy component readers
"""Resolve original component references with their actual owning parsers and digests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias, cast

from .audit_primitives import require_exact_fields, require_mapping, require_string
from .control_assessment import EvidenceReference
from .effective_profile import AdapterLock
from .policy_model_inputs import (
    checked_policy_budget,
    checked_policy_condition,
    policy_condition_from_dict,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .review_attestation import REVIEW_ATTESTATION_SCHEMA_VERSION, ReviewerAttestation
from .rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2
from .semantic_acceptance_policy import (
    REVIEWER_IDENTITY_POLICY_SCHEMA,
    ReviewerIdentityBinding,
    ReviewerIdentityPolicy,
)
from .standard_pack import ControlDefinition, EvidenceContract, RemediationContract
from .trust import TrustedPublicKey
from .typed_object_reference import TypedObjectRef1
from .verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

PolicyComponent: TypeAlias = (
    ControlDefinition
    | EvidenceContract
    | AuthorityClauseV2
    | FreshnessPolicyV2
    | AdapterLock
    | ReviewerIdentityPolicy
    | EvidenceReference
    | ReviewerAttestation
)
ADAPTER_LOCK_REFERENCE_FORMAT = "1.0"
LEGACY_EVIDENCE_REFERENCE_FORMAT = "1.0"
_EVIDENCE_FIELDS = frozenset(
    {
        "evidence_id",
        "evidence_type",
        "adapter_id",
        "adapter_digest",
        "artifact_digest",
        "artifact_size",
        "classification",
        "reference",
        "observed_at",
        "expires_at",
        "evidence_digest",
    }
)
_ADAPTER_FIELDS = frozenset(
    {
        "adapter_id",
        "version",
        "executable_digest",
        "config_digest",
        "command_digest",
        "environment_digest",
        "domains",
        "adapter_digest",
    }
)
SUPPORTED_POLICY_COMPONENT_FORMATS = frozenset(
    {
        ("control-definition", "1.0"),
        ("authority-clause", "2.0"),
        ("freshness-policy", "2.0"),
    }
)

SUPPORTED_ORIGINAL_COMPONENT_FORMATS = SUPPORTED_POLICY_COMPONENT_FORMATS | frozenset(
    {
        ("evidence-contract", "1.0"),
        ("evidence-reference", LEGACY_EVIDENCE_REFERENCE_FORMAT),
        ("review-attestation", REVIEW_ATTESTATION_SCHEMA_VERSION),
        ("adapter-lock", ADAPTER_LOCK_REFERENCE_FORMAT),
        ("reviewer-identity-policy", REVIEWER_IDENTITY_POLICY_SCHEMA),
    }
)


def _sequences(
    values: tuple[object, ...], budget: PolicyReadBudget1, *, wire: bool = False
) -> None:
    """Bound original immutable child sequences before their existing serializers run."""
    count = 0
    for value in values:
        if type(value) is not (list if wire else tuple):
            raise ValueError("original policy component requires closed child sequences")
        sequence = cast(list[object] | tuple[object, ...], value)
        count += len(sequence)
        if count > budget.max_references:
            raise ValueError("original policy component exceeds the reference budget")


def _parse(kind: object, value: object, budget: PolicyReadBudget1) -> PolicyComponent:
    """Use only fixed original parsers; no file value can appoint another reader."""
    if type(kind) is not str or kind not in {
        "control-definition",
        "evidence-contract",
        "evidence-reference",
        "review-attestation",
        "authority-clause",
        "freshness-policy",
        "adapter-lock",
        "reviewer-identity-policy",
    }:
        raise ValueError("unsupported policy component kind")
    policy_wire_size(value, budget=budget)
    data = require_mapping(value, "original policy component")
    if kind == "control-definition":
        evidence = require_mapping(data.get("evidence"), "original evidence contract")
        remediation = require_mapping(data.get("remediation"), "original remediation contract")
        _sequences(
            (
                evidence.get("required_adapters"),
                evidence.get("evidence_types"),
                remediation.get("dependencies"),
                remediation.get("procedure_ids"),
                remediation.get("acceptance_gates"),
                remediation.get("reopen_triggers"),
            ),
            budget,
            wire=True,
        )
        if data.get("condition") is not None:
            policy_condition_from_dict(data["condition"], budget=budget)
        parsed: PolicyComponent = ControlDefinition.from_dict(value)
    elif kind == "evidence-contract":
        _sequences((data.get("required_adapters"), data.get("evidence_types")), budget, wire=True)
        parsed = EvidenceContract.from_dict(value)
    elif kind == "authority-clause":
        _sequences((data.get("grantor_classes"),), budget, wire=True)
        parsed = AuthorityClauseV2.from_dict(value)
    elif kind == "freshness-policy":
        _sequences((data.get("invalidator_ids"),), budget, wire=True)
        parsed = FreshnessPolicyV2.from_dict(value)
    elif kind == "adapter-lock":
        require_exact_fields(data, _ADAPTER_FIELDS, "original adapter custody")
        _sequences((data.get("domains"),), budget, wire=True)
        parsed = AdapterLock.from_dict(value)
    elif kind == "evidence-reference":
        require_exact_fields(data, _EVIDENCE_FIELDS, "original evidence reference")
        parsed = EvidenceReference.from_dict(value)
    elif kind == "review-attestation":
        parsed = ReviewerAttestation.from_dict(value)
    else:
        trust = require_mapping(data.get("trust_policy"), "reviewer public trust policy")
        _sequences((data.get("bindings"), trust.get("keys")), budget, wire=True)
        parsed = ReviewerIdentityPolicy.from_dict(value)
    if parsed.to_dict() != value:
        raise ValueError("original policy component wire must remain unchanged")
    return parsed


@dataclass(frozen=True)
class PolicyComponent1:
    """An original component reader, with no replacement wire or new authority.

    Original control, numeric evidence, authority, freshness, adapter custody,
    evidence reference and review records keep their actual schemas and digests.
    Adapter custody has no inserted schema header; its explicit reference format
    identifies the unchanged original parser. Identity policies have no original
    ID field, so their exact original digest is their content-addressed identity.
    Original attestations likewise use their complete attestation digest, keeping
    the separate reviewer identity unchanged. Parsing approves no signatures,
    evidence results, semantic extraction, policy selection or effects.
    """

    record: PolicyComponent
    budget: PolicyReadBudget1 = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        """Refuse invalid direct objects before deriving any source reference."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Return the complete revalidated original record without adding object_kind."""
        limits = checked_policy_budget(self.budget)
        record = self.record
        if type(record) is ControlDefinition:
            if (
                type(record.evidence) is not EvidenceContract
                or type(record.remediation) is not RemediationContract
            ):
                raise ValueError("original control requires its actual evidence and remediation")
            if record.condition is not None:
                checked_policy_condition(record.condition, budget=limits)
            _sequences(
                (
                    record.evidence.required_adapters,
                    record.evidence.evidence_types,
                    record.remediation.dependencies,
                    record.remediation.procedure_ids,
                    record.remediation.acceptance_gates,
                    record.remediation.reopen_triggers,
                ),
                limits,
            )
            kind = "control-definition"
        elif type(record) is EvidenceContract:
            _sequences((record.required_adapters, record.evidence_types), limits)
            kind = "evidence-contract"
        elif type(record) is AuthorityClauseV2:
            _sequences((record.grantor_classes,), limits)
            kind = "authority-clause"
        elif type(record) is FreshnessPolicyV2:
            _sequences((record.invalidator_ids,), limits)
            kind = "freshness-policy"
        elif type(record) is AdapterLock:
            _sequences((record.domains,), limits)
            kind = "adapter-lock"
        elif type(record) is EvidenceReference:
            kind = "evidence-reference"
        elif type(record) is ReviewerAttestation:
            kind = "review-attestation"
        elif type(record) is ReviewerIdentityPolicy:
            if type(record.trust_policy) is not OfflineTrustPolicy:
                raise ValueError(
                    "reviewer identity requires the actual original public trust policy"
                )
            _sequences((record.bindings, record.trust_policy.keys), limits)
            if any(type(binding) is not ReviewerIdentityBinding for binding in record.bindings):
                raise ValueError("reviewer identity requires actual original key bindings")
            for key in record.trust_policy.keys:
                if type(key) is not VerificationKeyPolicy or type(key.key) is not TrustedPublicKey:
                    raise ValueError(
                        "reviewer identity requires actual original public key policies"
                    )
            kind = "reviewer-identity-policy"
        else:
            raise ValueError("actual supported original policy component is required")
        return dict(_parse(kind, record.to_dict(), limits).to_dict())

    @classmethod
    def from_dict(cls, kind: str, value: object, *, budget: PolicyReadBudget1) -> PolicyComponent1:
        """Parse a named original kind through the fixed original owner only."""
        limits = checked_policy_budget(budget)
        return cls(_parse(kind, value, limits), limits)

    def reference(self) -> TypedObjectRef1:
        """Bind the original identity and actual digest, preserving legacy control_digest."""
        data = self.to_dict()
        if type(self.record) is ControlDefinition:
            kind, identity, digest = (
                "control-definition",
                self.record.versioned_id,
                self.record.control_digest,
            )
        elif type(self.record) is EvidenceContract:
            kind, identity, digest = (
                "evidence-contract",
                self.record.contract_id,
                self.record.contract_digest,
            )
        elif type(self.record) is AuthorityClauseV2:
            kind, identity, digest = (
                "authority-clause",
                self.record.clause_id,
                self.record.clause_digest,
            )
        elif type(self.record) is FreshnessPolicyV2:
            freshness = self.record
            kind, identity, digest = (
                "freshness-policy",
                freshness.policy_id,
                freshness.policy_digest,
            )
        elif type(self.record) is AdapterLock:
            return TypedObjectRef1.build(
                kind="adapter-lock",
                format_version=ADAPTER_LOCK_REFERENCE_FORMAT,
                object_id=self.record.adapter_id,
                object_digest=self.record.adapter_digest,
            )
        elif type(self.record) is EvidenceReference:
            return TypedObjectRef1.build(
                kind="evidence-reference",
                format_version=LEGACY_EVIDENCE_REFERENCE_FORMAT,
                object_id=self.record.evidence_id,
                object_digest=self.record.evidence_digest,
            )
        elif type(self.record) is ReviewerAttestation:
            kind, identity, digest = (
                "review-attestation",
                self.record.attestation_digest,
                self.record.attestation_digest,
            )
        else:
            policy = cast(ReviewerIdentityPolicy, self.record)
            kind, identity, digest = (
                "reviewer-identity-policy",
                policy.policy_digest,
                policy.policy_digest,
            )
        return TypedObjectRef1.build(
            kind=kind,
            format_version=require_string(data["schema_version"], "original component format"),
            object_id=identity,
            object_digest=digest,
        )


def resolve_policy_component(
    reference: TypedObjectRef1,
    records: tuple[PolicyComponent1, ...],
    *,
    budget: PolicyReadBudget1,
) -> PolicyComponent1:
    """Resolve one exact reference from a bounded cohort using all original owners.

    Parameters
    ----------
    reference : TypedObjectRef1
        Original supported kind, format, identity and owning digest. It contains
        no reader appointment, file locator or executable callback.
    records : tuple[PolicyComponent1, ...]
        Complete supplied immutable component cohort. Duplicate identities and
        malformed unselected components refuse before returning any target.
    budget : PolicyReadBudget1
        Explicit count and aggregate encoded byte ceilings for this cohort.

    Returns
    -------
    PolicyComponent1
        The actual matched original component, revalidated under this budget.
        Equal-length hashes or caller-provided result strings never resolve it.

    Raises
    ------
    ValueError
        The kind, target, complete cohort, exact bytes or parser limits differ.
    """
    limits = checked_policy_budget(budget)
    if type(reference) is not TypedObjectRef1:
        raise ValueError("an actual typed policy component reference is required")
    checked = TypedObjectRef1.from_dict(reference.to_dict())
    if (checked.kind, checked.format_version) not in SUPPORTED_ORIGINAL_COMPONENT_FORMATS:
        raise ValueError("unsupported original policy component reference")
    if type(records) is not tuple or len(records) > limits.max_references:
        raise ValueError("policy component cohort exceeds its immutable reference budget")
    identities: set[tuple[str, str, str]] = set()
    matched: PolicyComponent1 | None = None
    size = 2
    for index, record in enumerate(records):
        if type(record) is not PolicyComponent1:
            raise ValueError("policy component cohort requires actual original readers")
        candidate = PolicyComponent1(record.record, limits)
        data = candidate.to_dict()
        size += policy_wire_size(data, budget=limits) + (1 if index else 0)
        if size > limits.max_document_bytes:
            raise ValueError("policy component cohort exceeds the aggregate byte budget")
        target = candidate.reference()
        identity = (target.kind, target.format_version, target.object_id)
        if identity in identities:
            raise ValueError("policy component cohort has a duplicate identity")
        identities.add(identity)
        if identity == (checked.kind, checked.format_version, checked.object_id):
            if target != checked:
                raise ValueError(
                    "policy component reference differs from the original owning digest"
                )
            matched = candidate
    if matched is None:
        raise ValueError("policy component target is unresolved")
    return matched
