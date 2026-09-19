# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed rule-chain pack candidate
"""Bind v2 authority and qualitative evidence clauses to one signed pack."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, cast

from .audit_primitives import require_exact_fields
from .git_inventory import StableReadError
from .model_primitives import (
    require_digest,
    require_identifier,
    require_semantic_version,
    require_unique_strings,
    validate_unique_strings,
)
from .models import canonical_digest, require_mapping, require_string
from .pack_source_host import HostPackSourceVerifier
from .semantic_transition import SemanticTransitionProposal
from .signed_rule_chain_v2 import (
    RULE_CHAIN_V2_SCHEMA_VERSION,
    RuleChainV2Signature,
    RuleChainV2TrustRoles,
)
from .standard_pack import ControlDefinition

_CLAUSE_FIELDS: Final = frozenset(
    {
        "schema_version",
        "clause_id",
        "successor_id",
        "statement_digest",
        "source_receipt_digest",
        "transition_digest",
        "issuer_class",
        "grantor_classes",
        "scope_digest",
        "scope_selector_digest",
        "effect_class",
        "adapter_id",
        "clause_digest",
    }
)
_FRESHNESS_FIELDS: Final = frozenset(
    {
        "schema_version",
        "policy_id",
        "claim_type",
        "subject_class",
        "mode",
        "risk_class",
        "invalidator_ids",
        "proof_adapter_id",
        "policy_digest",
    }
)
_PACK_FIELDS: Final = frozenset(
    {
        "schema_version",
        "object_kind",
        "pack_id",
        "version",
        "source_uri",
        "source_digest",
        "transition_digest",
        "licence",
        "controls",
        "authority_clauses",
        "freshness_policies",
        "signature",
        "pack_digest",
    }
)
FreshnessMode = Literal["immutable-object", "mutable-state"]


@dataclass(frozen=True)
class AuthorityClauseV2:
    """Source-bound normative statement, not a standing execution grant."""

    clause_id: str
    successor_id: str
    statement_digest: str
    source_receipt_digest: str
    transition_digest: str
    issuer_class: str
    grantor_classes: tuple[str, ...]
    scope_digest: str
    scope_selector_digest: str
    effect_class: str
    adapter_id: str
    clause_digest: str

    @classmethod
    def build(
        cls,
        *,
        clause_id: str,
        successor_id: str,
        statement_digest: str,
        source_receipt_digest: str,
        transition_digest: str,
        issuer_class: str,
        grantor_classes: tuple[str, ...],
        scope_digest: str,
        scope_selector_digest: str,
        effect_class: str,
        adapter_id: str,
    ) -> AuthorityClauseV2:
        """Bind one clause to exact text, source, transition and effect class."""
        grantors = tuple(
            require_identifier(item, "clause.grantor_class")
            for item in validate_unique_strings(
                grantor_classes, "clause.grantor_classes", minimum=1
            )
        )
        fields: dict[str, object] = {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "clause_id": require_identifier(clause_id, "clause.clause_id"),
            "successor_id": require_identifier(successor_id, "clause.successor_id"),
            "statement_digest": require_digest(statement_digest, "clause.statement_digest"),
            "source_receipt_digest": require_digest(
                source_receipt_digest, "clause.source_receipt_digest"
            ),
            "transition_digest": require_digest(transition_digest, "clause.transition_digest"),
            "issuer_class": require_identifier(issuer_class, "clause.issuer_class"),
            "grantor_classes": list(grantors),
            "scope_digest": require_digest(scope_digest, "clause.scope_digest"),
            "scope_selector_digest": require_digest(
                scope_selector_digest, "clause.scope_selector_digest"
            ),
            "effect_class": require_identifier(effect_class, "clause.effect_class"),
            "adapter_id": require_identifier(adapter_id, "clause.adapter_id"),
        }
        return cls(
            clause_id=cast(str, fields["clause_id"]),
            successor_id=cast(str, fields["successor_id"]),
            statement_digest=cast(str, fields["statement_digest"]),
            source_receipt_digest=cast(str, fields["source_receipt_digest"]),
            transition_digest=cast(str, fields["transition_digest"]),
            issuer_class=cast(str, fields["issuer_class"]),
            grantor_classes=grantors,
            scope_digest=cast(str, fields["scope_digest"]),
            scope_selector_digest=cast(str, fields["scope_selector_digest"]),
            effect_class=cast(str, fields["effect_class"]),
            adapter_id=cast(str, fields["adapter_id"]),
            clause_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one integrity-bound authority clause."""
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "clause_id": self.clause_id,
            "successor_id": self.successor_id,
            "statement_digest": self.statement_digest,
            "source_receipt_digest": self.source_receipt_digest,
            "transition_digest": self.transition_digest,
            "issuer_class": self.issuer_class,
            "grantor_classes": list(self.grantor_classes),
            "scope_digest": self.scope_digest,
            "scope_selector_digest": self.scope_selector_digest,
            "effect_class": self.effect_class,
            "adapter_id": self.adapter_id,
            "clause_digest": self.clause_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AuthorityClauseV2:
        """Refuse any missing, unknown or digest-recomputed clause field."""
        data = require_mapping(value, "authority clause")
        require_exact_fields(data, _CLAUSE_FIELDS, "authority clause v2")
        if data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION:
            raise ValueError("unsupported authority-clause schema version")
        clause = cls.build(
            clause_id=require_identifier(data.get("clause_id"), "clause.clause_id"),
            successor_id=require_identifier(data.get("successor_id"), "clause.successor_id"),
            statement_digest=require_digest(
                data.get("statement_digest"), "clause.statement_digest"
            ),
            source_receipt_digest=require_digest(
                data.get("source_receipt_digest"), "clause.source_receipt_digest"
            ),
            transition_digest=require_digest(
                data.get("transition_digest"), "clause.transition_digest"
            ),
            issuer_class=require_identifier(data.get("issuer_class"), "clause.issuer_class"),
            grantor_classes=require_unique_strings(
                data.get("grantor_classes"), "clause.grantor_classes", minimum=1
            ),
            scope_digest=require_digest(data.get("scope_digest"), "clause.scope_digest"),
            scope_selector_digest=require_digest(
                data.get("scope_selector_digest"), "clause.scope_selector_digest"
            ),
            effect_class=require_identifier(data.get("effect_class"), "clause.effect_class"),
            adapter_id=require_identifier(data.get("adapter_id"), "clause.adapter_id"),
        )
        if data.get("clause_digest") != clause.clause_digest:
            raise ValueError("authority clause digest does not match its fields")
        return clause

    def matches_proposal_source(self, proposal: SemanticTransitionProposal) -> bool:
        """Match the exact successor, statement and receipt without admitting it.

        A true result proves a structural relation to an unreviewed proposal.
        Independent signed CLEAR and host-selected admission remain separate.
        """
        try:
            clause = AuthorityClauseV2.from_dict(self.to_dict())
            parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
        except (TypeError, ValueError):
            return False
        return (
            clause == self
            and clause.source_receipt_digest == parsed.source_receipt_digest
            and any(
                item.successor_id == clause.successor_id
                and item.statement_digest == clause.statement_digest
                for item in parsed.replacements
            )
        )


@dataclass(frozen=True)
class FreshnessPolicyV2:
    """Qualitative claim freshness with explicit invalidation and proof owners."""

    policy_id: str
    claim_type: str
    subject_class: str
    mode: FreshnessMode
    risk_class: str
    invalidator_ids: tuple[str, ...]
    proof_adapter_id: str
    policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        policy_id: str,
        claim_type: str,
        subject_class: str,
        mode: FreshnessMode,
        risk_class: str,
        invalidator_ids: tuple[str, ...],
        proof_adapter_id: str,
    ) -> FreshnessPolicyV2:
        """Require a typed proof and invalidator set without numeric TTL."""
        if mode not in {"immutable-object", "mutable-state"}:
            raise ValueError("freshness.mode is unsupported")
        invalidators = validate_unique_strings(
            invalidator_ids, "freshness.invalidator_ids", minimum=1
        )
        fields: dict[str, object] = {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "policy_id": require_identifier(policy_id, "freshness.policy_id"),
            "claim_type": require_identifier(claim_type, "freshness.claim_type"),
            "subject_class": require_identifier(subject_class, "freshness.subject_class"),
            "mode": mode,
            "risk_class": require_identifier(risk_class, "freshness.risk_class"),
            "invalidator_ids": [
                require_identifier(item, "freshness.invalidator_id") for item in invalidators
            ],
            "proof_adapter_id": require_identifier(proof_adapter_id, "freshness.proof_adapter_id"),
        }
        return cls(
            policy_id=cast(str, fields["policy_id"]),
            claim_type=cast(str, fields["claim_type"]),
            subject_class=cast(str, fields["subject_class"]),
            mode=mode,
            risk_class=cast(str, fields["risk_class"]),
            invalidator_ids=tuple(cast(list[str], fields["invalidator_ids"])),
            proof_adapter_id=cast(str, fields["proof_adapter_id"]),
            policy_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise an exact qualitative policy without expiry seconds."""
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "claim_type": self.claim_type,
            "subject_class": self.subject_class,
            "mode": self.mode,
            "risk_class": self.risk_class,
            "invalidator_ids": list(self.invalidator_ids),
            "proof_adapter_id": self.proof_adapter_id,
            "policy_digest": self.policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> FreshnessPolicyV2:
        """Refuse extra duration fields and altered typed invalidator data."""
        data = require_mapping(value, "freshness policy")
        require_exact_fields(data, _FRESHNESS_FIELDS, "freshness policy v2")
        if data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION:
            raise ValueError("unsupported freshness-policy schema version")
        raw_invalidators = data.get("invalidator_ids")
        if not isinstance(raw_invalidators, list):
            raise ValueError("freshness.invalidator_ids must be an array")
        policy = cls.build(
            policy_id=require_identifier(data.get("policy_id"), "freshness.policy_id"),
            claim_type=require_identifier(data.get("claim_type"), "freshness.claim_type"),
            subject_class=require_identifier(data.get("subject_class"), "freshness.subject_class"),
            mode=cast(FreshnessMode, require_string(data.get("mode"), "freshness.mode")),
            risk_class=require_identifier(data.get("risk_class"), "freshness.risk_class"),
            invalidator_ids=tuple(
                require_identifier(item, "freshness.invalidator_id")
                for item in cast(list[object], raw_invalidators)
            ),
            proof_adapter_id=require_identifier(
                data.get("proof_adapter_id"), "freshness.proof_adapter_id"
            ),
        )
        if data.get("policy_digest") != policy.policy_digest:
            raise ValueError("freshness policy digest does not match its fields")
        return policy


@dataclass(frozen=True)
class StandardPackV2:
    """Signed pack body retaining audit controls and separate authority clauses."""

    pack_id: str
    version: str
    source_uri: str
    source_digest: str
    transition_digest: str
    licence: str
    controls: tuple[ControlDefinition, ...]
    authority_clauses: tuple[AuthorityClauseV2, ...]
    freshness_policies: tuple[FreshnessPolicyV2, ...]
    signature: RuleChainV2Signature
    pack_digest: str

    @staticmethod
    def body(
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        transition_digest: str,
        licence: str,
        controls: tuple[ControlDefinition, ...],
        authority_clauses: tuple[AuthorityClauseV2, ...],
        freshness_policies: tuple[FreshnessPolicyV2, ...],
    ) -> dict[str, object]:
        """Derive the exact versioned content to be signed, without a grant."""
        identity = require_identifier(pack_id, "pack.pack_id")
        uri = require_string(source_uri, "pack.source_uri")
        if any(character.isspace() for character in uri):
            raise ValueError("pack.source_uri must not contain whitespace")
        if not authority_clauses or not freshness_policies:
            raise ValueError("v2 pack needs authority and freshness clauses")
        parsed_controls = tuple(ControlDefinition.from_dict(item.to_dict()) for item in controls)
        parsed_clauses = tuple(
            AuthorityClauseV2.from_dict(item.to_dict()) for item in authority_clauses
        )
        parsed_freshness = tuple(
            FreshnessPolicyV2.from_dict(item.to_dict()) for item in freshness_policies
        )
        ids = (
            tuple(item.control_id for item in parsed_controls)
            + tuple(item.clause_id for item in parsed_clauses)
            + tuple(item.policy_id for item in parsed_freshness)
        )
        if len(ids) != len(set(ids)):
            raise ValueError("pack control, clause and freshness identifiers must be distinct")
        if any(not item.startswith(f"{identity}/") for item in ids):
            raise ValueError("v2 pack component identifiers must use its namespace")
        transition = require_digest(transition_digest, "pack.transition_digest")
        if any(item.transition_digest != transition for item in parsed_clauses):
            raise ValueError("authority clause refers to another semantic transition")
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "object_kind": "standard-pack",
            "pack_id": identity,
            "version": require_semantic_version(version, "pack.version"),
            "source_uri": uri,
            "source_digest": require_digest(source_digest, "pack.source_digest"),
            "transition_digest": transition,
            "licence": require_string(licence, "pack.licence"),
            "controls": [item.to_dict() for item in parsed_controls],
            "authority_clauses": [item.to_dict() for item in parsed_clauses],
            "freshness_policies": [item.to_dict() for item in parsed_freshness],
        }

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        transition_digest: str,
        licence: str,
        controls: tuple[ControlDefinition, ...],
        authority_clauses: tuple[AuthorityClauseV2, ...],
        freshness_policies: tuple[FreshnessPolicyV2, ...],
        signature: RuleChainV2Signature,
    ) -> StandardPackV2:
        """Require exact v2 signature metadata over the complete pack body."""
        body = cls.body(
            pack_id=pack_id,
            version=version,
            source_uri=source_uri,
            source_digest=source_digest,
            transition_digest=transition_digest,
            licence=licence,
            controls=controls,
            authority_clauses=authority_clauses,
            freshness_policies=freshness_policies,
        )
        verified_signature = RuleChainV2Signature.from_dict(signature.to_dict())
        if (
            verified_signature.object_kind != "standard-pack"
            or verified_signature.body_digest != canonical_digest(body)
        ):
            raise ValueError("v2 pack signature does not bind the complete pack body")
        return cls(
            pack_id=cast(str, body["pack_id"]),
            version=cast(str, body["version"]),
            source_uri=cast(str, body["source_uri"]),
            source_digest=cast(str, body["source_digest"]),
            transition_digest=cast(str, body["transition_digest"]),
            licence=cast(str, body["licence"]),
            controls=controls,
            authority_clauses=authority_clauses,
            freshness_policies=freshness_policies,
            signature=verified_signature,
            pack_digest=canonical_digest({**body, "signature": verified_signature.to_dict()}),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the typed signed pack and its complete integrity digest."""
        return {
            **self.body(
                pack_id=self.pack_id,
                version=self.version,
                source_uri=self.source_uri,
                source_digest=self.source_digest,
                transition_digest=self.transition_digest,
                licence=self.licence,
                controls=self.controls,
                authority_clauses=self.authority_clauses,
                freshness_policies=self.freshness_policies,
            ),
            "signature": self.signature.to_dict(),
            "pack_digest": self.pack_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> StandardPackV2:
        """Parse exact v2 content without coercing a v1 pack or evidence TTL."""
        data = require_mapping(value, "v2 pack")
        require_exact_fields(data, _PACK_FIELDS, "standard-pack v2")
        if data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION:
            raise ValueError("unsupported v2 pack schema version")
        if data.get("object_kind") != "standard-pack":
            raise ValueError("v2 pack object kind is invalid")
        arrays = (
            data.get("controls"),
            data.get("authority_clauses"),
            data.get("freshness_policies"),
        )
        if any(not isinstance(item, list) for item in arrays):
            raise ValueError("v2 pack components must be arrays")
        raw_controls, raw_clauses, raw_freshness = cast(tuple[list[object], ...], arrays)
        pack = cls.build(
            pack_id=require_identifier(data.get("pack_id"), "pack.pack_id"),
            version=require_semantic_version(data.get("version"), "pack.version"),
            source_uri=require_string(data.get("source_uri"), "pack.source_uri"),
            source_digest=require_digest(data.get("source_digest"), "pack.source_digest"),
            transition_digest=require_digest(
                data.get("transition_digest"), "pack.transition_digest"
            ),
            licence=require_string(data.get("licence"), "pack.licence"),
            controls=tuple(ControlDefinition.from_dict(item) for item in raw_controls),
            authority_clauses=tuple(AuthorityClauseV2.from_dict(item) for item in raw_clauses),
            freshness_policies=tuple(FreshnessPolicyV2.from_dict(item) for item in raw_freshness),
            signature=RuleChainV2Signature.from_dict(data.get("signature")),
        )
        if data.get("pack_digest") != pack.pack_digest:
            raise ValueError("v2 pack digest does not match its content")
        return pack

    def verify_structural_source_signature(
        self,
        *,
        roles: RuleChainV2TrustRoles,
        source_verifier: object,
        now: datetime,
    ) -> bool:
        """Check only signature and retained pack-source identity.

        The host verifier must be composed outside the request. This method
        does not accept semantic transitions or discovery receipts. A true
        result is structural evidence only, never profile or Guard admission.
        """
        if not isinstance(source_verifier, HostPackSourceVerifier):
            return False
        try:
            StandardPackV2.from_dict(self.to_dict())
            source_verifier.verify(
                pack_id=self.pack_id,
                source_uri=self.source_uri,
                source_digest=self.source_digest,
            )
        except (OSError, PermissionError, StableReadError, ValueError):
            return False
        return self.signature.verify(
            body_digest=canonical_digest(
                self.body(
                    pack_id=self.pack_id,
                    version=self.version,
                    source_uri=self.source_uri,
                    source_digest=self.source_digest,
                    transition_digest=self.transition_digest,
                    licence=self.licence,
                    controls=self.controls,
                    authority_clauses=self.authority_clauses,
                    freshness_policies=self.freshness_policies,
                )
            ),
            roles=roles,
            now=now,
        )
