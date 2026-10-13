# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed v2 effective-rule lock candidate
"""Bind a complete resolved pack/profile projection to a lock-resolver signature."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, cast

from ._rule_chain_lock_body_v2 import _LockProjectionV2
from .audit_primitives import require_exact_fields
from .effective_profile import AdapterLock, PolicyContradiction
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_unique_strings,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_mapping, require_string
from .pack_source_host import HostPackSourceVerifier
from .rule_chain_candidate_v2 import RuleChainCandidateReportV2
from .rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2, StandardPackV2
from .rule_chain_profile_v2 import ProjectProfileV2
from .signed_rule_chain_v2 import (
    RULE_CHAIN_V2_SCHEMA_VERSION,
    RuleChainV2Signature,
    RuleChainV2TrustRoles,
)

_LOCK_FIELDS: Final = frozenset(
    {
        "schema_version",
        "object_kind",
        "project_id",
        "profile_id",
        "profile_digest",
        "selector_scope_digest",
        "acceptance_digest",
        "acceptance_host_selection_digest",
        "reviewer_policy_digest",
        "effect_operations_digest",
        "pack_digests",
        "pack_source_verification_digests",
        "authority_clauses",
        "successor_clause_digests",
        "freshness_policies",
        "local_constraint_digests",
        "excluded_clause_ids",
        "adapter_custody",
        "issuer_order",
        "grantor_classes",
        "rule_projection_digest",
        "resolver_code_digest",
        "resolution_status",
        "contradictions",
        "resolved_at",
        "signature",
        "lock_digest",
    }
)
ResolutionStatus = Literal["effective", "held"]


def _array(value: object, label: str) -> list[object]:
    """Require a JSON array without coercing tuples or scalars."""
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return cast(list[object], value)


@dataclass(frozen=True)
class EffectiveProfileLockV2(_LockProjectionV2):
    """Signed complete rule projection awaiting protected host selection.

    Attributes
    ----------
    project_id : str
        Exact selected project identity.
    profile_id : str
        Exact selected profile identity.
    profile_digest : str
        Digest of the signed selected profile.
    selector_scope_digest : str
        Protected selector-scope digest.
    acceptance_digest : str
        Signed transition acceptance envelope digest shared by every authority clause.
    acceptance_host_selection_digest : str
        Protected acceptance-host selection precondition.
    reviewer_policy_digest : str
        Complete selected reviewer identity policy digest.
    effect_operations_digest : str
        Selected closed operation catalogue digest.
    pack_digests : tuple[str, ...]
        Unique selected pack digests, in selection order.
    pack_source_verification_digests : tuple[str, ...]
        One retained-source proof digest per selected pack, in the same order.
    authority_clauses : tuple[AuthorityClauseV2, ...]
        Complete ordered selected authority clauses.
    successor_clause_digests : tuple[str, ...]
        Four distinct selected successor clause digests, in proposal order.
    freshness_policies : tuple[FreshnessPolicyV2, ...]
        Complete ordered selected freshness policies.
    local_constraint_digests : tuple[str, ...]
        Unique additional selected constraint digests.
    excluded_clause_ids : tuple[str, ...]
        Unique excluded clause IDs, disjoint from selected authority clauses.
    adapter_custody : tuple[AdapterLock, ...]
        Current custody records for exactly the required adapter IDs.
    issuer_order : tuple[str, ...]
        Protected unique ordered grantor identities.
    resolution_status : ResolutionStatus
        Effective for an unblocked projection; held when blocking contradictions are present.
    contradictions : tuple[PolicyContradiction, ...]
        Blocking contradiction records matching the declared hold status.
    resolved_at : str
        Declared timezone-aware UTC resolution timestamp.
    resolver_code_digest : str
        Protected resolver implementation digest carried in the body.
    grantor_classes : tuple[str, ...]
        Sorted grantor identities derived from the selected clauses.
    rule_projection_digest : str
        Canonical digest over every resolved projection component.
    signature : RuleChainV2Signature
        External lock-resolver signature binding the complete unsigned body.
    lock_digest : str
        Canonical digest of the complete body and detached signature envelope.

    Notes
    -----
    Body construction and parsing validate integrity. Runtime consumers freshly verify this lock
    against protected sources, roles, current adapters and selected state.
    """

    project_id: str
    profile_id: str
    profile_digest: str
    selector_scope_digest: str
    acceptance_digest: str
    acceptance_host_selection_digest: str
    reviewer_policy_digest: str
    effect_operations_digest: str
    pack_digests: tuple[str, ...]
    pack_source_verification_digests: tuple[str, ...]
    authority_clauses: tuple[AuthorityClauseV2, ...]
    successor_clause_digests: tuple[str, ...]
    freshness_policies: tuple[FreshnessPolicyV2, ...]
    local_constraint_digests: tuple[str, ...]
    excluded_clause_ids: tuple[str, ...]
    adapter_custody: tuple[AdapterLock, ...]
    issuer_order: tuple[str, ...]
    grantor_classes: tuple[str, ...]
    rule_projection_digest: str
    resolver_code_digest: str
    resolution_status: ResolutionStatus
    contradictions: tuple[PolicyContradiction, ...]
    resolved_at: str
    signature: RuleChainV2Signature
    lock_digest: str

    @classmethod
    def build(
        cls,
        *,
        project_id: str,
        profile_id: str,
        profile_digest: str,
        selector_scope_digest: str,
        acceptance_digest: str,
        acceptance_host_selection_digest: str,
        reviewer_policy_digest: str,
        effect_operations_digest: str,
        pack_digests: tuple[str, ...],
        pack_source_verification_digests: tuple[str, ...],
        authority_clauses: tuple[AuthorityClauseV2, ...],
        successor_clause_digests: tuple[str, ...],
        freshness_policies: tuple[FreshnessPolicyV2, ...],
        local_constraint_digests: tuple[str, ...],
        excluded_clause_ids: tuple[str, ...],
        adapter_custody: tuple[AdapterLock, ...],
        issuer_order: tuple[str, ...],
        resolution_status: ResolutionStatus,
        contradictions: tuple[PolicyContradiction, ...],
        resolved_at: str,
        resolver_code_digest: str,
        signature: RuleChainV2Signature,
    ) -> EffectiveProfileLockV2:
        """Bind a supplied resolver signature to the complete canonical lock body.

        Parameters
        ----------
        project_id : str
            Exact selected project identity.
        profile_id : str
            Exact selected profile identity.
        profile_digest : str
            Digest of the signed selected profile.
        selector_scope_digest : str
            Protected selector-scope digest.
        acceptance_digest : str
            Signed transition acceptance envelope digest shared by every authority clause.
        acceptance_host_selection_digest : str
            Protected acceptance-host selection precondition.
        reviewer_policy_digest : str
            Complete selected reviewer identity policy digest.
        effect_operations_digest : str
            Selected closed operation catalogue digest.
        pack_digests : tuple[str, ...]
            Unique selected pack digests, in selection order.
        pack_source_verification_digests : tuple[str, ...]
            One retained-source proof digest per selected pack, in the same order.
        authority_clauses : tuple[AuthorityClauseV2, ...]
            Complete ordered selected authority clauses.
        successor_clause_digests : tuple[str, ...]
            Four distinct selected successor clause digests, in proposal order.
        freshness_policies : tuple[FreshnessPolicyV2, ...]
            Complete ordered selected freshness policies.
        local_constraint_digests : tuple[str, ...]
            Unique additional selected constraint digests.
        excluded_clause_ids : tuple[str, ...]
            Unique excluded clause IDs, disjoint from selected authority clauses.
        adapter_custody : tuple[AdapterLock, ...]
            Current custody records for exactly the required adapter IDs.
        issuer_order : tuple[str, ...]
            Protected unique ordered grantor identities.
        resolution_status : ResolutionStatus
            Effective for an unblocked projection; held when blocking contradictions are present.
        contradictions : tuple[PolicyContradiction, ...]
            Blocking contradiction records matching the declared hold status.
        resolved_at : str
            Declared timezone-aware UTC resolution timestamp.
        resolver_code_digest : str
            Protected resolver implementation digest carried in the body.
        signature : RuleChainV2Signature
            External effective-profile-lock signature whose body digest must match the complete
            projection.

        Returns
        -------
        EffectiveProfileLockV2
            Exact lock record and recomputed envelope digest.

        Raises
        ------
        ValueError
            The projection is malformed or the signature object kind or body digest differs.

        Notes
        -----
        Attaching correctly shaped signature bytes does not verify the signing key or establish
        protected selection; consuming verification does both.
        """
        body = cls.body(
            project_id=project_id,
            profile_id=profile_id,
            profile_digest=profile_digest,
            selector_scope_digest=selector_scope_digest,
            acceptance_digest=acceptance_digest,
            acceptance_host_selection_digest=acceptance_host_selection_digest,
            reviewer_policy_digest=reviewer_policy_digest,
            effect_operations_digest=effect_operations_digest,
            pack_digests=pack_digests,
            pack_source_verification_digests=pack_source_verification_digests,
            authority_clauses=authority_clauses,
            successor_clause_digests=successor_clause_digests,
            freshness_policies=freshness_policies,
            local_constraint_digests=local_constraint_digests,
            excluded_clause_ids=excluded_clause_ids,
            adapter_custody=adapter_custody,
            issuer_order=issuer_order,
            resolution_status=resolution_status,
            contradictions=contradictions,
            resolved_at=resolved_at,
            resolver_code_digest=resolver_code_digest,
        )
        signed = RuleChainV2Signature.from_dict(signature.to_dict())
        if (
            signed.object_kind != "effective-profile-lock"
            or signed.body_digest != canonical_digest(body)
        ):
            raise ValueError("lock resolver signature does not bind the full projection")
        return cls(
            project_id=cast(str, body["project_id"]),
            profile_id=cast(str, body["profile_id"]),
            profile_digest=cast(str, body["profile_digest"]),
            selector_scope_digest=cast(str, body["selector_scope_digest"]),
            acceptance_digest=cast(str, body["acceptance_digest"]),
            acceptance_host_selection_digest=cast(str, body["acceptance_host_selection_digest"]),
            reviewer_policy_digest=cast(str, body["reviewer_policy_digest"]),
            effect_operations_digest=cast(str, body["effect_operations_digest"]),
            pack_digests=pack_digests,
            pack_source_verification_digests=pack_source_verification_digests,
            authority_clauses=authority_clauses,
            successor_clause_digests=successor_clause_digests,
            freshness_policies=freshness_policies,
            local_constraint_digests=local_constraint_digests,
            excluded_clause_ids=excluded_clause_ids,
            adapter_custody=adapter_custody,
            issuer_order=issuer_order,
            grantor_classes=tuple(cast(list[str], body["grantor_classes"])),
            rule_projection_digest=cast(str, body["rule_projection_digest"]),
            resolution_status=resolution_status,
            contradictions=contradictions,
            resolved_at=cast(str, body["resolved_at"]),
            resolver_code_digest=cast(str, body["resolver_code_digest"]),
            signature=signed,
            lock_digest=canonical_digest({**body, "signature": signed.to_dict()}),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the exact lock and detached resolver signature.

        Returns
        -------
        dict[str, object]
            Closed wire preserving every selected field and integrity digest.

        Raises
        ------
        ValueError
            Stored projection fields or derived grantor/projection data are inconsistent.
        """
        body = self.body(
            project_id=self.project_id,
            profile_id=self.profile_id,
            profile_digest=self.profile_digest,
            selector_scope_digest=self.selector_scope_digest,
            acceptance_digest=self.acceptance_digest,
            acceptance_host_selection_digest=self.acceptance_host_selection_digest,
            reviewer_policy_digest=self.reviewer_policy_digest,
            effect_operations_digest=self.effect_operations_digest,
            pack_digests=self.pack_digests,
            pack_source_verification_digests=self.pack_source_verification_digests,
            authority_clauses=self.authority_clauses,
            successor_clause_digests=self.successor_clause_digests,
            freshness_policies=self.freshness_policies,
            local_constraint_digests=self.local_constraint_digests,
            excluded_clause_ids=self.excluded_clause_ids,
            adapter_custody=self.adapter_custody,
            issuer_order=self.issuer_order,
            resolution_status=self.resolution_status,
            contradictions=self.contradictions,
            resolved_at=self.resolved_at,
            resolver_code_digest=self.resolver_code_digest,
        )
        if body["rule_projection_digest"] != self.rule_projection_digest or body[
            "grantor_classes"
        ] != list(self.grantor_classes):
            raise ValueError("lock projection differs from its canonical content")
        return {**body, "signature": self.signature.to_dict(), "lock_digest": self.lock_digest}

    @classmethod
    def from_dict(cls, value: object) -> EffectiveProfileLockV2:
        """Rebuild the full lock and reject missing, extra or changed fields.

        Parameters
        ----------
        value : object
            Exact closed v2 lock wire, including signature and derived integrity digests.

        Returns
        -------
        EffectiveProfileLockV2
            Lock rebuilt from canonical projection validation and envelope digest checks.

        Raises
        ------
        ValueError
            Schema, fields, projection, signature shape or recomputed digests differ.
        """
        data = require_mapping(value, "effective profile lock v2")
        require_exact_fields(data, _LOCK_FIELDS, "effective profile lock v2")
        if (
            data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION
            or data.get("object_kind") != "effective-profile-lock"
        ):
            raise ValueError("unsupported v2 effective-profile-lock type")
        status = require_string(data.get("resolution_status"), "lock.resolution_status")
        if status not in {"effective", "held"}:
            raise ValueError("lock resolution status is unsupported")
        lock = cls.build(
            project_id=require_identifier(data.get("project_id"), "lock.project_id"),
            profile_id=require_identifier(data.get("profile_id"), "lock.profile_id"),
            profile_digest=require_digest(data.get("profile_digest"), "lock.profile_digest"),
            selector_scope_digest=require_digest(
                data.get("selector_scope_digest"), "lock.selector_scope_digest"
            ),
            acceptance_digest=require_digest(
                data.get("acceptance_digest"), "lock.acceptance_digest"
            ),
            acceptance_host_selection_digest=require_digest(
                data.get("acceptance_host_selection_digest"),
                "lock.acceptance_host_selection_digest",
            ),
            reviewer_policy_digest=require_digest(
                data.get("reviewer_policy_digest"), "lock.reviewer_policy_digest"
            ),
            effect_operations_digest=require_digest(
                data.get("effect_operations_digest"), "lock.effect_operations_digest"
            ),
            pack_digests=tuple(
                require_digest(item, "lock.pack_digest")
                for item in _array(data.get("pack_digests"), "lock.pack_digests")
            ),
            pack_source_verification_digests=tuple(
                require_digest(item, "lock.pack_source_verification_digest")
                for item in _array(
                    data.get("pack_source_verification_digests"),
                    "lock.pack_source_verification_digests",
                )
            ),
            authority_clauses=tuple(
                AuthorityClauseV2.from_dict(item)
                for item in _array(data.get("authority_clauses"), "lock.authority_clauses")
            ),
            successor_clause_digests=tuple(
                require_digest(item, "lock.successor_clause_digest")
                for item in _array(
                    data.get("successor_clause_digests"), "lock.successor_clause_digests"
                )
            ),
            freshness_policies=tuple(
                FreshnessPolicyV2.from_dict(item)
                for item in _array(data.get("freshness_policies"), "lock.freshness_policies")
            ),
            local_constraint_digests=tuple(
                require_digest(item, "lock.local_constraint_digest")
                for item in _array(
                    data.get("local_constraint_digests"), "lock.local_constraint_digests"
                )
            ),
            excluded_clause_ids=tuple(
                require_identifier(item, "lock.excluded_clause_id")
                for item in _array(data.get("excluded_clause_ids"), "lock.excluded_clause_ids")
            ),
            adapter_custody=tuple(
                AdapterLock.from_dict(item)
                for item in _array(data.get("adapter_custody"), "lock.adapter_custody")
            ),
            issuer_order=require_unique_strings(
                data.get("issuer_order"), "lock.issuer_order", minimum=1
            ),
            resolution_status=cast(ResolutionStatus, status),
            contradictions=tuple(
                PolicyContradiction.from_dict(item)
                for item in _array(data.get("contradictions"), "lock.contradictions")
            ),
            resolved_at=require_utc_timestamp(data.get("resolved_at"), "lock.resolved_at"),
            resolver_code_digest=require_digest(
                data.get("resolver_code_digest"), "lock.resolver_code_digest"
            ),
            signature=RuleChainV2Signature.from_dict(data.get("signature")),
        )
        if (
            data.get("grantor_classes") != list(lock.grantor_classes)
            or data.get("rule_projection_digest") != lock.rule_projection_digest
            or data.get("lock_digest") != lock.lock_digest
        ):
            raise ValueError("v2 lock content or projection digest differs")
        return lock

    def verify_structural_lock(
        self,
        *,
        candidate: RuleChainCandidateReportV2,
        profile: ProjectProfileV2,
        packs: tuple[StandardPackV2, ...],
        source_verifiers: Mapping[str, HostPackSourceVerifier],
        current_adapters: tuple[AdapterLock, ...],
        roles: RuleChainV2TrustRoles,
        expected_acceptance_host_selection_digest: str,
        expected_effect_operations_digest: str,
        expected_resolver_code_digest: str,
        expected_issuer_order: tuple[str, ...],
        now: datetime,
    ) -> bool:
        """Check a signed projection against a freshly inspected read-only chain.

        Parameters
        ----------
        candidate : RuleChainCandidateReportV2
            Fresh four-successor chain inspection result from the trusted host composition.
        profile : ProjectProfileV2
            Exact selected signed project profile.
        packs : tuple[StandardPackV2, ...]
            Exact signed pack objects in selection order.
        source_verifiers : Mapping[str, HostPackSourceVerifier]
            Protected retained-source verifier for every selected pack ID.
        current_adapters : tuple[AdapterLock, ...]
            Current host-owned adapter custody records.
        roles : RuleChainV2TrustRoles
            Five current enrolled signing-role policies.
        expected_acceptance_host_selection_digest : str
            Protected current acceptance selection precondition.
        expected_effect_operations_digest : str
            Protected current closed operation catalogue precondition.
        expected_resolver_code_digest : str
            Protected current resolver implementation precondition.
        expected_issuer_order : tuple[str, ...]
            Protected unique grantor ordering.
        now : datetime
            Trusted current timezone-aware UTC for signature and chronology checks.

        Returns
        -------
        bool
            True only for an effective lock with matching projection, profile, source proofs, current
            adapters, selected preconditions and a valid active resolver signature. Malformed typed
            records return false.

        Raises
        ------
        PermissionError
            A protected retained-source provider refuses verification.
        OSError
            Required retained-source custody cannot be safely read.

        Notes
        -----
        This does not authenticate a caller-supplied state provider or select the lock for execution.
        Production reruns the complete chain under protected state.
        """
        try:
            parsed = EffectiveProfileLockV2.from_dict(self.to_dict())
            selected = ProjectProfileV2.from_dict(profile.to_dict())
            exact_packs = tuple(StandardPackV2.from_dict(item.to_dict()) for item in packs)
            adapters = tuple(AdapterLock.from_dict(item.to_dict()) for item in current_adapters)
            expected = require_digest(
                expected_acceptance_host_selection_digest, "lock.expected_host_selection"
            )
            expected_operations = require_digest(
                expected_effect_operations_digest, "lock.expected_effect_operations_digest"
            )
            resolver_digest = require_digest(
                expected_resolver_code_digest, "lock.expected_resolver_code_digest"
            )
            issuers = tuple(
                require_identifier(item, "lock.expected_issuer")
                for item in validate_unique_strings(
                    expected_issuer_order, "lock.expected_issuer_order", minimum=1
                )
            )
            resolved = parse_utc_timestamp(self.resolved_at, "lock.resolved_at")
            signed_at = parse_utc_timestamp(self.signature.signed_at, "lock.signature.signed_at")
        except (TypeError, ValueError):
            return False
        clause_ids = [
            clause.clause_id for pack in exact_packs for clause in pack.authority_clauses
        ]
        freshness_ids = [
            policy.policy_id for pack in exact_packs for policy in pack.freshness_policies
        ]
        if len(set(clause_ids)) != len(clause_ids) or len(set(freshness_ids)) != len(
            freshness_ids
        ):
            return False
        pack_clauses = {
            clause.clause_id: clause for pack in exact_packs for clause in pack.authority_clauses
        }
        pack_freshness = {
            policy.policy_id: policy for pack in exact_packs for policy in pack.freshness_policies
        }
        if (
            parsed != self
            or now.tzinfo is None
            or now.utcoffset() != UTC.utcoffset(now)
            or not resolved <= signed_at <= now
            or self.resolution_status != "effective"
            or self.acceptance_host_selection_digest != expected
            or self.effect_operations_digest != expected_operations
            or self.resolver_code_digest != resolver_digest
            or self.issuer_order != issuers
            or self.acceptance_digest != candidate.acceptance_digest
            or self.reviewer_policy_digest != candidate.reviewer_policy_digest
            or self.profile_digest != candidate.profile_digest
            or self.profile_digest != selected.profile_digest
            or self.project_id != selected.project_id
            or self.profile_id != selected.profile_id
            or self.selector_scope_digest != selected.selector_scope_digest
            or self.pack_digests != candidate.pack_digests
            or self.pack_digests != tuple(item.pack_digest for item in exact_packs)
            or self.local_constraint_digests != selected.local_constraint_digests
            or self.excluded_clause_ids != selected.excluded_clause_ids
            or self.authority_clauses
            != tuple(pack_clauses.get(item) for item in selected.authority_clause_ids)
            or self.freshness_policies
            != tuple(pack_freshness.get(item) for item in selected.freshness_policy_ids)
            or self.successor_clause_digests != candidate.successor_clause_digests
            or self.adapter_custody != adapters
            or set(source_verifiers) != {item.pack_id for item in exact_packs}
        ):
            return False
        if not selected.verify_structural_selection(
            packs=exact_packs,
            roles=roles,
            source_verifiers=source_verifiers,
            expected_project_id=self.project_id,
            expected_scope_digest=self.selector_scope_digest,
            now=now,
        ):
            return False
        for index, pack in enumerate(exact_packs):
            proof = source_verifiers[pack.pack_id].verify(
                pack_id=pack.pack_id,
                source_uri=pack.source_uri,
                source_digest=pack.source_digest,
            )
            if (
                proof.get("assertion_class") != "retained-object-integrity-only"
                or proof.get("promotable") is not False
                or proof.get("source_verification_digest")
                != self.pack_source_verification_digests[index]
            ):
                return False
        return self.signature.verify(
            body_digest=canonical_digest(
                self.body(
                    project_id=self.project_id,
                    profile_id=self.profile_id,
                    profile_digest=self.profile_digest,
                    selector_scope_digest=self.selector_scope_digest,
                    acceptance_digest=self.acceptance_digest,
                    acceptance_host_selection_digest=self.acceptance_host_selection_digest,
                    reviewer_policy_digest=self.reviewer_policy_digest,
                    effect_operations_digest=self.effect_operations_digest,
                    pack_digests=self.pack_digests,
                    pack_source_verification_digests=self.pack_source_verification_digests,
                    authority_clauses=self.authority_clauses,
                    successor_clause_digests=self.successor_clause_digests,
                    freshness_policies=self.freshness_policies,
                    local_constraint_digests=self.local_constraint_digests,
                    excluded_clause_ids=self.excluded_clause_ids,
                    adapter_custody=self.adapter_custody,
                    issuer_order=self.issuer_order,
                    resolution_status=self.resolution_status,
                    contradictions=self.contradictions,
                    resolved_at=self.resolved_at,
                    resolver_code_digest=self.resolver_code_digest,
                )
            ),
            roles=roles,
            now=now,
        )
