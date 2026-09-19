# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed rule-chain profile candidate
"""Bind an explicit project selection to authenticated v2 pack objects."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, cast

from .audit_primitives import require_exact_fields
from .model_primitives import require_digest, require_identifier, validate_unique_strings
from .models import canonical_digest, require_mapping
from .pack_source_host import HostPackSourceVerifier
from .rule_chain_pack_v2 import StandardPackV2
from .signed_rule_chain_v2 import (
    RULE_CHAIN_V2_SCHEMA_VERSION,
    RuleChainV2Signature,
    RuleChainV2TrustRoles,
)

_SELECTION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "pack_id",
        "pack_digest",
        "source_digest",
        "transition_digest",
        "pack_signer_key_id",
        "selection_digest",
    }
)
_PROFILE_FIELDS: Final = frozenset(
    {
        "schema_version",
        "object_kind",
        "project_id",
        "profile_id",
        "selector_scope_digest",
        "selected_packs",
        "authority_clause_ids",
        "freshness_policy_ids",
        "local_constraint_digests",
        "excluded_clause_ids",
        "signature",
        "profile_digest",
    }
)


def _wire_identifiers(value: object, field: str) -> tuple[str, ...]:
    """Parse a unique identifier array without coercing other JSON types."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return tuple(require_identifier(item, field) for item in cast(list[object], value))


def _wire_digests(value: object, field: str) -> tuple[str, ...]:
    """Parse a unique digest array without accepting a scalar shortcut."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return tuple(require_digest(item, field) for item in cast(list[object], value))


@dataclass(frozen=True)
class SelectedPackV2:
    """Pin one exact pack object and its pack-issuer verification identity."""

    pack_id: str
    pack_digest: str
    source_digest: str
    transition_digest: str
    pack_signer_key_id: str
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        pack_digest: str,
        source_digest: str,
        transition_digest: str,
        pack_signer_key_id: str,
    ) -> SelectedPackV2:
        """Build an exact reference that cannot silently select latest."""
        fields = {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "pack_id": require_identifier(pack_id, "selection.pack_id"),
            "pack_digest": require_digest(pack_digest, "selection.pack_digest"),
            "source_digest": require_digest(source_digest, "selection.source_digest"),
            "transition_digest": require_digest(transition_digest, "selection.transition_digest"),
            "pack_signer_key_id": require_identifier(
                pack_signer_key_id, "selection.pack_signer_key_id"
            ),
        }
        return cls(
            pack_id=fields["pack_id"],
            pack_digest=fields["pack_digest"],
            source_digest=fields["source_digest"],
            transition_digest=fields["transition_digest"],
            pack_signer_key_id=fields["pack_signer_key_id"],
            selection_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise the exact pack and signer reference."""
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "pack_id": self.pack_id,
            "pack_digest": self.pack_digest,
            "source_digest": self.source_digest,
            "transition_digest": self.transition_digest,
            "pack_signer_key_id": self.pack_signer_key_id,
            "selection_digest": self.selection_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SelectedPackV2:
        """Refuse a missing, excess or recomputed selection field."""
        data = require_mapping(value, "v2 selected pack")
        require_exact_fields(data, _SELECTION_FIELDS, "selected-pack v2")
        if data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION:
            raise ValueError("unsupported selected-pack schema version")
        selection = cls.build(
            pack_id=require_identifier(data.get("pack_id"), "selection.pack_id"),
            pack_digest=require_digest(data.get("pack_digest"), "selection.pack_digest"),
            source_digest=require_digest(data.get("source_digest"), "selection.source_digest"),
            transition_digest=require_digest(
                data.get("transition_digest"), "selection.transition_digest"
            ),
            pack_signer_key_id=require_identifier(
                data.get("pack_signer_key_id"), "selection.pack_signer_key_id"
            ),
        )
        if data.get("selection_digest") != selection.selection_digest:
            raise ValueError("v2 pack selection digest does not match its fields")
        return selection


@dataclass(frozen=True)
class ProjectProfileV2:
    """Signed project choice without an implicit effect grant or resolved lock."""

    project_id: str
    profile_id: str
    selector_scope_digest: str
    selected_packs: tuple[SelectedPackV2, ...]
    authority_clause_ids: tuple[str, ...]
    freshness_policy_ids: tuple[str, ...]
    local_constraint_digests: tuple[str, ...]
    excluded_clause_ids: tuple[str, ...]
    signature: RuleChainV2Signature
    profile_digest: str

    @staticmethod
    def body(
        *,
        project_id: str,
        profile_id: str,
        selector_scope_digest: str,
        selected_packs: tuple[SelectedPackV2, ...],
        authority_clause_ids: tuple[str, ...],
        freshness_policy_ids: tuple[str, ...],
        local_constraint_digests: tuple[str, ...],
        excluded_clause_ids: tuple[str, ...],
    ) -> dict[str, object]:
        """Return the complete typed selection signed by the project selector."""
        if not selected_packs or not authority_clause_ids or not freshness_policy_ids:
            raise ValueError("v2 profile needs packs, authority and freshness selections")
        parsed_packs = tuple(SelectedPackV2.from_dict(item.to_dict()) for item in selected_packs)
        pack_ids = tuple(item.pack_id for item in parsed_packs)
        if len(pack_ids) != len(set(pack_ids)):
            raise ValueError("v2 profile cannot select a pack twice")
        selected_authority = validate_unique_strings(
            authority_clause_ids, "profile.authority_clause_ids", minimum=1
        )
        selected_freshness = validate_unique_strings(
            freshness_policy_ids, "profile.freshness_policy_ids", minimum=1
        )
        excluded = validate_unique_strings(excluded_clause_ids, "profile.excluded_clause_ids")
        if set(selected_authority).intersection(excluded):
            raise ValueError("v2 profile cannot select and exclude the same clause")
        constraints = validate_unique_strings(
            local_constraint_digests, "profile.local_constraint_digests"
        )
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "object_kind": "project-profile",
            "project_id": require_identifier(project_id, "profile.project_id"),
            "profile_id": require_identifier(profile_id, "profile.profile_id"),
            "selector_scope_digest": require_digest(
                selector_scope_digest, "profile.selector_scope_digest"
            ),
            "selected_packs": [item.to_dict() for item in parsed_packs],
            "authority_clause_ids": [
                require_identifier(item, "profile.authority_clause_id")
                for item in selected_authority
            ],
            "freshness_policy_ids": [
                require_identifier(item, "profile.freshness_policy_id")
                for item in selected_freshness
            ],
            "local_constraint_digests": [
                require_digest(item, "profile.local_constraint_digest") for item in constraints
            ],
            "excluded_clause_ids": [
                require_identifier(item, "profile.excluded_clause_id") for item in excluded
            ],
        }

    @classmethod
    def build(
        cls,
        *,
        project_id: str,
        profile_id: str,
        selector_scope_digest: str,
        selected_packs: tuple[SelectedPackV2, ...],
        authority_clause_ids: tuple[str, ...],
        freshness_policy_ids: tuple[str, ...],
        local_constraint_digests: tuple[str, ...],
        excluded_clause_ids: tuple[str, ...],
        signature: RuleChainV2Signature,
    ) -> ProjectProfileV2:
        """Build one profile only when its signature metadata binds its body."""
        body = cls.body(
            project_id=project_id,
            profile_id=profile_id,
            selector_scope_digest=selector_scope_digest,
            selected_packs=selected_packs,
            authority_clause_ids=authority_clause_ids,
            freshness_policy_ids=freshness_policy_ids,
            local_constraint_digests=local_constraint_digests,
            excluded_clause_ids=excluded_clause_ids,
        )
        verified_signature = RuleChainV2Signature.from_dict(signature.to_dict())
        if (
            verified_signature.object_kind != "project-profile"
            or verified_signature.body_digest != canonical_digest(body)
        ):
            raise ValueError("v2 profile signature does not bind the complete body")
        return cls(
            project_id=cast(str, body["project_id"]),
            profile_id=cast(str, body["profile_id"]),
            selector_scope_digest=cast(str, body["selector_scope_digest"]),
            selected_packs=selected_packs,
            authority_clause_ids=authority_clause_ids,
            freshness_policy_ids=freshness_policy_ids,
            local_constraint_digests=local_constraint_digests,
            excluded_clause_ids=excluded_clause_ids,
            signature=verified_signature,
            profile_digest=canonical_digest({**body, "signature": verified_signature.to_dict()}),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise a revalidated, exact signed project selection."""
        return {
            **self.body(
                project_id=self.project_id,
                profile_id=self.profile_id,
                selector_scope_digest=self.selector_scope_digest,
                selected_packs=self.selected_packs,
                authority_clause_ids=self.authority_clause_ids,
                freshness_policy_ids=self.freshness_policy_ids,
                local_constraint_digests=self.local_constraint_digests,
                excluded_clause_ids=self.excluded_clause_ids,
            ),
            "signature": self.signature.to_dict(),
            "profile_digest": self.profile_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProjectProfileV2:
        """Parse exact v2 fields without coercing a v1 project profile."""
        data = require_mapping(value, "v2 project profile")
        require_exact_fields(data, _PROFILE_FIELDS, "project-profile v2")
        if data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION:
            raise ValueError("unsupported v2 project-profile schema version")
        if data.get("object_kind") != "project-profile":
            raise ValueError("v2 project-profile object kind is invalid")
        raw_packs = data.get("selected_packs")
        if not isinstance(raw_packs, list):
            raise ValueError("profile.selected_packs must be an array")
        profile = cls.build(
            project_id=require_identifier(data.get("project_id"), "profile.project_id"),
            profile_id=require_identifier(data.get("profile_id"), "profile.profile_id"),
            selector_scope_digest=require_digest(
                data.get("selector_scope_digest"), "profile.selector_scope_digest"
            ),
            selected_packs=tuple(
                SelectedPackV2.from_dict(item) for item in cast(list[object], raw_packs)
            ),
            authority_clause_ids=_wire_identifiers(
                data.get("authority_clause_ids"), "profile.authority_clause_ids"
            ),
            freshness_policy_ids=_wire_identifiers(
                data.get("freshness_policy_ids"), "profile.freshness_policy_ids"
            ),
            local_constraint_digests=_wire_digests(
                data.get("local_constraint_digests"), "profile.local_constraint_digests"
            ),
            excluded_clause_ids=_wire_identifiers(
                data.get("excluded_clause_ids"), "profile.excluded_clause_ids"
            ),
            signature=RuleChainV2Signature.from_dict(data.get("signature")),
        )
        if data.get("profile_digest") != profile.profile_digest:
            raise ValueError("v2 profile digest does not match its content")
        return profile

    def verify_structural_selection(
        self,
        *,
        packs: tuple[StandardPackV2, ...],
        roles: RuleChainV2TrustRoles,
        source_verifiers: Mapping[str, HostPackSourceVerifier],
        expected_project_id: str,
        expected_scope_digest: str,
        now: datetime,
    ) -> bool:
        """Authenticate signed pack references and project scope structurally.

        The host must compose one source verifier per selected pack.
        Semantic-transition and receipt admission are NOT checked here;
        this result cannot select an effective profile or grant effects.
        """
        try:
            ProjectProfileV2.from_dict(self.to_dict())
        except ValueError:
            return False
        if (
            self.project_id != expected_project_id
            or self.selector_scope_digest != expected_scope_digest
            or len(packs) != len(self.selected_packs)
        ):
            return False
        exact_packs = {pack.pack_id: pack for pack in packs}
        if len(exact_packs) != len(packs) or set(source_verifiers) != set(exact_packs):
            return False
        for selection in self.selected_packs:
            pack = exact_packs.get(selection.pack_id)
            source_verifier = source_verifiers.get(selection.pack_id)
            if (
                pack is None
                or (
                    selection.pack_digest != pack.pack_digest
                    or selection.source_digest != pack.source_digest
                    or selection.transition_digest != pack.transition_digest
                    or selection.pack_signer_key_id != pack.signature.key_id
                )
                or not isinstance(source_verifier, HostPackSourceVerifier)
            ):
                return False
            if not pack.verify_structural_source_signature(
                roles=roles,
                source_verifier=source_verifier,
                now=now,
            ):
                return False
        clauses = {item.clause_id for pack in packs for item in pack.authority_clauses}
        freshness = {item.policy_id for pack in packs for item in pack.freshness_policies}
        if not set(self.authority_clause_ids).issubset(clauses):
            return False
        if not set(self.excluded_clause_ids).issubset(clauses):
            return False
        if not set(self.freshness_policy_ids).issubset(freshness):
            return False
        return self.signature.verify(
            body_digest=canonical_digest(
                self.body(
                    project_id=self.project_id,
                    profile_id=self.profile_id,
                    selector_scope_digest=self.selector_scope_digest,
                    selected_packs=self.selected_packs,
                    authority_clause_ids=self.authority_clause_ids,
                    freshness_policy_ids=self.freshness_policy_ids,
                    local_constraint_digests=self.local_constraint_digests,
                    excluded_clause_ids=self.excluded_clause_ids,
                )
            ),
            roles=roles,
            now=now,
        )
