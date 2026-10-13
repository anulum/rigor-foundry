# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical v2 lock projection validation
"""Validate the canonical projection used by the public v2 lock API."""

from __future__ import annotations

from typing import Literal

from .effective_profile import AdapterLock, PolicyContradiction
from .model_primitives import (
    require_digest,
    require_identifier,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest
from .rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2
from .signed_rule_chain_v2 import RULE_CHAIN_V2_SCHEMA_VERSION

ResolutionStatus = Literal["effective", "held"]


class _LockProjectionV2:
    """Canonical projection validation inherited by the public effective lock."""

    @staticmethod
    def body(
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
    ) -> dict[str, object]:
        """Validate and derive the complete canonical resolved lock projection.

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

        Returns
        -------
        dict[str, object]
            Closed unsigned lock body with derived grantor classes and rule-projection digest.

        Raises
        ------
        ValueError
            Any identifier, digest, timestamp, clause, freshness, successor, custody, exclusion, grantor
            or hold relation is invalid.

        Notes
        -----
        This builds integrity-bound data. Selected pack signatures, retained sources, key lifecycles and
        trusted host choice are checked by consuming verifiers.
        """
        packs = tuple(require_digest(value, "lock.pack_digest") for value in pack_digests)
        sources = tuple(
            require_digest(value, "lock.pack_source_verification_digest")
            for value in pack_source_verification_digests
        )
        if not packs or len(packs) != len(sources) or len(set(packs)) != len(packs):
            raise ValueError("lock needs one unique source proof per selected pack")
        clauses = tuple(AuthorityClauseV2.from_dict(item.to_dict()) for item in authority_clauses)
        freshness = tuple(
            FreshnessPolicyV2.from_dict(item.to_dict()) for item in freshness_policies
        )
        adapters = tuple(AdapterLock.from_dict(item.to_dict()) for item in adapter_custody)
        blockers = tuple(PolicyContradiction.from_dict(item.to_dict()) for item in contradictions)
        clause_ids = tuple(item.clause_id for item in clauses)
        freshness_ids = tuple(item.policy_id for item in freshness)
        adapter_ids = tuple(item.adapter_id for item in adapters)
        if (
            not clauses
            or not freshness
            or len(set(clause_ids)) != len(clause_ids)
            or len(set(freshness_ids)) != len(freshness_ids)
            or len(set(adapter_ids)) != len(adapter_ids)
            or set(adapter_ids)
            != {item.adapter_id for item in clauses}
            | {item.proof_adapter_id for item in freshness}
        ):
            raise ValueError("lock projection clauses, freshness or adapters differ")
        successor_digests = tuple(
            require_digest(value, "lock.successor_clause_digest")
            for value in successor_clause_digests
        )
        if (
            len(successor_digests) != 4
            or len(set(successor_digests)) != 4
            or not set(successor_digests).issubset({item.clause_digest for item in clauses})
        ):
            raise ValueError("lock requires four selected successor clauses")
        acceptance = require_digest(acceptance_digest, "lock.acceptance_digest")
        if any(item.transition_digest != acceptance for item in clauses):
            raise ValueError("lock authority clause transition differs")
        constraints = tuple(
            require_digest(value, "lock.local_constraint_digest")
            for value in local_constraint_digests
        )
        exclusions = tuple(
            require_identifier(value, "lock.excluded_clause_id") for value in excluded_clause_ids
        )
        if len(set(constraints)) != len(constraints) or len(set(exclusions)) != len(exclusions):
            raise ValueError("lock constraints and exclusions must be unique")
        if set(exclusions).intersection(clause_ids):
            raise ValueError("lock cannot select an excluded authority clause")
        issuers = validate_unique_strings(issuer_order, "lock.issuer_order", minimum=1)
        issuers = tuple(require_identifier(item, "lock.issuer") for item in issuers)
        grantors = tuple(sorted({item for clause in clauses for item in clause.grantor_classes}))
        if not set(grantors).issubset(issuers):
            raise ValueError("lock grantors must belong to selected issuer order")
        if resolution_status not in {"effective", "held"}:
            raise ValueError("lock resolution status is unsupported")
        if (
            (resolution_status == "effective" and blockers)
            or (resolution_status == "held" and not blockers)
            or any(not item.blocking for item in blockers)
        ):
            raise ValueError("lock hold status and blockers differ")
        projection: dict[str, object] = {
            "authority_clauses": [item.to_dict() for item in clauses],
            "successor_clause_digests": list(successor_digests),
            "freshness_policies": [item.to_dict() for item in freshness],
            "local_constraint_digests": list(constraints),
            "excluded_clause_ids": list(exclusions),
            "adapter_custody": [item.to_dict() for item in adapters],
            "issuer_order": list(issuers),
            "grantor_classes": list(grantors),
        }
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "object_kind": "effective-profile-lock",
            "project_id": require_identifier(project_id, "lock.project_id"),
            "profile_id": require_identifier(profile_id, "lock.profile_id"),
            "profile_digest": require_digest(profile_digest, "lock.profile_digest"),
            "selector_scope_digest": require_digest(
                selector_scope_digest, "lock.selector_scope_digest"
            ),
            "acceptance_digest": acceptance,
            "acceptance_host_selection_digest": require_digest(
                acceptance_host_selection_digest, "lock.acceptance_host_selection_digest"
            ),
            "reviewer_policy_digest": require_digest(
                reviewer_policy_digest, "lock.reviewer_policy_digest"
            ),
            "effect_operations_digest": require_digest(
                effect_operations_digest, "lock.effect_operations_digest"
            ),
            "pack_digests": list(packs),
            "pack_source_verification_digests": list(sources),
            **projection,
            "rule_projection_digest": canonical_digest(projection),
            "resolver_code_digest": require_digest(
                resolver_code_digest, "lock.resolver_code_digest"
            ),
            "resolution_status": resolution_status,
            "contradictions": [item.to_dict() for item in blockers],
            "resolved_at": require_utc_timestamp(resolved_at, "lock.resolved_at"),
        }
