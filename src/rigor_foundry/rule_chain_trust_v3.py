# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected five-role v3 trust policy
"""Bind five original lifecycle policies to the closed v3 signature boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .models import canonical_digest, require_string
from .signed_rule_chain_v2 import RuleChainV2TrustRoles
from .verification_policy import OfflineTrustPolicy

TRUST_ROLES_V3_SCHEMA_VERSION = "3.0"
RuleObjectKindV3 = Literal[
    "standard-pack",
    "project-profile",
    "effective-profile-lock",
    "rule-corpus-author",
    "rule-corpus-acceptance",
]
SignerRoleV3 = Literal[
    "pack-issuer", "project-selector", "lock-resolver", "semantic-author", "semantic-reviewer"
]
_BOUNDARIES: dict[str, tuple[str, SignerRoleV3, str]] = {
    "standard-pack": ("3.0", "pack-issuer", "rigor-foundry.standard-pack.v3"),
    "project-profile": ("3.0", "project-selector", "rigor-foundry.project-profile-selection.v3"),
    "effective-profile-lock": ("3.0", "lock-resolver", "rigor-foundry.effective-profile-lock.v3"),
    "rule-corpus-author": ("1.0", "semantic-author", "rigor-foundry.rule-corpus-author.v3"),
    "rule-corpus-acceptance": (
        "1.0",
        "semantic-reviewer",
        "rigor-foundry.rule-corpus-acceptance.v3",
    ),
}


def rule_chain_v3_signature_boundary(
    object_kind: object,
) -> tuple[RuleObjectKindV3, str, SignerRoleV3, str]:
    """Resolve one exact signature kind, body version, signer role and domain.

    Parameters
    ----------
    object_kind : object
        One of the five supported signature kinds. Corpus authors sign the
        acceptance body under the separate ``rule-corpus-author`` kind.

    Returns
    -------
    tuple
        Kind, owning body schema version, role and domain, respectively.

    Raises
    ------
    ValueError
        The input is not a supported kind. No old-version alias is accepted.
    """
    kind = require_string(object_kind, "v3 signature object kind")
    if kind not in _BOUNDARIES:
        raise ValueError("unsupported rule-chain v3 object kind")
    version, role, domain = _BOUNDARIES[kind]
    return cast(RuleObjectKindV3, kind), version, role, domain


@dataclass(frozen=True)
class TrustRolesV3:
    """Five selected lifecycle policies and their generation-specific identity.

    The original role-policy owner enforces distinct key IDs and public keys,
    v1 nonsemantic key records, and v2 semantic records with disjoint enrolled
    author/reviewer identities. Reusing that validation never aliases signature
    domains or selects a host, enrolls a key, or ratifies a source corpus.
    """

    pack_issuers: OfflineTrustPolicy
    project_selectors: OfflineTrustPolicy
    lock_resolvers: OfflineTrustPolicy
    semantic_authors: OfflineTrustPolicy
    semantic_reviewers: OfflineTrustPolicy
    trust_roles_digest: str

    @classmethod
    def build(
        cls,
        *,
        pack_issuers: OfflineTrustPolicy,
        project_selectors: OfflineTrustPolicy,
        lock_resolvers: OfflineTrustPolicy,
        semantic_authors: OfflineTrustPolicy,
        semantic_reviewers: OfflineTrustPolicy,
    ) -> TrustRolesV3:
        """Reparse complete original policies and bind the five selected roles.

        Parameters
        ----------
        pack_issuers, project_selectors, lock_resolvers : OfflineTrustPolicy
            Exact original policies using nonsemantic v1 key records.
        semantic_authors, semantic_reviewers : OfflineTrustPolicy
            Exact original policies with enrolled, separated semantic identities.

        Returns
        -------
        TrustRolesV3
            Revalidated immutable policies and a canonical digest of schema 3.0
            plus the five named original policy digests.

        Raises
        ------
        ValueError
            A policy is malformed, inconsistent, aliased or assigned to an
            incompatible role. This operation performs no key enrollment.
        """
        items = (
            pack_issuers,
            project_selectors,
            lock_resolvers,
            semantic_authors,
            semantic_reviewers,
        )
        if any(type(item) is not OfflineTrustPolicy for item in items):
            raise ValueError("v3 trust roles require exact original offline policies")
        checked = RuleChainV2TrustRoles.build(
            pack_issuers=pack_issuers,
            project_selectors=project_selectors,
            lock_resolvers=lock_resolvers,
            semantic_authors=semantic_authors,
            semantic_reviewers=semantic_reviewers,
        )
        policies = (
            checked.pack_issuers,
            checked.project_selectors,
            checked.lock_resolvers,
            checked.semantic_authors,
            checked.semantic_reviewers,
        )
        names = (
            "pack_issuers",
            "project_selectors",
            "lock_resolvers",
            "semantic_authors",
            "semantic_reviewers",
        )
        digest = canonical_digest(
            {
                "schema_version": TRUST_ROLES_V3_SCHEMA_VERSION,
                **{
                    name: policy.policy_digest
                    for name, policy in zip(names, policies, strict=True)
                },
            }
        )
        return cls(*policies, digest)

    def policy_for(self, object_kind: RuleObjectKindV3) -> OfflineTrustPolicy:
        """Return only the selected policy for one closed signature kind.

        Parameters
        ----------
        object_kind : RuleObjectKindV3
            Exact supported signature kind, including the distinct corpus kinds.

        Returns
        -------
        OfflineTrustPolicy
            Original role policy. A caller must still verify complete roles,
            selected digest, signature bytes and both lifecycle instants.

        Raises
        ------
        ValueError
            The kind is unsupported; old semantic-kind aliases are refused.
        """
        kind, _, _, _ = rule_chain_v3_signature_boundary(object_kind)
        return {
            "standard-pack": self.pack_issuers,
            "project-profile": self.project_selectors,
            "effective-profile-lock": self.lock_resolvers,
            "rule-corpus-author": self.semantic_authors,
            "rule-corpus-acceptance": self.semantic_reviewers,
        }[kind]
