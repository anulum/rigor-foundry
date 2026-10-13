# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected clause-semantics binding
"""Bind a dual-signed semantics body to every selected successor clause."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from .clause_semantics_scope_v2 import bind_clause_scope_groups_v2
from .constraint_evaluator_registry_v2 import ConstraintEvaluatorRegistryV2
from .effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from .effect_target_table_v2 import EffectTargetTableV2
from .effect_vocabulary_v2 import EffectVocabularyV2
from .models import canonical_digest
from .owner_confirmation_v2 import OwnerConfirmationRecordV2, verify_owner_confirmation_v2
from .project_registry_models import ProjectRegistry
from .rule_chain_pack_v2 import AuthorityClauseV2
from .signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2
from .signed_rule_chain_v2 import RuleChainV2TrustRoles


@dataclass(frozen=True)
class ClauseSemanticsBindingV2:
    """Authenticated reference bindings, without operational admission.

    Attributes
    ----------
    semantics_set_digest : str
        Exact authenticated canonical semantics body.
    successor_clause_digests : tuple[str, ...]
        Host-selected successors in their declared order.
    active_admit_clause_digests : tuple[str, ...]
        Sorted admits not superseded by another admit; applicability is untested.
    authority_requirement_digest, owner_confirmation_digest : str or None
        Rechecked owner-confirmation dependencies when a precondition exists.
    """

    semantics_set_digest: str
    successor_clause_digests: tuple[str, ...]
    active_admit_clause_digests: tuple[str, ...]
    authority_requirement_digest: str | None
    owner_confirmation_digest: str | None

    @property
    def guard_admissible(self) -> Literal[False]:
        """Return false because this reference proof grants no execution authority."""
        return False


def bind_clause_semantics_v2(
    *,
    signed: SignedClauseSemanticsSetV2,
    roles: RuleChainV2TrustRoles,
    now: datetime,
    expected_semantics_set_digest: str,
    clauses: tuple[AuthorityClauseV2, ...],
    predecessor_acceptance_digest: str,
    rule_projection_digest: str,
    successor_clause_digests: tuple[str, ...],
    project_id: str,
    registry: ProjectRegistry,
    expected_registry_sha256: str,
    scope_digest: str,
    effect_vocabulary_digest: str,
    vocabulary: EffectVocabularyV2,
    effect_target_table_digest: str,
    target_table: EffectTargetTableV2,
    evaluator_registry_digest: str,
    evaluator_registry: ConstraintEvaluatorRegistryV2,
    resolver_version: str,
    authority_requirement: EffectClassAuthorityRequirementV2 | None = None,
    expected_authority_requirement_digest: str | None = None,
    owner_confirmation: OwnerConfirmationRecordV2 | None = None,
    expected_owner_confirmation_digest: str | None = None,
    confirmation_manifest: bytes | None = None,
    confirmation_question: bytes | None = None,
    confirmation_reply: bytes | None = None,
) -> ClauseSemanticsBindingV2:
    """Bind every selected clause to authenticated canonical semantics.

    Parameters
    ----------
    signed : SignedClauseSemanticsSetV2
        Exact body and separate author/reviewer signatures to reverify.
    roles : RuleChainV2TrustRoles
        Selected current key policies for the five signing roles.
    now : datetime
        Explicit UTC instant used for current signature eligibility.
    expected_semantics_set_digest : str
        Host-selected body identity.
    clauses : tuple[AuthorityClauseV2, ...]
        Complete selected authority clauses; pack/source verification is upstream.
    predecessor_acceptance_digest, rule_projection_digest : str
        Selected predecessor and rule-projection identities.
    successor_clause_digests : tuple[str, ...]
        Ordered selected successor subset of the complete authority clauses.
    project_id : str
        Active project identifier in the selected registry.
    registry : ProjectRegistry
        Complete registry generation, revalidated against its serialized bytes.
    expected_registry_sha256 : str
        Host-selected registry identity.
    scope_digest : str
        Selected chain scope identity.
    effect_vocabulary_digest, effect_target_table_digest : str
        Host-selected fixed effect mappings.
    vocabulary : EffectVocabularyV2
        Fixed effect vocabulary to revalidate.
    target_table : EffectTargetTableV2
        Fixed target mapping to revalidate; concrete applicability is downstream.
    evaluator_registry_digest : str
        Host-selected fixed evaluator-identifier mapping.
    evaluator_registry : ConstraintEvaluatorRegistryV2
        Fixed evaluator registry; measured evaluator code is selected separately.
    resolver_version : str
        Exact declared resolver identifier.
    authority_requirement : EffectClassAuthorityRequirementV2 or None
        Selected requirement list, mandatory if any entry is a precondition.
    expected_authority_requirement_digest : str or None
        Host-selected requirement identity.
    owner_confirmation : OwnerConfirmationRecordV2 or None
        Selected retained confirmation record for that exact requirement.
    expected_owner_confirmation_digest : str or None
        Host-selected confirmation identity.
    confirmation_manifest, confirmation_question, confirmation_reply : bytes or None
        Retained captures mandatory for preconditions; native files are rechecked.

    Returns
    -------
    ClauseSemanticsBindingV2
        Immutable reference proof with ``guard_admissible`` always false.

    Raises
    ------
    PermissionError
        Authentication, selection, completeness, scope or supersession differs.
    ValueError
        A selected object or retained capture is malformed.
    OSError
        A retained transcript cannot be read safely.

    Notes
    -----
    All selection inputs require protected host custody. Caller-selected pins
    prove only their supplied relation. This API does not verify pack sources,
    ratify the chain, evaluate constraints or authorize an effect.
    """
    if not signed.verify(roles=roles, now=now):
        raise PermissionError("clause semantics signatures no longer verify")
    if signed.body.body_digest != expected_semantics_set_digest:
        raise PermissionError("clause semantics differs from protected selected digest")
    if (
        ProjectRegistry.from_bytes(registry.to_bytes()) != registry
        or registry.registry_sha256 != expected_registry_sha256
    ):
        raise PermissionError("project registry differs from protected selected generation")
    selected_project = next(
        (
            item
            for item in registry.projects
            if item.project_id == project_id and item.lifecycle_state == "active"
        ),
        None,
    )
    if selected_project is None:
        raise PermissionError("semantics project is not active in selected registry")
    owning_group_id = selected_project.owning_group_id
    registered_group_ids = frozenset(
        item.group_id for item in registry.groups if item.lifecycle_state == "active"
    )
    if owning_group_id not in registered_group_ids:
        raise PermissionError("semantics owning group is absent from selected registry")
    if (
        EffectVocabularyV2.from_bytes(vocabulary.body_bytes) != vocabulary
        or vocabulary.vocabulary_digest != effect_vocabulary_digest
    ):
        raise PermissionError("effect vocabulary differs from protected selection")
    if (
        EffectTargetTableV2.from_bytes(target_table.body_bytes) != target_table
        or target_table.table_digest != effect_target_table_digest
    ):
        raise PermissionError("effect target table differs from protected selection")
    if (
        ConstraintEvaluatorRegistryV2.from_bytes(evaluator_registry.body_bytes)
        != evaluator_registry
        or evaluator_registry.registry_digest != evaluator_registry_digest
    ):
        raise PermissionError("evaluator registry differs from protected selection")
    body = signed.body.to_dict()
    expected = {
        "predecessor_acceptance_digest": predecessor_acceptance_digest,
        "rule_projection_digest": rule_projection_digest,
        "successor_clause_digests": list(successor_clause_digests),
        "project_id": project_id,
        "scope_digest": scope_digest,
        "effect_vocabulary_digest": effect_vocabulary_digest,
        "effect_target_table_digest": effect_target_table_digest,
        "evaluator_registry_digest": evaluator_registry_digest,
        "resolver_version": resolver_version,
    }
    if any(body[field] != value for field, value in expected.items()):
        raise PermissionError("clause semantics differs from selected chain or host pins")
    exact_clauses = tuple(AuthorityClauseV2.from_dict(item.to_dict()) for item in clauses)
    if exact_clauses != clauses or len({item.clause_digest for item in clauses}) != len(clauses):
        raise PermissionError("selected authority clause list differs")
    by_digest = {item.clause_digest: item for item in clauses}
    if not set(successor_clause_digests).issubset(by_digest):
        raise PermissionError("selected successor clause is absent from authority clauses")
    entries = cast(list[dict[str, object]], body["entries"])
    selected_authority_requirement_digest: str | None = None
    selected_owner_confirmation_digest: str | None = None
    if any(entry["subject"] == "precondition" for entry in entries):
        if (
            authority_requirement is None
            or expected_authority_requirement_digest is None
            or owner_confirmation is None
            or expected_owner_confirmation_digest is None
            or confirmation_manifest is None
            or confirmation_question is None
            or confirmation_reply is None
        ):
            raise PermissionError("precondition owner confirmation is not selected")
        try:
            proof = verify_owner_confirmation_v2(
                record=owner_confirmation,
                requirement=authority_requirement,
                manifest_bytes=confirmation_manifest,
                question_capture=confirmation_question,
                reply_capture=confirmation_reply,
                expected_authority_requirement_digest=expected_authority_requirement_digest,
                expected_owner_confirmation_digest=expected_owner_confirmation_digest,
            )
        except ValueError as exc:
            raise PermissionError("precondition owner confirmation differs") from exc
        selected_authority_requirement_digest = cast(str, proof["authority_requirement_digest"])
        selected_owner_confirmation_digest = cast(str, proof["owner_confirmation_digest"])
    if {cast(str, entry["clause_digest"]) for entry in entries} != set(by_digest):
        raise PermissionError("clause semantics does not cover every selected clause")
    admits: dict[str, tuple[str, ...]] = {}
    for entry in entries:
        digest = cast(str, entry["clause_digest"])
        clause = by_digest[digest]
        bind_clause_scope_groups_v2(
            cast(dict[str, object], entry["scope"]),
            owning_group_id=owning_group_id,
            registered_group_ids=registered_group_ids,
        )
        if (
            entry["statement_digest"] != clause.statement_digest
            or entry["successor_id"] != clause.successor_id
            or entry["effect_class"] != clause.effect_class
            or not vocabulary.contains(clause.effect_class)
            or canonical_digest(entry["scope"]) != clause.scope_selector_digest
        ):
            raise PermissionError("clause semantics entry differs from its selected clause")
        subject = cast(str, entry["subject"])
        if subject == "admit":
            admits[digest] = tuple(cast(list[str], entry["supersedes"]))
    # Count each edge once, including shared ancestors in a diamond graph.
    remaining = {digest: len(edges) for digest, edges in admits.items()}
    dependants: dict[str, list[str]] = {digest: [] for digest in admits}
    for digest, edges in admits.items():
        if any(edge not in admits for edge in edges):
            raise PermissionError("clause semantics supersedes a veto or constraint")
        for edge in edges:
            dependants[edge].append(digest)
    frontier = deque(digest for digest, count in remaining.items() if count == 0)
    visited = 0
    while frontier:
        visited += 1
        for digest in dependants[frontier.popleft()]:
            remaining[digest] -= 1
            if remaining[digest] == 0:
                frontier.append(digest)
    if visited != len(admits):
        raise PermissionError("clause semantics supersession cycle differs")
    superseded = {edge for edges in admits.values() for edge in edges}
    active = tuple(sorted(set(admits) - superseded))
    return ClauseSemanticsBindingV2(
        signed.body.body_digest,
        successor_clause_digests,
        active,
        selected_authority_requirement_digest,
        selected_owner_confirmation_digest,
    )
