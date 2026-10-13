# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected selected clause-semantics verification
"""Recheck signed, owner-ratified semantics inside the selected chain lease."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .clause_scope_registry_expansion_v2 import expand_clause_scope_v2
from .clause_semantics_binding_v2 import ClauseSemanticsBindingV2, bind_clause_semantics_v2
from .clause_semantics_ratification_v2 import verify_clause_semantics_ratification_v2
from .constraint_evaluator_registry_v2 import ConstraintEvaluatorRegistryV2
from .effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from .effect_target_table_v2 import EffectTargetTableV2
from .effect_vocabulary_v2 import EffectVocabularyV2
from .models import canonical_digest
from .owner_confirmation_v2 import OwnerConfirmationRecordV2
from .project_registry_models import ProjectRegistry
from .selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    HostSelectedRuleChainVerifierV2,
    SelectedRuleChainProofV2,
)
from .signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2


@dataclass(frozen=True)
class HostSelectedClauseSemanticsStateV2:
    """Protected semantics selection and native owner evidence for one chain lease.

    Attributes
    ----------
    chain : HostSelectedRuleChainVerifierV2
        Host verifier for the same selected signed rule-chain lease.
    signed : SignedClauseSemanticsSetV2
        Exact dual-signed canonical semantics set.
    registry : ProjectRegistry
        Exact selected current project registry.
    vocabulary : EffectVocabularyV2
        Exact reviewed effect vocabulary.
    target_table : EffectTargetTableV2
        Exact reviewed target-kind table.
    evaluator_registry : ConstraintEvaluatorRegistryV2
        Exact sealed evaluator identities.
    monorepo_root : Path
        Canonical deployment root used for current selector expansion.
    expected_semantics_set_digest : str
        Protected semantics body precondition.
    expected_registry_sha256 : str
        Protected registry generation body precondition.
    expected_effect_vocabulary_digest : str
        Protected vocabulary body precondition.
    expected_effect_target_table_digest : str
        Protected target-table body precondition.
    expected_evaluator_registry_digest : str
        Protected evaluator registry body precondition.
    expected_resolver_version : str
        Protected scope-resolver identifier.
    ratification_manifest : bytes
        Exact selected native semantics ratification manifest bytes.
    ratification_question : bytes
        Exact full rendered semantics owner question bytes.
    ratification_reply : bytes
        Exact selected native human owner approval bytes.
    ratification_transcript_path : Path
        Protected original native transcript path.
    expected_ratification_manifest_sha256 : str
        Protected manifest hash precondition.
    expected_ratification_question_sha256 : str
        Protected question capture hash precondition.
    expected_ratification_reply_sha256 : str
        Protected reply capture hash precondition.
    authority_requirement : EffectClassAuthorityRequirementV2 | None
        Optional selected per-effect authority requirement proposal.
    expected_authority_requirement_digest : str | None
        Protected requirement precondition when supplied.
    owner_confirmation : OwnerConfirmationRecordV2 | None
        Optional owner confirmation for that exact requirement.
    expected_owner_confirmation_digest : str | None
        Protected confirmation precondition when supplied.
    confirmation_manifest : bytes | None
        Selected native confirmation manifest when confirmation is supplied.
    confirmation_question : bytes | None
        Selected exact requirement confirmation question capture.
    confirmation_reply : bytes | None
        Selected exact native human confirmation reply capture.
    revalidate : Callable[[], None]
        Host callback refusing changed selected custody or revocations.

    Notes
    -----
    All nested chain and semantics objects must remain pinned for the entire lease. Fixture
    providers and digest-bound caller files do not authenticate protected installation or owner
    custody.
    """

    chain: HostSelectedRuleChainVerifierV2
    signed: SignedClauseSemanticsSetV2
    registry: ProjectRegistry
    vocabulary: EffectVocabularyV2
    target_table: EffectTargetTableV2
    evaluator_registry: ConstraintEvaluatorRegistryV2
    monorepo_root: Path
    expected_semantics_set_digest: str
    expected_registry_sha256: str
    expected_effect_vocabulary_digest: str
    expected_effect_target_table_digest: str
    expected_evaluator_registry_digest: str
    expected_resolver_version: str
    ratification_manifest: bytes
    ratification_question: bytes
    ratification_reply: bytes
    ratification_transcript_path: Path
    expected_ratification_manifest_sha256: str
    expected_ratification_question_sha256: str
    expected_ratification_reply_sha256: str
    authority_requirement: EffectClassAuthorityRequirementV2 | None
    expected_authority_requirement_digest: str | None
    owner_confirmation: OwnerConfirmationRecordV2 | None
    expected_owner_confirmation_digest: str | None
    confirmation_manifest: bytes | None
    confirmation_question: bytes | None
    confirmation_reply: bytes | None
    revalidate: Callable[[], None]


@dataclass(frozen=True)
class SelectedClauseSemanticsProofV2:
    """Read-only semantics and ratification evidence for the selected chain.

    Attributes
    ----------
    chain : SelectedRuleChainProofV2
        Fresh read-only selected rule-chain proof.
    binding : ClauseSemanticsBindingV2
        Verified signed semantics-to-clause and role binding.
    ratification_proof_digest : str
        Exact rendered native human semantics approval dependency digest.
    scope_expansion_digest : str
        Canonical digest of each clause's expanded targets and exclusions.
    registry_generation_id : str
        Current selected registry generation.
    registry_sha256 : str
        Exact selected registry body digest.

    Notes
    -----
    This proof grants no action applicability, permit or effect authority.
    """

    chain: SelectedRuleChainProofV2
    binding: ClauseSemanticsBindingV2
    ratification_proof_digest: str
    scope_expansion_digest: str
    registry_generation_id: str
    registry_sha256: str


def _verify_selected(
    selected: HostSelectedClauseSemanticsStateV2,
    chain_state: HostSelectedRuleChainStateV2,
    chain_proof: SelectedRuleChainProofV2,
) -> SelectedClauseSemanticsProofV2:
    """Recheck all selected bytes against the same pinned chain and clock."""
    selected.revalidate()
    binding = bind_clause_semantics_v2(
        signed=selected.signed,
        roles=chain_state.roles,
        now=chain_state.clock(),
        expected_semantics_set_digest=selected.expected_semantics_set_digest,
        clauses=chain_state.lock.authority_clauses,
        predecessor_acceptance_digest=chain_proof.acceptance_digest,
        rule_projection_digest=chain_proof.rule_projection_digest,
        successor_clause_digests=chain_proof.successor_clause_digests,
        project_id=chain_state.profile.project_id,
        registry=selected.registry,
        expected_registry_sha256=selected.expected_registry_sha256,
        scope_digest=chain_state.profile.selector_scope_digest,
        effect_vocabulary_digest=selected.expected_effect_vocabulary_digest,
        vocabulary=selected.vocabulary,
        effect_target_table_digest=selected.expected_effect_target_table_digest,
        target_table=selected.target_table,
        evaluator_registry_digest=selected.expected_evaluator_registry_digest,
        evaluator_registry=selected.evaluator_registry,
        resolver_version=selected.expected_resolver_version,
        authority_requirement=selected.authority_requirement,
        expected_authority_requirement_digest=selected.expected_authority_requirement_digest,
        owner_confirmation=selected.owner_confirmation,
        expected_owner_confirmation_digest=selected.expected_owner_confirmation_digest,
        confirmation_manifest=selected.confirmation_manifest,
        confirmation_question=selected.confirmation_question,
        confirmation_reply=selected.confirmation_reply,
    )
    ratification = verify_clause_semantics_ratification_v2(
        body=selected.signed.body,
        manifest_bytes=selected.ratification_manifest,
        question_capture=selected.ratification_question,
        reply_capture=selected.ratification_reply,
        transcript_path=selected.ratification_transcript_path,
        expected_manifest_sha256=selected.expected_ratification_manifest_sha256,
        expected_question_sha256=selected.expected_ratification_question_sha256,
        expected_reply_sha256=selected.expected_ratification_reply_sha256,
    )
    entries = cast(list[dict[str, object]], selected.signed.body.to_dict()["entries"])
    scopes: list[dict[str, object]] = []
    for entry in entries:
        expanded = expand_clause_scope_v2(
            scope=cast(dict[str, object], entry["scope"]),
            subject=cast(str, entry["subject"]),
            effect_class=cast(str, entry["effect_class"]),
            project_id=chain_state.profile.project_id,
            registry=selected.registry,
            expected_registry_sha256=selected.expected_registry_sha256,
            monorepo_root=selected.monorepo_root,
            resolver_version=selected.expected_resolver_version,
        )
        scopes.append(
            {
                "clause_digest": entry["clause_digest"],
                "targets": list(expanded.targets),
                "exclusions": list(expanded.exclusions),
            }
        )
    scope_expansion_digest = canonical_digest(
        {
            "schema": "rigor.selected-clause-scope-expansion.v2",
            "registry_generation_id": selected.registry.generation_id,
            "registry_sha256": selected.registry.registry_sha256,
            "entries": scopes,
        }
    )
    selected.revalidate()
    return SelectedClauseSemanticsProofV2(
        chain_proof,
        binding,
        str(ratification["proof_digest"]),
        scope_expansion_digest,
        selected.registry.generation_id,
        selected.registry.registry_sha256,
    )


@dataclass(frozen=True)
class HostSelectedClauseSemanticsVerifierV2:
    """Verify signed semantics and owner ratification inside the selected chain lease.

    Attributes
    ----------
    state : Callable[[], AbstractContextManager[HostSelectedClauseSemanticsStateV2]]
        Protected callable yielding a pinned semantics state in a context manager.

    Notes
    -----
    Consumers still verify concrete action applicability, authority, permits, journal and handler
    custody through their own protected path.
    """

    state: Callable[[], AbstractContextManager[HostSelectedClauseSemanticsStateV2]]

    @contextmanager
    def verified_lease(
        self,
    ) -> Iterator[tuple[HostSelectedClauseSemanticsStateV2, SelectedClauseSemanticsProofV2]]:
        """Repeat chain, semantics and owner evidence checks after the consumer.

        Yields
        ------
        tuple[HostSelectedClauseSemanticsStateV2, SelectedClauseSemanticsProofV2]
            Pinned selected semantics state and initial read-only proof for use inside the context.

        Raises
        ------
        ValueError
            A signed body, registry, native capture or selected digest is malformed.
        PermissionError
            An initial or final chain, semantics, source, role, selection or owner approval check
            differs.
        OSError
            A selected native source or no-follow deployment root cannot be opened.
        RuntimeError
            A provider suppresses a failure without completing the lease.

        Notes
        -----
        The same pinned chain state is rechecked. The context supplies proof, while the protected effect
        path supplies action-specific authorization.
        """
        with self.verified_context() as (selected, _chain_state, proof):
            yield selected, proof

    @contextmanager
    def verified_context(
        self,
    ) -> Iterator[
        tuple[
            HostSelectedClauseSemanticsStateV2,
            HostSelectedRuleChainStateV2,
            SelectedClauseSemanticsProofV2,
        ]
    ]:
        """Expose the actual chain state held by the complete semantics lease.

        Yields
        ------
        tuple[HostSelectedClauseSemanticsStateV2, HostSelectedRuleChainStateV2, SelectedClauseSemanticsProofV2]
            Pinned semantics, the same held chain used for verification, and their read-only proof.
            Consumers use these values only while this context remains open.

        Raises
        ------
        ValueError
            A signed body, registry, native capture or selected digest is malformed.
        PermissionError
            Initial verification or closing source, role, selection or proof checks refuse.
        OSError
            A retained source or deployment root cannot be safely opened.
        RuntimeError
            A provider suppresses a failure without completing the lease.

        Notes
        -----
        This acquires each protected state provider once. It permits composed consumers to use the
        already held chain rather than reentering its provider. It creates no effect authority.
        """
        completed = False
        with self.state() as selected:
            if not isinstance(selected, HostSelectedClauseSemanticsStateV2):
                raise PermissionError("selected clause semantics host state is unavailable")
            with selected.chain.verified_lease() as (chain_state, chain_proof):
                proof = _verify_selected(selected, chain_state, chain_proof)
                yield selected, chain_state, proof
                selected.revalidate()
                final_chain = HostSelectedRuleChainVerifierV2(
                    lambda: nullcontext(chain_state)
                ).verify()
                if _verify_selected(selected, chain_state, final_chain) != proof:
                    raise PermissionError("selected clause semantics changed during lease")
                completed = True
        if not completed:
            raise RuntimeError("selected clause semantics host lease suppressed a failure")

    def verify(self) -> SelectedClauseSemanticsProofV2:
        """Verify one complete read-only lease, including its closing checks.

        Returns
        -------
        SelectedClauseSemanticsProofV2
            Selected chain and semantics proof after the lease closes successfully.

        Raises
        ------
        ValueError
            Canonical input or native capture validation fails.
        PermissionError
            Selected source, role, ratification or lease revalidation refuses.
        OSError
            A required selected source or deployment root cannot be safely read.
        RuntimeError
            A provider suppresses a lease failure.
        """
        with self.verified_lease() as (_, selected_proof):
            return selected_proof
