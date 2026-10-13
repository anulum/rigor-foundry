# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared selected dispatch Stage B evaluation
"""Evaluate every extracted part with the current operation's closed route boundary."""

from __future__ import annotations

from collections.abc import Callable

from .constraint_evaluators_v2 import EvaluatorContextV2
from .effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from .effect_journal_rate_v2 import EffectJournalRateSourceV2
from .selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    SelectedClauseSemanticsProofV2,
)
from .selected_dispatch_extraction_v2 import ExtractedDispatchPartV2, SelectedDispatchExtractionV2
from .selected_rule_chain_host_v2 import HostSelectedRuleChainStateV2
from .stage_b_evaluator_v2 import evaluate_stage_b_part_v2
from .stage_b_result_v2 import StageBResultV2


def evaluate_selected_stage_b_results_v3(
    extraction: SelectedDispatchExtractionV2,
    *,
    semantics: HostSelectedClauseSemanticsStateV2,
    semantics_proof: SelectedClauseSemanticsProofV2,
    context_for: Callable[[str, str], EvaluatorContextV2],
) -> tuple[StageBResultV2, ...]:
    """Evaluate all actual ordered parts without accepting stored success bodies.

    Parameters
    ----------
    extraction
        Complete selected classification, independently derived by its consumer.
        Direct instances establish no selected-extractor provenance.
    semantics, semantics_proof
        Same retained verified selected sources as the deriving operation owner.
    context_for
        Installed host constraint-context source, never a request field.

    Returns
    -------
    tuple[StageBResultV2, ...]
        Actual ordered evaluation results, never effect permission or a permit.

    Raises
    ------
    ValueError, PermissionError
        If classification is malformed or actual rules/constraints refuse.

    Notes
    -----
    The current registered first operation has no route extractor. An applicable
    route constraint refuses before context IO. This function adds no catalogue
    operation and neither reads owner permission nor changes accounting.
    """
    if type(extraction) is not SelectedDispatchExtractionV2 or (
        type(extraction.parts) is not tuple
        or not extraction.parts
        or any(type(part) is not ExtractedDispatchPartV2 for part in extraction.parts)
        or tuple(part.part_index for part in extraction.parts)
        != tuple(range(len(extraction.parts)))
    ):
        raise ValueError("selected Stage B requires complete exact ordered classification")

    results: list[StageBResultV2] = []
    for part in extraction.parts:
        installed_context = (
            context_for.for_part(semantics, part)
            if isinstance(context_for, EffectJournalRateSourceV2)
            else context_for
        )

        def context_for_operation(
            clause_digest: str,
            subject: str,
            installed: Callable[[str, str], EvaluatorContextV2] = installed_context,
        ) -> EvaluatorContextV2:
            """Preserve the installed first operation's refusing null-route boundary.

            Parameters
            ----------
            clause_digest, subject
                Current applicable clause and fixed constraint subject.
            installed
                Part-bound installed reader captured for this iteration.

            Returns
            -------
            EvaluatorContextV2
                Actual installed non-route evidence context.

            Raises
            ------
            PermissionError
                Route evaluation lacks a registered operation-specific extractor.
            """
            if subject == "route":
                raise PermissionError("route constraint requires a registered route extractor")
            return installed(clause_digest, subject)

        results.append(
            evaluate_stage_b_part_v2(
                selected=semantics,
                proof=semantics_proof,
                part_index=part.part_index,
                effect_class=part.effect_class,
                target_kind=part.target_kind,
                target_ref=part.target_ref,
                context_for=context_for_operation,
            )
        )
    return tuple(results)


def derive_selected_stage_b_pins_v3(
    chain: HostSelectedRuleChainStateV2,
    extraction: SelectedDispatchExtractionV2,
    *,
    semantics: HostSelectedClauseSemanticsStateV2,
    semantics_proof: SelectedClauseSemanticsProofV2,
) -> dict[str, str]:
    """Return actual source expectations shared by deriving and comparing consumers.

    Parameters
    ----------
    chain, extraction, semantics, semantics_proof
        Same retained source leases and actual extracted catalogue identity.
        Direct dataclasses authenticate no custody or native source authority.

    Returns
    -------
    dict[str, str]
        Actual selected source identities; no physical pin is inferred.

    Raises
    ------
    PermissionError
        If an expected authority requirement lacks its actual selected binding.
    """
    selected_pins: dict[str, str] = {
        "expected_effect_vocabulary_digest": chain.effect_vocabulary.vocabulary_digest,
        "expected_effect_target_table_digest": chain.effect_target_table.table_digest,
        "expected_effect_operations_digest": extraction.effect_operations_digest,
        "extractor_registry_digest": chain.extractor_registry.registry_digest,
        "expected_evaluator_registry_digest": semantics.evaluator_registry.registry_digest,
        "expected_semantics_set_digest": semantics.expected_semantics_set_digest,
        "expected_resolver_version": semantics.expected_resolver_version,
    }
    if semantics.expected_authority_requirement_digest is not None:
        requirement = semantics.authority_requirement
        expected = semantics.expected_authority_requirement_digest
        if (
            type(requirement) is not EffectClassAuthorityRequirementV2
            or EffectClassAuthorityRequirementV2.from_bytes(requirement.body_bytes) != requirement
            or requirement.requirement_digest != expected
            or semantics_proof.binding.authority_requirement_digest != expected
        ):
            raise PermissionError("selected Stage B authority requirement is not source-bound")
        selected_pins["expected_authority_requirement_digest"] = expected
    return selected_pins
