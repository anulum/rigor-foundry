# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected Stage B clause composition
"""Compose B1 admits, B2 vetoes and B4 constraints for one extracted part."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from .clause_scope_registry_expansion_v2 import expand_clause_scope_v2
from .clause_selector_match_v2 import match_clause_selector_v2
from .constraint_evaluation_boundary_v2 import evaluate_selected_constraint_v2
from .constraint_evaluators_v2 import EvaluatorContextV2
from .effect_journal_records_v2 import parse_effect_target_ref_v2
from .effect_target_table_v2 import EffectTargetTableV2
from .model_primitives import require_digest
from .models import canonical_digest
from .selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    SelectedClauseSemanticsProofV2,
)
from .stage_b_result_v2 import STAGE_B_RESULT_SCHEMA_V2, StageBResultV2


def evaluate_stage_b_part_v2(
    *,
    selected: HostSelectedClauseSemanticsStateV2,
    proof: SelectedClauseSemanticsProofV2,
    part_index: int,
    effect_class: str,
    target_kind: str,
    target_ref: dict[str, str],
    context_for: Callable[[str, str], EvaluatorContextV2],
) -> StageBResultV2:
    """Evaluate one host-extracted part inside a verified selection lease.

    Parameters
    ----------
    selected, proof
        Matching semantics and proof retained inside the actual verified host context.
    part_index
        Nonnegative index assigned by actual request extraction.
    effect_class, target_kind, target_ref
        Independently extracted action classification and canonical target mapping.
    context_for
        Installed reader of fresh contexts for applicable fixed constraints.

    Returns
    -------
    StageBResultV2
        Canonical admitted part after active covering admits, veto checks and
        every applicable constraint; no stored success result is consumed.

    Raises
    ------
    ValueError
        Part index, target, scope or canonical result structure is malformed.
    PermissionError
        Selected target table, proof, registry, scope, admit, veto or constraint refuses.

    Notes
    -----
    The installed owner supplies these values while holding the complete
    selected lease. Caller-built records or successful applicability establish
    no effect permission, protected custody or handler capability.
    """
    if type(part_index) is not int or part_index < 0:
        raise ValueError("Stage B part index differs")
    form, value = parse_effect_target_ref_v2(target_ref)
    if EffectTargetTableV2.from_bytes(
        selected.target_table.body_bytes
    ) != selected.target_table or not selected.target_table.allows(
        effect_class, target_kind, form
    ):
        raise PermissionError("Stage B extracted target triple differs from selected table")
    body = selected.signed.body.to_dict()
    if (
        selected.signed.body.body_digest != selected.expected_semantics_set_digest
        or proof.binding.semantics_set_digest != selected.expected_semantics_set_digest
        or proof.registry_generation_id != selected.registry.generation_id
        or proof.registry_sha256 != selected.expected_registry_sha256
        or selected.registry.registry_sha256 != selected.expected_registry_sha256
    ):
        raise PermissionError("Stage B semantics or registry differs from selected proof")
    entries = cast(list[dict[str, object]], body["entries"])
    expanded_proof: list[dict[str, object]] = []
    applicable: list[dict[str, object]] = []
    for entry in entries:
        subject = cast(str, entry["subject"])
        entry_class = cast(str, entry["effect_class"])
        scope = expand_clause_scope_v2(
            scope=cast(dict[str, object], entry["scope"]),
            subject=subject,
            effect_class=entry_class,
            project_id=cast(str, body["project_id"]),
            registry=selected.registry,
            expected_registry_sha256=selected.expected_registry_sha256,
            monorepo_root=selected.monorepo_root,
            resolver_version=selected.expected_resolver_version,
        )
        expanded_proof.append(
            {
                "clause_digest": entry["clause_digest"],
                "targets": list(scope.targets),
                "exclusions": list(scope.exclusions),
            }
        )
        if entry_class != effect_class:
            continue

        def matches(selector: str, *, exclusion: bool, checked_subject: str = subject) -> bool:
            """Compare a concrete scope selector with the extracted part.

            Parameters
            ----------
            selector, exclusion
                Concrete expanded target/exclusion and its grammar role.
            checked_subject
                Current clause subject captured before the next loop iteration.

            Returns
            -------
            bool
                Exact coverage result from the selected target table and matcher.

            Raises
            ------
            ValueError, PermissionError
                Concrete grammar or the selected target triple refuses.
            """
            return match_clause_selector_v2(
                selector=selector,
                subject=checked_subject,
                exclusion=exclusion,
                effect_class=effect_class,
                project_id=cast(str, body["project_id"]),
                target_kind=target_kind,
                target_form=form,
                target_value=value,
                target_table=selected.target_table,
            )

        covers = any(matches(item, exclusion=False) for item in scope.targets)
        excluded = any(matches(item, exclusion=True) for item in scope.exclusions)
        if covers and not excluded:
            applicable.append(entry)
    expansion_digest = canonical_digest(
        {
            "schema": "rigor.selected-clause-scope-expansion.v2",
            "registry_generation_id": selected.registry.generation_id,
            "registry_sha256": selected.registry.registry_sha256,
            "entries": expanded_proof,
        }
    )
    if expansion_digest != proof.scope_expansion_digest:
        raise PermissionError("Stage B scope expansion differs from selected proof")
    active = set(proof.binding.active_admit_clause_digests)
    admitted = sorted(
        entry["clause_digest"]
        for entry in applicable
        if entry["subject"] == "admit" and entry["clause_digest"] in active
    )
    if not admitted:
        raise PermissionError("Stage B has no active covering admit clause")
    if any(entry["subject"] == "veto" for entry in applicable):
        raise PermissionError("Stage B covering veto refuses")
    constraints: list[dict[str, str]] = []
    for entry in applicable:
        subject = cast(str, entry["subject"])
        if subject in {"admit", "veto"}:
            continue
        digest = require_digest(entry["clause_digest"], "Stage B clause")
        try:
            context = context_for(digest, subject)
        except Exception as exc:
            raise PermissionError("Stage B constraint context is unavailable") from exc
        decision = evaluate_selected_constraint_v2(
            subject=subject,
            effect_class=effect_class,
            ctx=context,
            params=cast(dict[str, object], entry["params"]),
            authority_requirement=selected.authority_requirement,
            selected_authority_requirement_digest=proof.binding.authority_requirement_digest,
        )
        if decision.outcome != "pass":
            raise PermissionError("Stage B applicable constraint refuses")
        evaluator = cast(dict[str, str], entry["evaluator"])
        constraints.append(
            {
                "clause_digest": digest,
                "subject": subject,
                "evaluator_id": evaluator["id"],
                "result": "pass",
            }
        )
    constraints.sort(key=lambda item: item["clause_digest"])
    return StageBResultV2.from_dict(
        {
            "schema": STAGE_B_RESULT_SCHEMA_V2,
            "part_index": part_index,
            "outcome": "admit",
            "effect_class": effect_class,
            "target_ref": target_ref,
            "admitting_clause_digests": admitted,
            "constraint_results": constraints,
            "semantics_set_digest": selected.expected_semantics_set_digest,
            "scope_expansion_digest": expansion_digest,
        }
    )
