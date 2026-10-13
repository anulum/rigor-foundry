# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected Stage-B constraint evaluation boundary
"""Apply result polarity and selected K6 authority around fixed evaluators."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from .constraint_evaluators_v2 import (
    EvaluatorContextV2,
    EvaluatorResultV2,
    PreconditionContextV2,
    evaluate_builtin_constraint_v2,
)
from .effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from .effect_vocabulary_v2 import EFFECT_CLASSES_V2

_REFUSAL_REASONS: Final = {
    "rate": frozenset({"context-invalid", "params-invalid", "rate-cap", "rate-limit"}),
    "window": frozenset({"context-invalid", "params-invalid", "window-outside"}),
    "route": frozenset(
        {"context-invalid", "params-invalid", "route-mismatch", "route-over-ceiling"}
    ),
    "precondition": frozenset({"context-invalid", "params-invalid", "precondition-failed"}),
}


@dataclass(frozen=True)
class ConstraintDecisionV2:
    """One closed Stage-B constraint outcome for the selected action.

    Attributes
    ----------
    outcome : Literal["pass", "refuse"]
        Result after evaluator polarity and selected authority checks.
    reason : str
        Evaluator refusal or boundary failure classification; ``passed`` only
        accompanies an accepted fixed evaluator result.
    """

    outcome: Literal["pass", "refuse"]
    reason: str


def evaluate_selected_constraint_v2(
    *,
    subject: str,
    effect_class: str,
    ctx: EvaluatorContextV2,
    params: Mapping[str, object],
    authority_requirement: EffectClassAuthorityRequirementV2 | None,
    selected_authority_requirement_digest: str | None,
) -> ConstraintDecisionV2:
    """Refuse malformed evaluator output and cooperative K6 for listed classes.

    Parameters
    ----------
    subject, effect_class
        Supported constraint subject and actual extracted action class.
    ctx
        Installed host evidence context for that subject, never request data.
    params
        Selected clause's canonical closed evaluator parameters.
    authority_requirement
        Exact selected per-effect requirement, mandatory for preconditions.
    selected_authority_requirement_digest
        Expected digest bound by the verified selected semantics proof.

    Returns
    -------
    ConstraintDecisionV2
        Pass only for the fixed evaluator's exact success polarity. Malformed
        results, evaluator exceptions and missing or conflicting authority refuse.

    Notes
    -----
    A cooperative precondition cannot satisfy an enforced-required class.
    The protected host authenticates contexts and requirement custody; this
    calculation supplies neither effect authority nor protected installation.
    """
    if subject not in _REFUSAL_REASONS or effect_class not in EFFECT_CLASSES_V2:
        return ConstraintDecisionV2("refuse", "context-invalid")
    if subject == "precondition":
        if not isinstance(ctx, PreconditionContextV2):
            return ConstraintDecisionV2("refuse", "context-invalid")
        if authority_requirement is None or selected_authority_requirement_digest is None:
            return ConstraintDecisionV2("refuse", "authority-requirement-invalid")
        try:
            exact_requirement = EffectClassAuthorityRequirementV2.from_bytes(
                authority_requirement.body_bytes
            )
        except ValueError:
            return ConstraintDecisionV2("refuse", "authority-requirement-invalid")
        if (
            exact_requirement != authority_requirement
            or exact_requirement.requirement_digest != selected_authority_requirement_digest
        ):
            return ConstraintDecisionV2("refuse", "authority-requirement-invalid")
        if ctx.enforcement_class == "cooperative" and exact_requirement.requires_enforced(
            effect_class
        ):
            return ConstraintDecisionV2("refuse", "cooperative-precondition-for-enforced-class")
    try:
        result = evaluate_builtin_constraint_v2(subject, ctx, params)
    except Exception:
        return ConstraintDecisionV2("refuse", "evaluator-error")
    if type(result) is not EvaluatorResultV2:
        return ConstraintDecisionV2("refuse", "evaluator-result-invalid")
    if result.outcome == "pass" and result.reason == "passed":
        return ConstraintDecisionV2("pass", "passed")
    if result.outcome == "refuse" and result.reason in _REFUSAL_REASONS[subject]:
        return ConstraintDecisionV2("refuse", result.reason)
    return ConstraintDecisionV2("refuse", "evaluator-result-invalid")
