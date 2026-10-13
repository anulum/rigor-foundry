# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed built-in Stage-B constraint evaluators
"""Evaluate rate, UTC window, route and host-computed precondition inputs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_EVEN, Context, InvalidOperation, Overflow
from typing import Literal, TypeAlias, cast

from .clause_semantics_set_v2 import _CONDITIONS, _rate, _route, _window

EvaluatorOutcomeV2: TypeAlias = Literal["pass", "refuse"]
EvaluatorReasonV2: TypeAlias = Literal[
    "passed",
    "context-invalid",
    "params-invalid",
    "rate-cap",
    "rate-limit",
    "window-outside",
    "route-mismatch",
    "route-over-ceiling",
    "precondition-failed",
]
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_RATE_CAP = 100_000
_AMOUNT = re.compile(r"(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,6})?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class EvaluatorResultV2:
    """Closed decision from one fixed evaluator.

    Attributes
    ----------
    outcome : EvaluatorOutcomeV2
        Literal pass or refusal; consumers also verify its matching reason.
    reason : EvaluatorReasonV2
        Closed success, context, parameter or subject-specific refusal reason.
    """

    outcome: EvaluatorOutcomeV2
    reason: EvaluatorReasonV2


@dataclass(frozen=True)
class RateIntentV2:
    """One journal operation-intent selected by the host.

    Attributes
    ----------
    effect_class : str
        Class verified against the intent's original operation catalogue.
    target_ref : str
        Canonical rendered target, matched exactly to the pending action.
    host_time : datetime
        Verified UTC journal timestamp; future or naive timestamps refuse.
    """

    effect_class: str
    target_ref: str
    host_time: datetime


@dataclass(frozen=True)
class RateContextV2:
    """Host-selected journal window and exact pending action.

    Attributes
    ----------
    now : datetime
        Fresh timezone-aware UTC host clock used to compute the window.
    effect_class, target_ref : str
        Actual pending effect and canonical rendered target.
    intents : tuple[RateIntentV2, ...]
        Verified retained history, bounded by the evaluator's record cap.
    window_start_reached : bool
        Whether an independently established history origin covers the whole window.

    Notes
    -----
    Constructing this record does not authenticate the clock or journal history.
    """

    now: datetime
    effect_class: str
    target_ref: str
    intents: tuple[RateIntentV2, ...]
    window_start_reached: bool


@dataclass(frozen=True)
class WindowContextV2:
    """UTC host clock reading for a window decision.

    Attributes
    ----------
    now : datetime
        Installed host clock; naive or non-UTC values refuse during evaluation.
    """

    now: datetime


@dataclass(frozen=True)
class RouteContextV2:
    """Host-extracted route and finite maximum cost for the action.

    Attributes
    ----------
    provider, account_ref, privacy_class : str
        Exact route labels compared with the selected signed clause.
    cost_upper_bound_amount : str | None
        Finite canonical decimal upper bound; absence refuses.
    cost_upper_bound_currency : str | None
        Exact bound currency, which must match the signed ceiling.

    Notes
    -----
    The installing host authenticates extraction; labels alone grant no provider access.
    """

    provider: str
    account_ref: str
    privacy_class: str
    cost_upper_bound_amount: str | None
    cost_upper_bound_currency: str | None


@dataclass(frozen=True)
class PreconditionContextV2:
    """One named host check and declared custody classification.

    Attributes
    ----------
    condition : str
        Canonical supported check name, matched to the selected clause.
    passed : bool
        Literal host-computed result; truthy substitutes refuse.
    evidence_digest : str
        Exact lowercase SHA-256 of the retained evidence used by the host check.
    enforcement_class : Literal["enforced", "cooperative"]
        Host custody classification, constrained by the selected authority boundary.

    Notes
    -----
    This record does not independently prove enforced custody or evidence provenance.
    """

    condition: str
    passed: bool
    evidence_digest: str
    enforcement_class: Literal["enforced", "cooperative"]


EvaluatorContextV2: TypeAlias = (
    RateContextV2 | WindowContextV2 | RouteContextV2 | PreconditionContextV2
)


def _utc(value: datetime) -> bool:
    """Accept only timezone-aware UTC host timestamps."""
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)


def evaluate_rate_v2(ctx: RateContextV2, params: Mapping[str, object]) -> EvaluatorResultV2:
    """Count matching verified intents under the bounded host journal read.

    Parameters
    ----------
    ctx
        Host-selected UTC clock, pending class/target and complete journal window.
    params
        Closed rate fields validated with the canonical semantics parser's rules.

    Returns
    -------
    EvaluatorResultV2
        Pass below the limit; refusal for invalid parameters, history or a spent window.

    Notes
    -----
    The caller supplies authenticated history; this pure calculation grants no effect authority.
    """
    if not _utc(ctx.now) or not ctx.window_start_reached:
        return EvaluatorResultV2("refuse", "context-invalid")
    if len(ctx.intents) > _RATE_CAP:
        return EvaluatorResultV2("refuse", "rate-cap")
    try:
        _rate(dict(params))
    except ValueError:
        return EvaluatorResultV2("refuse", "params-invalid")
    limit = cast(int, params["limit"])
    seconds = cast(int, params["window_seconds"])
    try:
        start = ctx.now - timedelta(seconds=seconds)
    except OverflowError:
        return EvaluatorResultV2("refuse", "context-invalid")
    count = 0
    for intent in ctx.intents:
        if not _utc(intent.host_time) or intent.host_time > ctx.now:
            return EvaluatorResultV2("refuse", "context-invalid")
        if (
            intent.host_time >= start
            and intent.effect_class == ctx.effect_class
            and intent.target_ref == ctx.target_ref
        ):
            count += 1
            if count >= limit:
                return EvaluatorResultV2("refuse", "rate-limit")
    return EvaluatorResultV2("pass", "passed")


def evaluate_window_v2(ctx: WindowContextV2, params: Mapping[str, object]) -> EvaluatorResultV2:
    """Check the host's UTC weekday and minute against closed canonical intervals.

    Parameters
    ----------
    ctx
        Fresh timezone-aware UTC host clock.
    params
        Canonical ordered ranges with valid clock text, calendar-ordered weekdays and no overlap.

    Returns
    -------
    EvaluatorResultV2
        Pass inside a start-inclusive/end-exclusive range; otherwise a typed refusal.

    Notes
    -----
    All ranges are validated before matching, including those after an applicable range.
    """
    if not _utc(ctx.now):
        return EvaluatorResultV2("refuse", "context-invalid")
    try:
        _window(dict(params))
    except ValueError:
        return EvaluatorResultV2("refuse", "params-invalid")
    ranges = cast(list[dict[str, object]], params["utc_ranges"])
    day = _WEEKDAYS[ctx.now.weekday()]
    minute = ctx.now.strftime("%H:%M")
    for item in ranges:
        days = cast(list[str], item["weekdays"])
        start = cast(str, item["start"])
        end = cast(str, item["end"])
        if day in days and start <= minute < end:
            return EvaluatorResultV2("pass", "passed")
    return EvaluatorResultV2("refuse", "window-outside")


def evaluate_route_v2(ctx: RouteContextV2, params: Mapping[str, object]) -> EvaluatorResultV2:
    """Compare closed route labels and a bounded decimal cost with fixed context.

    Parameters
    ----------
    ctx
        Host-extracted provider, account, privacy class and finite cost upper bound.
    params
        Canonical route fields and decimal ceiling under the semantics parser's rules.

    Returns
    -------
    EvaluatorResultV2
        Pass for matching labels and a bound at or below the ceiling; otherwise refusal.

    Notes
    -----
    The caller authenticates route extraction. Decimal comparison performs no provider call.
    """
    try:
        _route(dict(params))
    except ValueError:
        return EvaluatorResultV2("refuse", "params-invalid")
    if (
        ctx.provider != params.get("provider")
        or ctx.account_ref != params.get("account_ref")
        or ctx.privacy_class != params.get("privacy_class")
    ):
        return EvaluatorResultV2("refuse", "route-mismatch")
    ceiling = cast(dict[str, str], params["cost_ceiling"])
    amount = ceiling["amount"]
    currency = ceiling["currency"]
    if ctx.cost_upper_bound_amount is None or ctx.cost_upper_bound_currency is None:
        return EvaluatorResultV2("refuse", "params-invalid")
    if currency != ctx.cost_upper_bound_currency:
        return EvaluatorResultV2("refuse", "route-mismatch")
    if _AMOUNT.fullmatch(ctx.cost_upper_bound_amount) is None:
        return EvaluatorResultV2("refuse", "context-invalid")
    decimal_context = Context(prec=22, rounding=ROUND_HALF_EVEN)
    decimal_context.traps[InvalidOperation] = True
    decimal_context.traps[Overflow] = True
    bound = decimal_context.create_decimal(ctx.cost_upper_bound_amount)
    maximum = decimal_context.create_decimal(amount)
    if bound > maximum:
        return EvaluatorResultV2("refuse", "route-over-ceiling")
    return EvaluatorResultV2("pass", "passed")


def evaluate_precondition_v2(
    ctx: PreconditionContextV2, params: Mapping[str, object]
) -> EvaluatorResultV2:
    """Accept only a canonical named condition's host-computed pass result.

    Parameters
    ----------
    ctx
        Host-computed result, exact evidence digest and declared custody classification.
    params
        Closed single condition field naming one canonical supported check.

    Returns
    -------
    EvaluatorResultV2
        Pass only for the matching check's literal true result; otherwise refusal.

    Notes
    -----
    The selected constraint boundary separately enforces the authority requirement.
    """
    condition = params.get("condition")
    if (
        set(params) != {"condition"}
        or not isinstance(condition, str)
        or condition not in _CONDITIONS
    ):
        return EvaluatorResultV2("refuse", "params-invalid")
    if (
        ctx.condition != params.get("condition")
        or _DIGEST.fullmatch(ctx.evidence_digest) is None
        or type(ctx.passed) is not bool
        or ctx.enforcement_class not in {"enforced", "cooperative"}
    ):
        return EvaluatorResultV2("refuse", "context-invalid")
    return (
        EvaluatorResultV2("pass", "passed")
        if ctx.passed
        else EvaluatorResultV2("refuse", "precondition-failed")
    )


def evaluate_builtin_constraint_v2(
    subject: str, ctx: EvaluatorContextV2, params: Mapping[str, object]
) -> EvaluatorResultV2:
    """Dispatch only the four fixed subject/context pairs.

    Parameters
    ----------
    subject
        Rate, window, route or precondition; no dynamic evaluator identifier.
    ctx
        Matching installed host context. A cross-subject context refuses.
    params
        Closed canonical parameters checked by the corresponding evaluator.

    Returns
    -------
    EvaluatorResultV2
        Actual fixed evaluator result, or context-invalid for unsupported pairs.

    Notes
    -----
    The selected constraint boundary separately checks result polarity and the
    current authority requirement. Dispatch supplies no effect capability.
    """
    if subject == "rate" and isinstance(ctx, RateContextV2):
        return evaluate_rate_v2(ctx, params)
    if subject == "window" and isinstance(ctx, WindowContextV2):
        return evaluate_window_v2(ctx, params)
    if subject == "route" and isinstance(ctx, RouteContextV2):
        return evaluate_route_v2(ctx, params)
    if subject == "precondition" and isinstance(ctx, PreconditionContextV2):
        return evaluate_precondition_v2(ctx, params)
    return EvaluatorResultV2("refuse", "context-invalid")
