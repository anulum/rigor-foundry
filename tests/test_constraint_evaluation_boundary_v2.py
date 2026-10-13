# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected constraint evaluation boundary tests
"""Check actual built-ins and fail-closed result polarity at Stage B."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest

from rigor_foundry.constraint_evaluation_boundary_v2 import (
    ConstraintDecisionV2,
    evaluate_selected_constraint_v2,
)
from rigor_foundry.constraint_evaluators_v2 import (
    EvaluatorContextV2,
    EvaluatorResultV2,
    PreconditionContextV2,
    RateContextV2,
    RateIntentV2,
    RouteContextV2,
    WindowContextV2,
    evaluate_builtin_constraint_v2,
)
from rigor_foundry.effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2

_NOW = datetime(2026, 9, 21, 10, 0, tzinfo=UTC)
_PRECONDITION = PreconditionContextV2("verify-passed", True, "a" * 64, "cooperative")
_REQUIREMENT = EffectClassAuthorityRequirementV2.build_default()


def _check(
    subject: str,
    ctx: EvaluatorContextV2,
    params: dict[str, object],
    *,
    effect_class: str = "local-file-write",
    requirement: EffectClassAuthorityRequirementV2 | None = _REQUIREMENT,
    digest: str | None = _REQUIREMENT.requirement_digest,
) -> ConstraintDecisionV2:
    """Call the public selected boundary with ordinary fixture evidence and exact K6 pins."""
    return evaluate_selected_constraint_v2(
        subject=subject,
        effect_class=effect_class,
        ctx=ctx,
        params=params,
        authority_requirement=requirement,
        selected_authority_requirement_digest=digest,
    )


def test_fixed_evaluators_pass_and_refuse_through_selected_boundary() -> None:
    """Preserve actual rate, window, route and precondition pass/refusal results at selection."""
    rate = RateContextV2(_NOW, "local-file-write", "path:/tmp/a", (), True)
    rate_params: dict[str, object] = {
        "limit": 1,
        "window_seconds": 60,
        "count_basis": "operation-intent",
    }
    assert _check("rate", rate, rate_params) == ConstraintDecisionV2("pass", "passed")
    assert _check("rate", rate, {**rate_params, "limit": True}).reason == "params-invalid"
    window = WindowContextV2(_NOW)
    window_params: dict[str, object] = {
        "utc_ranges": [{"weekdays": ["mon"], "start": "10:00", "end": "11:00"}]
    }
    assert _check("window", window, window_params).outcome == "pass"
    assert _check("window", window, {"utc_ranges": []}).reason == "params-invalid"
    route = RouteContextV2("local", "ref:owner.local", "internal", "10", "CHF")
    route_params: dict[str, object] = {
        "provider": "local",
        "account_ref": "ref:owner.local",
        "privacy_class": "internal",
        "cost_ceiling": {"amount": "10", "currency": "CHF"},
    }
    assert _check("route", route, route_params).outcome == "pass"
    assert (
        _check("route", replace(route, provider="other"), route_params).reason == "route-mismatch"
    )
    assert _check("precondition", _PRECONDITION, {"condition": "verify-passed"}).outcome == "pass"
    assert (
        _check(
            "precondition", replace(_PRECONDITION, passed=False), {"condition": "verify-passed"}
        ).reason
        == "precondition-failed"
    )


def test_k6_requirement_applies_only_to_preconditions() -> None:
    """Require enforced preconditions for the selected classes without imposing that rule on rates."""
    params: dict[str, object] = {"condition": "verify-passed"}
    assert (
        _check("precondition", _PRECONDITION, params, effect_class="external-send").reason
        == "cooperative-precondition-for-enforced-class"
    )
    assert (
        _check("precondition", _PRECONDITION, params, effect_class="compute-job").outcome == "pass"
    )
    enforced = replace(_PRECONDITION, enforcement_class="enforced")
    assert _check("precondition", enforced, params, effect_class="external-send").outcome == "pass"
    assert (
        _check(
            "rate",
            RateContextV2(_NOW, "external-send", "x", (), True),
            {"limit": 1, "window_seconds": 1, "count_basis": "operation-intent"},
            effect_class="external-send",
            requirement=None,
            digest=None,
        ).outcome
        == "pass"
    )


def test_precondition_requirement_must_match_selected_digest() -> None:
    """Refuse absent, malformed or changed authority requirements before accepting a precondition."""
    params: dict[str, object] = {"condition": "verify-passed"}
    assert _check("precondition", _PRECONDITION, params, requirement=None).reason == (
        "authority-requirement-invalid"
    )
    assert _check("precondition", _PRECONDITION, params, digest=None).reason == (
        "authority-requirement-invalid"
    )
    assert _check("precondition", _PRECONDITION, params, digest="0" * 64).reason == (
        "authority-requirement-invalid"
    )
    malformed = replace(_REQUIREMENT, body_bytes=b"bad")
    assert _check("precondition", _PRECONDITION, params, requirement=malformed).reason == (
        "authority-requirement-invalid"
    )
    forged = replace(_REQUIREMENT, enforced_required=())
    assert _check("precondition", _PRECONDITION, params, requirement=forged).reason == (
        "authority-requirement-invalid"
    )


def test_unknown_class_subject_and_context_refuse() -> None:
    """Reject unknown subjects/effect classes and contexts belonging to a different evaluator."""
    params: dict[str, object] = {"condition": "verify-passed"}
    assert _check("permission", _PRECONDITION, params).reason == "context-invalid"
    assert _check("precondition", _PRECONDITION, params, effect_class="unknown").reason == (
        "context-invalid"
    )
    assert _check("precondition", WindowContextV2(_NOW), params).reason == "context-invalid"


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("non-UTC-clock", "context-invalid"),
        ("incomplete-window", "context-invalid"),
        ("invalid-params", "params-invalid"),
        ("journal-cap", "rate-cap"),
        ("rate-limit", "rate-limit"),
    ],
)
def test_builtin_return_polarity_stays_closed_for_real_inputs(fault: str, reason: str) -> None:
    """Actual built-in refusals retain their exact result at the selected boundary.

    Public callers supply contexts and parameters, not evaluator functions or
    results. Every unchanged built-in return constructs EvaluatorResultV2 with
    a fixed valid pair. The malformed-return guards cannot be exercised by
    these inputs; they remain uncovered without fabricated return values.
    This replaces the five result substitutions with five real refusal inputs.
    """
    ctx = RateContextV2(_NOW, "local-file-write", "x", (), True)
    params: dict[str, object] = {
        "limit": 1,
        "window_seconds": 60,
        "count_basis": "operation-intent",
    }
    intent = RateIntentV2("local-file-write", "x", _NOW)
    if fault == "non-UTC-clock":
        ctx = replace(ctx, now=_NOW.astimezone(timezone(timedelta(hours=1))))
    elif fault == "incomplete-window":
        ctx = replace(ctx, window_start_reached=False)
    elif fault == "invalid-params":
        params = {}
    elif fault == "journal-cap":
        ctx = replace(ctx, intents=(intent,) * 100_001)
    else:
        ctx = replace(ctx, intents=(intent,))
    result = evaluate_builtin_constraint_v2("rate", ctx, params)
    assert type(result) is EvaluatorResultV2
    assert result.outcome == "refuse"
    assert result.reason == reason
    assert _check("rate", ctx, params) == ConstraintDecisionV2("refuse", reason)


def test_unrepresentable_rate_window_refuses() -> None:
    """A real UTC datetime underflow is refused through the public boundary."""
    ctx = RateContextV2(datetime.min.replace(tzinfo=UTC), "local-file-write", "x", (), True)
    params: dict[str, object] = {
        "limit": 1,
        "window_seconds": 60,
        "count_basis": "operation-intent",
    }
    result = _check("rate", ctx, params)
    assert result == ConstraintDecisionV2("refuse", "context-invalid")


def test_builtin_exception_refuses() -> None:
    """A runtime-invalid public context cannot make an evaluator exception escape the boundary."""
    ctx = RateContextV2(cast(datetime, None), "local-file-write", "x", (), True)
    params: dict[str, object] = {
        "limit": 1,
        "window_seconds": 60,
        "count_basis": "operation-intent",
    }
    assert _check("rate", ctx, params) == ConstraintDecisionV2("refuse", "evaluator-error")
