# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed Stage-B evaluator tests
"""Exercise signed-parameter boundaries with host-selected immutable inputs."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

import pytest

from rigor_foundry.constraint_evaluators_v2 import (
    EvaluatorContextV2,
    EvaluatorResultV2,
    PreconditionContextV2,
    RateContextV2,
    RateIntentV2,
    RouteContextV2,
    WindowContextV2,
    evaluate_builtin_constraint_v2,
    evaluate_precondition_v2,
    evaluate_rate_v2,
    evaluate_route_v2,
    evaluate_window_v2,
)

_NOW = datetime(2026, 9, 21, 10, 0, tzinfo=UTC)
_RATE_PARAMS: dict[str, object] = {
    "limit": 2,
    "window_seconds": 60,
    "count_basis": "operation-intent",
}
_ROUTE_PARAMS: dict[str, object] = {
    "provider": "local",
    "account_ref": "ref:owner.local",
    "privacy_class": "internal",
    "cost_ceiling": {"amount": "10.000000", "currency": "CHF"},
}


def _rate(*intents: RateIntentV2, reached: bool = True) -> RateContextV2:
    """Supply one host-selected action and verified journal window."""
    return RateContextV2(_NOW, "local-file-write", "path:/tmp/a", intents, reached)


def _intent(seconds_ago: int, *, target: str = "path:/tmp/a") -> RateIntentV2:
    """Make a verified operation-intent at one UTC time."""
    return RateIntentV2("local-file-write", target, _NOW - timedelta(seconds=seconds_ago))


def test_rate_counts_matching_intents_and_refuses_at_limit() -> None:
    """Only matching class, target and window consume a rate slot."""
    context = _rate(_intent(30), _intent(31, target="path:/tmp/b"), _intent(61))
    assert evaluate_rate_v2(context, _RATE_PARAMS) == EvaluatorResultV2("pass", "passed")
    assert evaluate_builtin_constraint_v2("rate", context, _RATE_PARAMS).outcome == "pass"
    assert evaluate_rate_v2(_rate(_intent(30), _intent(10)), _RATE_PARAMS).reason == "rate-limit"


def test_rate_refuses_unverified_window_cap_or_bad_time() -> None:
    """An incomplete host read and future or naive journal times fail closed."""
    assert evaluate_rate_v2(_rate(reached=False), _RATE_PARAMS).reason == "context-invalid"
    assert (
        evaluate_rate_v2(_rate(*(_intent(1) for _ in range(100_001))), _RATE_PARAMS).reason
        == "rate-cap"
    )
    assert evaluate_rate_v2(_rate(_intent(-1)), _RATE_PARAMS).reason == "context-invalid"
    assert (
        evaluate_rate_v2(_rate(_intent(1), reached=True), {**_RATE_PARAMS, "limit": True}).reason
        == "params-invalid"
    )
    assert (
        evaluate_rate_v2(replace(_rate(), now=_NOW.replace(tzinfo=None)), _RATE_PARAMS).reason
        == "context-invalid"
    )
    assert (
        evaluate_rate_v2(
            _rate(RateIntentV2("local-file-write", "path:/tmp/a", _NOW.replace(tzinfo=None))),
            _RATE_PARAMS,
        ).reason
        == "context-invalid"
    )


def test_utc_window_boundary_and_bad_shape() -> None:
    """A Monday interval admits its start minute and refuses its end."""
    params: dict[str, object] = {
        "utc_ranges": [{"weekdays": ["mon"], "start": "10:00", "end": "11:00"}]
    }
    assert evaluate_window_v2(WindowContextV2(_NOW), params).outcome == "pass"
    assert (
        evaluate_builtin_constraint_v2("window", WindowContextV2(_NOW), params).outcome == "pass"
    )
    assert (
        evaluate_window_v2(WindowContextV2(_NOW.replace(hour=11)), params).reason
        == "window-outside"
    )
    assert (
        evaluate_window_v2(WindowContextV2(_NOW.replace(tzinfo=None)), params).reason
        == "context-invalid"
    )
    assert evaluate_window_v2(WindowContextV2(_NOW), {"utc_ranges": []}).reason == "params-invalid"
    assert (
        evaluate_window_v2(WindowContextV2(_NOW), {"utc_ranges": ["bad"]}).reason
        == "params-invalid"
    )
    assert (
        evaluate_window_v2(
            WindowContextV2(_NOW),
            {"utc_ranges": [{"weekdays": "mon", "start": 10, "end": "11:00"}]},
        ).reason
        == "params-invalid"
    )


def test_route_exact_identity_cost_and_currency() -> None:
    """A finite extracted upper bound must fit the signed ceiling exactly."""
    context = RouteContextV2("local", "ref:owner.local", "internal", "10.000000", "CHF")
    assert evaluate_route_v2(context, _ROUTE_PARAMS).outcome == "pass"
    assert evaluate_builtin_constraint_v2("route", context, _ROUTE_PARAMS).outcome == "pass"
    assert (
        evaluate_route_v2(replace(context, provider="other"), _ROUTE_PARAMS).reason
        == "route-mismatch"
    )
    assert (
        evaluate_route_v2(replace(context, cost_upper_bound_currency="USD"), _ROUTE_PARAMS).reason
        == "route-mismatch"
    )
    assert (
        evaluate_route_v2(
            replace(context, cost_upper_bound_amount="10.000001"), _ROUTE_PARAMS
        ).reason
        == "route-over-ceiling"
    )
    assert (
        evaluate_route_v2(replace(context, cost_upper_bound_amount=None), _ROUTE_PARAMS).reason
        == "params-invalid"
    )
    assert (
        evaluate_route_v2(replace(context, cost_upper_bound_amount="NaN"), _ROUTE_PARAMS).reason
        == "context-invalid"
    )
    assert (
        evaluate_route_v2(
            replace(context, cost_upper_bound_amount="10.0000001"), _ROUTE_PARAMS
        ).reason
        == "context-invalid"
    )
    assert (
        evaluate_route_v2(context, {**_ROUTE_PARAMS, "cost_ceiling": "bad"}).reason
        == "params-invalid"
    )
    assert (
        evaluate_route_v2(
            context, {**_ROUTE_PARAMS, "cost_ceiling": {"amount": 10, "currency": "CHF"}}
        ).reason
        == "params-invalid"
    )


def test_precondition_uses_host_result_and_exact_evidence() -> None:
    """The built-in does not derive an agent claim from its own environment."""
    context = PreconditionContextV2("verify-passed", True, "a" * 64, "cooperative")
    params: dict[str, object] = {"condition": "verify-passed"}
    assert evaluate_precondition_v2(context, params).outcome == "pass"
    assert evaluate_builtin_constraint_v2("precondition", context, params).outcome == "pass"
    assert (
        evaluate_precondition_v2(replace(context, passed=False), params).reason
        == "precondition-failed"
    )
    assert (
        evaluate_precondition_v2(context, {"condition": "repo-lease-held"}).reason
        == "context-invalid"
    )
    assert (
        evaluate_precondition_v2(replace(context, evidence_digest="wrong"), params).reason
        == "context-invalid"
    )
    assert (
        evaluate_precondition_v2(
            replace(context, enforcement_class=cast(Literal["enforced", "cooperative"], "other")),
            params,
        ).reason
        == "context-invalid"
    )


@pytest.mark.parametrize("subject", ["permission", "rate", "window", "route", "precondition"])
def test_dispatch_refuses_unknown_or_cross_subject_context(subject: str) -> None:
    """A subject cannot borrow another built-in's host context."""
    context = WindowContextV2(_NOW)
    result = evaluate_builtin_constraint_v2(subject, context, {})
    assert result.reason == ("params-invalid" if subject == "window" else "context-invalid")


@pytest.mark.parametrize(
    "ranges",
    [
        [{"weekdays": ["mon"], "start": "00:00", "end": "99:00"}],
        [{"weekdays": ["mon"], "start": "0:00", "end": "11:00"}],
        [{"weekdays": ["mon", "mon"], "start": "09:00", "end": "11:00"}],
        [{"weekdays": ["tue", "mon"], "start": "09:00", "end": "11:00"}],
        [{"weekdays": ["mon", "holiday"], "start": "09:00", "end": "11:00"}],
        [{"weekdays": [], "start": "09:00", "end": "11:00"}],
        [{"weekdays": ["mon"], "start": "11:00", "end": "09:00"}],
        [{"weekdays": ["mon"], "start": "09:00", "end": "11:00", "extra": True}],
        [
            {"weekdays": ["mon"], "start": "09:00", "end": "11:00"},
            {"weekdays": ["mon"], "start": "10:30", "end": "12:00"},
        ],
        [{"weekdays": ["mon"], "start": "09:00", "end": "11:00"}, "bad"],
    ],
)
def test_public_window_validates_all_ranges_before_any_pass(ranges: object) -> None:
    """An applicable first range cannot hide malformed or overlapping trailing parameters."""
    params = {"utc_ranges": ranges}
    expected = EvaluatorResultV2("refuse", "params-invalid")
    assert evaluate_window_v2(WindowContextV2(_NOW), params) == expected
    assert evaluate_builtin_constraint_v2("window", WindowContextV2(_NOW), params) == expected


@pytest.mark.parametrize("subject", ["rate", "window", "route", "precondition"])
def test_public_evaluators_refuse_open_parameter_field_sets(subject: str) -> None:
    """Canonical signature parsing and direct evaluator calls share closed parameter rules."""
    contexts: dict[str, EvaluatorContextV2] = {
        "rate": _rate(),
        "window": WindowContextV2(_NOW),
        "route": RouteContextV2("local", "ref:owner.local", "internal", "1", "CHF"),
        "precondition": PreconditionContextV2("verify-passed", True, "a" * 64, "cooperative"),
    }
    params: dict[str, dict[str, object]] = {
        "rate": _RATE_PARAMS,
        "window": {"utc_ranges": [{"weekdays": ["mon"], "start": "09:00", "end": "11:00"}]},
        "route": _ROUTE_PARAMS,
        "precondition": {"condition": "verify-passed"},
    }
    result = evaluate_builtin_constraint_v2(
        subject, contexts[subject], {**params[subject], "extra": 1}
    )
    assert result == EvaluatorResultV2("refuse", "params-invalid")


def test_unsupported_precondition_cannot_pass_by_matching_context_label() -> None:
    """Matching host labels cannot create an unregistered condition."""
    context = PreconditionContextV2("unregistered", True, "a" * 64, "cooperative")
    assert evaluate_precondition_v2(context, {"condition": "unregistered"}) == EvaluatorResultV2(
        "refuse", "params-invalid"
    )


def test_rate_refuses_a_utc_clock_that_cannot_represent_its_window_start() -> None:
    """Valid parameter ranges cannot make datetime underflow escape the closed evaluator."""
    context = replace(_rate(), now=datetime.min.replace(tzinfo=UTC))
    expected = EvaluatorResultV2("refuse", "context-invalid")
    assert evaluate_rate_v2(context, _RATE_PARAMS) == expected
    assert evaluate_builtin_constraint_v2("rate", context, _RATE_PARAMS) == expected
