# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-bound instruction dispatch
"""Join scoped policy and fresh adapter evidence before a registered operation."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from .effective_profile import AdapterLock
from .instruction_resolution import (
    InstructionDecision,
    InstructionPolicy,
    resolve_instruction_action,
)
from .instruction_scope import ActionScope


@dataclass(frozen=True)
class DispatchRequest:
    """Exact immutable request, including every declared effect and route boundary.

    Payload is opaque to the resolver; the trusted adapter must derive effects
    from those exact bytes and bind them to actions. Route labels are exact
    identities, not aliases or permission claims. No implicit fallback exists.
    """

    actions: tuple[ActionScope, ...]
    adapter: AdapterLock
    provider: str
    account: str
    cost_class: str
    privacy_class: str
    payload: bytes

    @property
    def route(self) -> tuple[str, str, str, str]:
        """Return the complete provider, account, cost and privacy boundary."""
        return (self.provider, self.account, self.cost_class, self.privacy_class)


@dataclass(frozen=True)
class DispatchLease:
    """Fresh trusted-host bindings held through a specific registered operation.

    The state provider authenticates policy and adapter registration, observes
    current availability, and derives verified_actions from the request payload.
    Advertisement alone cannot supply verified_actions. The host owns account,
    resource, executable and target custody and must not accept these fields from
    an untrusted caller. None denotes missing evidence, never an empty permission.
    """

    policy: InstructionPolicy
    advertised_adapter: AdapterLock | None
    verified_adapter: AdapterLock
    verified_actions: tuple[ActionScope, ...] | None
    route: tuple[str, str, str, str]
    os_capable: bool
    revalidate: Callable[[DispatchRequest], None]
    execute: Callable[[bytes], bytes]


@dataclass(frozen=True)
class DispatchResult:
    """Actual handler output and the decisions used for its declared effects."""

    output: bytes
    decisions: tuple[InstructionDecision, ...]


def dispatch_instruction_action(
    request: DispatchRequest,
    *,
    state: Callable[[DispatchRequest], AbstractContextManager[DispatchLease]],
) -> DispatchResult:
    """Dispatch only under matching fresh host evidence and resolved permission.

    The host factory is trusted composition, not a request argument exposed over
    a service boundary. It authenticates grants and holds current policy/resource
    custody. Final revalidation must check current expiry/revocation and target/
    executable identity after resolution, immediately before handler invocation.
    The registered handler receives precisely the inspected immutable payload.

    This cooperative in-process API does not sandbox hostile callbacks, verify
    a new signed wire grant, or cancel an operation after admission. Existing
    independent remediation approval and native sandbox requirements still apply.
    A suppressed failure cannot become a successful empty result.
    """
    if not request.actions or len(set(request.actions)) != len(request.actions):
        raise ValueError("dispatch requires unique explicit effects")
    if type(request.payload) is not bytes:
        raise ValueError("dispatch payload must be immutable bytes")
    if any(
        (action.provider, action.account, action.cost_class, action.privacy_class) != request.route
        for action in request.actions
    ):
        raise ValueError("action route differs from dispatch route")
    adapter = AdapterLock.from_dict(request.adapter.to_dict())
    with state(request) as lease:
        if lease.advertised_adapter != adapter or lease.verified_adapter != adapter:
            raise PermissionError("current advertisement and verified adapter must match request")
        if lease.verified_actions != request.actions:
            raise PermissionError("verified adapter effects are missing or differ from request")
        if lease.route != request.route:
            raise PermissionError("provider, account, cost or privacy boundary changed")
        if lease.os_capable is not True:
            raise PermissionError("required operating-system capability is unavailable")
        decisions = tuple(
            resolve_instruction_action(lease.policy, action) for action in request.actions
        )
        if not all(decision.allowed for decision in decisions):
            raise PermissionError("action instruction resolution refused dispatch")
        lease.revalidate(request)
        return DispatchResult(lease.execute(request.payload), decisions)
    raise RuntimeError("host dispatch lease suppressed a failure")
