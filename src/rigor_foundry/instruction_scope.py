# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — action-specific instruction scope
"""Represent host-authenticated instruction inputs without assigning authority."""

from __future__ import annotations

from dataclasses import dataclass

from .model_primitives import require_identifier
from .models import canonical_digest, require_string


@dataclass(frozen=True)
class ActionScope:
    """Exact action identity; targets are opaque canonical host identifiers.

    This is not a path parser or a claim of authority. The trusted operation
    adapter must bind its actual effects to these identities before dispatch.
    """

    actor: str
    runtime: str
    project: str
    task: str
    effect: str
    target: str
    provider: str
    account: str
    cost_class: str
    privacy_class: str

    def __post_init__(self) -> None:
        """Reject empty identities before they can participate in matching."""
        for value in self.values:
            require_string(value, "action scope")

    @property
    def values(self) -> tuple[str, ...]:
        """Return dimensions in the same order as instruction selectors."""
        return (
            self.actor,
            self.runtime,
            self.project,
            self.task,
            self.effect,
            self.target,
            self.provider,
            self.account,
            self.cost_class,
            self.privacy_class,
        )

    @property
    def digest(self) -> str:
        """Bind all exact dimensions without probing external resources."""
        return canonical_digest(self.values)


@dataclass(frozen=True)
class InstructionScope:
    """Exact dimension selectors; None is an explicit unrestricted dimension.

    No prefix, glob, filesystem normalisation or vendor alias is inferred.
    Selectors are trusted host policy, never caller-provided permission input.
    """

    actor: str | None = None
    runtime: str | None = None
    project: str | None = None
    task: str | None = None
    effect: str | None = None
    target: str | None = None
    provider: str | None = None
    account: str | None = None
    cost_class: str | None = None
    privacy_class: str | None = None

    def matches(self, action: ActionScope) -> bool:
        """Require equality for every constrained dimension of this action."""
        selectors = (
            self.actor,
            self.runtime,
            self.project,
            self.task,
            self.effect,
            self.target,
            self.provider,
            self.account,
            self.cost_class,
            self.privacy_class,
        )
        return all(
            wanted is None or wanted == actual
            for wanted, actual in zip(selectors, action.values, strict=True)
        )


@dataclass(frozen=True)
class ScopedInstruction:
    """One already-authenticated instruction in a host-owned policy snapshot.

    A subject identifies one independent constraint. The reserved subject
    ``permission`` must resolve to an allow issued by an authorised grantor;
    other subjects constrain that grant and cannot create one. Source IDs are
    durable provenance references, not evidence that authentication occurred.
    """

    source_id: str
    issuer: str
    subject: str
    scope: InstructionScope
    allow: bool
    supersedes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate instruction identity and exact override references."""
        for value in (self.source_id, self.issuer, self.subject, *self.supersedes):
            require_identifier(value, "instruction identity")
        if type(self.allow) is not bool:
            raise ValueError("instruction allow must be a boolean")
        if len(set(self.supersedes)) != len(self.supersedes):
            raise ValueError("instruction supersession references must be unique")
