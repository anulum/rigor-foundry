# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — scoped instruction authority resolution
"""Resolve authenticated host instructions before intersecting constraints."""

from __future__ import annotations

from dataclasses import dataclass

from .effective_profile import PolicyContradiction
from .instruction_scope import ActionScope, ScopedInstruction


@dataclass(frozen=True)
class InstructionPolicy:
    """Trusted host policy; issuer order runs from highest to lowest authority.

    The host authenticates sources and this ordering outside this pure resolver.
    Grantors are explicit: a vendor constraint issuer need not be a grantor.
    This is not a wire format or a replacement for quality-profile resolution.
    """

    instructions: tuple[ScopedInstruction, ...]
    issuer_order: tuple[str, ...]
    grantors: frozenset[str]

    def __post_init__(self) -> None:
        """Reject ambiguous global identities before resolving scoped actions."""
        sources = tuple(item.source_id for item in self.instructions)
        if len(set(sources)) != len(sources):
            raise ValueError("instruction source identifiers must be unique")
        if len(set(self.issuer_order)) != len(self.issuer_order):
            raise ValueError("issuer authority order must be unique")
        if not self.grantors.issubset(self.issuer_order):
            raise ValueError("grantors must belong to the trusted issuer order")


@dataclass(frozen=True)
class InstructionDecision:
    """Action-scoped source disposition; no execution authority is minted."""

    action: ActionScope
    selected: tuple[str, ...]
    excluded: tuple[str, ...]
    overridden: tuple[str, ...]
    contradictions: tuple[PolicyContradiction, ...]

    @property
    def allowed(self) -> bool:
        """Report whether this authenticated input resolved without a blocker."""
        return not self.contradictions


def resolve_instruction_action(
    policy: InstructionPolicy, action: ActionScope
) -> InstructionDecision:
    """Select scope, resolve authority and exact overrides, then combine subjects.

    Higher authority dominates only within the same constraint subject. At the
    same authority contradictory surviving values fail closed. Explicit override
    edges may replace equal or lower authority in the same subject, never an
    independent constraint. Cycles and unknown applicable references refuse this
    action. There is no document-recency heuristic or implicit permission.
    """
    known = {item.source_id: item for item in policy.instructions}
    active = {key: item for key, item in known.items() if item.scope.matches(action)}
    excluded = tuple(sorted(set(known).difference(active)))
    ranks = {issuer: rank for rank, issuer in enumerate(policy.issuer_order)}
    contradictions: list[PolicyContradiction] = []

    def conflict(code: str, sources: tuple[str, ...], detail: str) -> None:
        """Keep a deterministic existing contradiction record for this action."""
        contradictions.append(
            PolicyContradiction.build(
                code=code,
                subject=action.digest,
                sources=sources,
                detail=detail,
            )
        )

    edges: dict[str, set[str]] = {key: set() for key in active}
    for key, item in sorted(active.items()):
        if item.issuer not in ranks:
            conflict(
                "unknown-instruction-issuer", (key,), "applicable source has no trusted authority"
            )
            continue
        for target in item.supersedes:
            previous = known.get(target)
            if previous is None:
                conflict("unknown-instruction-override", (key,), "override source is absent")
            elif target in active:
                if (
                    previous.issuer not in ranks
                    or previous.subject != item.subject
                    or ranks[item.issuer] > ranks[previous.issuer]
                ):
                    conflict(
                        "unauthorised-instruction-override",
                        (key, target),
                        "override cannot cross subjects or exceed issuer authority",
                    )
                else:
                    edges[key].add(target)
    pending = {key: set(values) for key, values in edges.items()}
    while pending:
        leaves = {key for key, values in pending.items() if not values}
        if not leaves:
            conflict(
                "instruction-override-cycle",
                tuple(sorted(pending)),
                "applicable override graph contains a cycle",
            )
            break
        pending = {
            key: values.difference(leaves) for key, values in pending.items() if key not in leaves
        }
    overridden = set().union(*edges.values()) if edges else set()
    selected: set[str] = set()
    permission = False
    for subject in sorted({item.subject for item in active.values()}):
        candidates = [
            item
            for key, item in active.items()
            if item.subject == subject and key not in overridden and item.issuer in ranks
        ]
        if not candidates:
            continue
        rank = min(ranks[item.issuer] for item in candidates)
        winners = [item for item in candidates if ranks[item.issuer] == rank]
        selected.update(item.source_id for item in winners)
        overridden.update(item.source_id for item in candidates if ranks[item.issuer] > rank)
        sources = tuple(sorted(item.source_id for item in winners))
        values = {item.allow for item in winners}
        if len(values) > 1:
            conflict("instruction-conflict", sources, "equal-authority instructions contradict")
        elif not winners[0].allow:
            conflict(
                "instruction-denied", sources, "independent applicable constraint denies action"
            )
        elif subject == "permission":
            permission = all(item.issuer in policy.grantors for item in winners)
    if not permission:
        conflict(
            "missing-action-grant", (action.digest,), "no surviving authorised permission grant"
        )
    return InstructionDecision(
        action, tuple(sorted(selected)), excluded, tuple(sorted(overridden)), tuple(contradictions)
    )
