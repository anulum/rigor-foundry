# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed per-rule review guidance
"""Fixed rationale and verification guidance that each detector publishes per rule."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleGuidanceCase:
    """One labelled situation in which a rule raises a candidate.

    Parameters
    ----------
    condition : str
        A short fixed label naming the situation; empty only for a single-situation rule.
    rationale : str
        Why this situation is worth review.
    verification : str
        How a reviewer establishes or refutes the candidate.
    """

    condition: str
    rationale: str
    verification: str


@dataclass(frozen=True)
class RuleGuidance:
    """The fixed review guidance one detector attaches to the candidates of one rule.

    Parameters
    ----------
    rationale : str
        Why the rule's primary situation is worth review.
    verification : str
        How a reviewer establishes or refutes a candidate in that situation.
    condition : str, optional
        The primary situation's label. It is required when ``cases`` is not empty.
    cases : tuple[RuleGuidanceCase, ...], optional
        Further labelled situations of the same rule, in the detector's order.

    Raises
    ------
    ValueError
        If a rule with further cases leaves any situation, primary included, unlabelled.
    """

    rationale: str
    verification: str
    condition: str = ""
    cases: tuple[RuleGuidanceCase, ...] = ()

    def __post_init__(self) -> None:
        """Refuse an unlabelled situation on a rule that has more than one."""
        if self.cases and not all(case.condition for case in self.all_cases()):
            raise ValueError("every situation of a multi-case rule needs a condition label")

    def all_cases(self) -> tuple[RuleGuidanceCase, ...]:
        """Return the primary situation followed by every further case.

        Returns
        -------
        tuple[RuleGuidanceCase, ...]
            Every distinct situation of the rule, primary first.
        """
        return (RuleGuidanceCase(self.condition, self.rationale, self.verification), *self.cases)
