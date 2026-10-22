# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit condition observations
"""Represent supplied condition values separately from absence and missing knowledge."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, NoReturn, cast

from .audit_primitives import require_exact_fields
from .condition_language import ConditionValue
from .model_primitives import JsonScalar, require_json_scalar
from .models import canonical_digest, require_mapping, require_string

ObservationState = Literal["known", "absent", "unknown"]


class ConditionTruth(StrEnum):
    """Three-valued result requiring an explicit state comparison.

    Notes
    -----
    TRUE, FALSE and UNKNOWN have the string values true, false and unknown.
    Boolean conversion raises TypeError for every member, so a string-false
    or unresolved result cannot become a truthy permission check.
    """

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    def __bool__(self) -> NoReturn:
        """Refuse a Boolean cast that could turn unknown or string-false into true."""
        raise TypeError("condition truth requires an explicit state comparison")


@dataclass(frozen=True, eq=False)
class ConditionFact:
    """One inert supplied observation, without authentication or effect authority.

    Parameters
    ----------
    state : ObservationState
        Known for an observed value, absent for declared absence, or unknown.
        Trusted consumers must authenticate absence and value provenance first.
    value : ConditionValue
        Finite JSON scalar or immutable scalar array for known observations.
        Absence and unknown require None; known None is an observed null.

    Raises
    ------
    ValueError
        State is unsupported, a non-known state carries a value, or a known
        value is nested, mutable, nonfinite or outside the numeric domain.

    Notes
    -----
    Equality and hashing preserve the exact serialized operands, including
    Boolean versus numeric identity. They authenticate no observation.
    """

    state: ObservationState
    value: ConditionValue = None

    def __eq__(self, other: object) -> bool:
        """Compare exact serialized operands without Boolean/integer aliasing."""
        if not isinstance(other, ConditionFact):
            return False
        return canonical_digest(self.to_dict()) == canonical_digest(other.to_dict())

    def __hash__(self) -> int:
        """Hash the immutable typed data used by equality."""
        return hash(canonical_digest(self.to_dict()))

    def __post_init__(self) -> None:
        """Validate direct construction without conflating null and missing data."""
        if not isinstance(self.state, str) or self.state not in {"known", "absent", "unknown"}:
            raise ValueError("condition fact state is unsupported")
        if self.state != "known":
            if self.value is not None:
                raise ValueError("absent and unknown condition facts require null")
            return
        values = self.value if isinstance(self.value, tuple) else (self.value,)
        for item in values:
            try:
                require_json_scalar(item, "condition fact value")
            except OverflowError as exc:
                raise ValueError("condition fact number exceeds the finite domain") from exc

    @classmethod
    def known(cls, value: ConditionValue) -> ConditionFact:
        """Build a supplied observed value, including an observed null.

        Parameters
        ----------
        value : ConditionValue
            Finite JSON scalar or immutable flat scalar tuple. Empty tuples
            are allowed; mutable lists must be parsed through from_dict.

        Returns
        -------
        ConditionFact
            A known observation retaining the actual scalar or array value.

        Raises
        ------
        ValueError
            The value is nested, mutable, nonfinite or numerically unsupported.
        """
        return cls("known", value)

    @classmethod
    def absent(cls) -> ConditionFact:
        """Build declared absence without manufacturing provenance.

        Returns
        -------
        ConditionFact
            The absent state with a null payload. A trusted policy consumer
            must independently authenticate that absence before using it.
        """
        return cls("absent")

    @classmethod
    def unknown(cls) -> ConditionFact:
        """Build explicit missing knowledge without asserting absence.

        Returns
        -------
        ConditionFact
            The unknown state with a null payload, distinct from known null.
        """
        return cls("unknown")

    @classmethod
    def from_dict(cls, value: object) -> ConditionFact:
        """Parse a supplied observation without accepting a provenance claim.

        Parameters
        ----------
        value : object
            A mapping with exactly state and value. JSON scalar arrays are
            copied into immutable tuples; absent and unknown require null.

        Returns
        -------
        ConditionFact
            An observation validated by the same constructor as direct calls.

        Raises
        ------
        ValueError
            Fields, state, null requirements or the finite scalar domain fail.
        """
        data = require_mapping(value, "condition fact")
        require_exact_fields(data, frozenset({"state", "value"}), "condition fact")
        state = require_string(data["state"], "condition fact state")
        raw = data["value"]
        if isinstance(raw, list):
            parsed: ConditionValue = tuple(cast(list[JsonScalar], raw))
        else:
            parsed = cast(JsonScalar, raw)
        return cls(cast(ObservationState, state), parsed)

    def to_dict(self) -> dict[str, object]:
        """Return the complete supplied observation after revalidation.

        Returns
        -------
        dict[str, object]
            A fresh state/value mapping with tuples serialized as JSON arrays.
            Neither a signature nor a provenance statement is added.

        Raises
        ------
        ValueError
            A directly altered instance no longer satisfies the state contract.
        """
        checked = ConditionFact(self.state, self.value)
        return {
            "state": checked.state,
            "value": list(checked.value) if isinstance(checked.value, tuple) else checked.value,
        }
