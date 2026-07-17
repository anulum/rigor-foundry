# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared property-test strategies
"""Provide bounded domain strategies for public production invariants."""

from __future__ import annotations

from hypothesis import strategies as st

from rigor_foundry.condition_language import ConditionExpression

JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**31), max_value=2**31 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=40),
)
"""Finite JSON scalar values accepted by the protocol."""

REFERENCES = st.from_regex(r"[a-z][a-z0-9_]{0,11}(?:\.[a-z][a-z0-9_]{0,11}){0,2}", fullmatch=True)
"""Bounded condition context references."""

REPOSITORY_COMPONENTS = st.from_regex(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,15}", fullmatch=True).filter(
    lambda value: value not in {".", ".."}
)
"""Portable non-special repository path components."""

_LEAF_CONDITIONS = st.builds(
    ConditionExpression.build,
    st.sampled_from(("eq", "ne")),
    reference=REFERENCES,
    value=JSON_SCALARS,
)

CONDITIONS = st.one_of(
    _LEAF_CONDITIONS,
    st.builds(ConditionExpression.build, st.just("not"), children=st.tuples(_LEAF_CONDITIONS)),
    st.builds(
        ConditionExpression.build,
        st.sampled_from(("all", "any")),
        children=st.lists(_LEAF_CONDITIONS, min_size=1, max_size=3).map(tuple),
    ),
)
"""Validated condition trees below the production depth and node budgets."""
