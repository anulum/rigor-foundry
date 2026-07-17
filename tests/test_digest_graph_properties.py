# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — digest graph validation properties
"""Prove deterministic graph validation across declaration permutations."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from rigor_foundry.digest_dependencies import (
    DIGEST_DEPENDENCIES,
    DIGEST_NODES,
    DigestDependency,
    DigestNodeSpec,
    validate_digest_dependency_graph,
)

_PROPERTY_SETTINGS = settings(max_examples=100, deadline=None)


@_PROPERTY_SETTINGS
@given(st.permutations(DIGEST_NODES), st.permutations(DIGEST_DEPENDENCIES))
def test_valid_graph_is_invariant_under_declaration_permutation(
    nodes: tuple[DigestNodeSpec, ...],
    dependencies: tuple[DigestDependency, ...],
) -> None:
    """A semantic graph remains valid under arbitrary declaration order."""
    assert validate_digest_dependency_graph(nodes, dependencies) == ()


@_PROPERTY_SETTINGS
@given(st.permutations(DIGEST_DEPENDENCIES))
def test_invalid_graph_evidence_is_deterministic(
    dependencies: tuple[DigestDependency, ...],
) -> None:
    """Equivalent invalid edge declarations produce byte-identical errors."""
    invalid = (*dependencies, DigestDependency("report", "report", "self"))
    assert validate_digest_dependency_graph(
        DIGEST_NODES, invalid
    ) == validate_digest_dependency_graph(
        DIGEST_NODES,
        tuple(reversed(invalid)),
    )


def test_minimal_self_cycle_regression_is_retained() -> None:
    """The smallest cyclic declaration remains a permanent failing example."""
    errors = validate_digest_dependency_graph(
        DIGEST_NODES,
        (DigestDependency("report", "report", "self"),),
    )
    assert "digest dependency self-cycle: report" in errors
    assert "digest dependency cycle reaches report" in errors
