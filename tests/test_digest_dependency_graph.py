# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — normative digest graph structure tests
"""Prove schema completeness, topology, and malformed-graph rejection."""

from __future__ import annotations

from typing import cast

import pytest

import rigor_foundry
from rigor_foundry.digest_dependencies import (
    DIGEST_DEPENDENCIES,
    DIGEST_DEPENDENCY_SCHEMA_VERSION,
    DIGEST_NODES,
    DigestDependency,
    DigestNode,
    DigestNodeSpec,
    digest_dependency_graph,
    digest_dependency_graph_digest,
    direct_dependents,
    transitive_dependents,
    validate_digest_dependency_graph,
)
from rigor_foundry.work_closure import WorkClosure


def test_graph_schema_is_complete_acyclic_and_content_addressed() -> None:
    """The public graph names every established content-addressed record family."""
    assert DIGEST_DEPENDENCY_SCHEMA_VERSION == "1.8"
    assert tuple(node.name for node in DIGEST_NODES) == (
        "inventory",
        "ignored-inventory",
        "git-provenance",
        "policy",
        "rule-pack",
        "maturity-policy",
        "rule-maturity",
        "source-claim",
        "source-retrieval-policy",
        "source-capture",
        "source-verification",
        "adapter-profile",
        "adapter-lock",
        "standard-pack",
        "verification-key-policy",
        "offline-trust-policy",
        "toolchain",
        "effective-profile",
        "report",
        "report-diff",
        "review",
        "model-aliases",
        "evidence-signature",
        "review-evidence",
        "verification-bundle",
        "verification-result",
        "offline-verification",
        "campaign",
        "attestation",
        "comparison",
        "task",
        "closure",
    )
    assert len(DIGEST_DEPENDENCIES) == 49
    assert validate_digest_dependency_graph() == ()
    assert digest_dependency_graph()["schema_version"] == "1.8"
    assert rigor_foundry.digest_dependency_graph() == digest_dependency_graph()
    assert rigor_foundry.WorkClosure is WorkClosure
    assert direct_dependents("standard-pack") == (
        "effective-profile",
        "verification-bundle",
        "verification-result",
    )
    assert direct_dependents("verification-key-policy") == ("offline-trust-policy",)
    assert transitive_dependents("offline-trust-policy") == ("offline-verification",)
    assert transitive_dependents("model-aliases") == (
        "evidence-signature",
        "verification-bundle",
        "verification-result",
        "offline-verification",
    )
    assert direct_dependents("maturity-policy") == ("rule-maturity",)
    assert direct_dependents("source-claim") == ("source-verification",)
    assert transitive_dependents("source-retrieval-policy") == (
        "source-capture",
        "source-verification",
    )
    assert transitive_dependents("review") == (
        "review-evidence",
        "verification-bundle",
        "verification-result",
        "offline-verification",
        "task",
        "closure",
    )
    assert transitive_dependents("toolchain") == (
        "effective-profile",
        "campaign",
        "attestation",
        "comparison",
    )
    assert transitive_dependents("adapter-profile") == ("attestation",)
    assert transitive_dependents("inventory") == (
        "adapter-profile",
        "report",
        "report-diff",
        "review",
        "evidence-signature",
        "review-evidence",
        "verification-bundle",
        "verification-result",
        "offline-verification",
        "campaign",
        "attestation",
        "comparison",
        "task",
        "closure",
    )
    assert (
        digest_dependency_graph_digest()
        == "fe5e3f81e85ca1d47df6d8f04d8729650f7a8be43d8c75119d45c755da4ed5e8"
    )


@pytest.mark.parametrize(
    "nodes, dependencies, messages",
    [
        (
            (DIGEST_NODES[0], DIGEST_NODES[0]),
            (),
            ("node names", "identity fields"),
        ),
        (
            DIGEST_NODES,
            (DIGEST_DEPENDENCIES[0], DIGEST_DEPENDENCIES[0]),
            ("edges must be unique",),
        ),
        (
            DIGEST_NODES,
            (DigestDependency("inventory", "report", ""),),
            ("binding is empty",),
        ),
        (
            DIGEST_NODES,
            (DigestDependency("inventory", cast(DigestNode, "unknown"), "field"),),
            ("unknown node",),
        ),
        (
            DIGEST_NODES,
            (DigestDependency("inventory", "inventory", "field"),),
            ("self-cycle", "cycle reaches inventory"),
        ),
        (
            DIGEST_NODES,
            (
                DigestDependency("inventory", "report", "field"),
                DigestDependency("report", "inventory", "field"),
            ),
            ("cycle reaches inventory", "cycle reaches report"),
        ),
        (
            (
                DigestNodeSpec("inventory", "shared_digest", "one"),
                DigestNodeSpec("policy", "shared_digest", "one"),
            ),
            (),
            ("identity fields",),
        ),
    ],
)
def test_graph_validator_rejects_ambiguous_or_cyclic_schemas(
    nodes: tuple[DigestNodeSpec, ...],
    dependencies: tuple[DigestDependency, ...],
    messages: tuple[str, ...],
) -> None:
    """Malformed graph declarations fail with exact structural evidence."""
    errors = validate_digest_dependency_graph(nodes, dependencies)
    for message in messages:
        assert any(message in error for error in errors)
