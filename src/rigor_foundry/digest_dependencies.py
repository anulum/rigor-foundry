# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — normative digest-dependency registry
"""Declare the direct identity bindings between audit protocol records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .audit_primitives import canonical_digest

DIGEST_DEPENDENCY_SCHEMA_VERSION = "1.1"

DigestNode = Literal[
    "inventory",
    "git-provenance",
    "policy",
    "rule-pack",
    "adapter-lock",
    "standard-pack",
    "toolchain",
    "effective-profile",
    "report",
    "review",
    "campaign",
    "comparison",
    "task",
    "closure",
]


@dataclass(frozen=True)
class DigestNodeSpec:
    """One content-addressed protocol identity in the normative graph."""

    name: DigestNode
    identity_field: str
    owner_module: str

    def to_dict(self) -> dict[str, str]:
        """Serialise the node specification deterministically."""
        return {
            "name": self.name,
            "identity_field": self.identity_field,
            "owner_module": self.owner_module,
        }


@dataclass(frozen=True)
class DigestDependency:
    """One direct, unconditional upstream-to-downstream digest binding."""

    upstream: DigestNode
    downstream: DigestNode
    binding: str

    def to_dict(self) -> dict[str, str]:
        """Serialise the dependency specification deterministically."""
        return {
            "upstream": self.upstream,
            "downstream": self.downstream,
            "binding": self.binding,
        }


DIGEST_NODES: tuple[DigestNodeSpec, ...] = (
    DigestNodeSpec("inventory", "tracked_content_digest", "git_inventory"),
    DigestNodeSpec(
        "git-provenance",
        "git_provenance.identity_digest",
        "git_provenance",
    ),
    DigestNodeSpec("policy", "policy_digest", "models"),
    DigestNodeSpec("rule-pack", "rule_pack_digest", "rules"),
    DigestNodeSpec("adapter-lock", "adapter_digest", "effective_profile"),
    DigestNodeSpec("standard-pack", "pack_digest", "standard_pack"),
    DigestNodeSpec("toolchain", "toolchain.identity_digest", "campaign_models"),
    DigestNodeSpec("effective-profile", "lock_digest", "effective_profile"),
    DigestNodeSpec("report", "report_digest", "models"),
    DigestNodeSpec("review", "review_digest", "models"),
    DigestNodeSpec("campaign", "contract_digest", "campaign_models"),
    DigestNodeSpec("comparison", "comparison_digest", "campaign_compare"),
    DigestNodeSpec("task", "definition_digest", "work_models"),
    DigestNodeSpec("closure", "closure_digest", "work_closure"),
)

DIGEST_DEPENDENCIES: tuple[DigestDependency, ...] = (
    DigestDependency("inventory", "report", "tracked_content_digest"),
    DigestDependency("git-provenance", "report", "git_provenance"),
    DigestDependency("policy", "report", "policy + policy_digest"),
    DigestDependency("rule-pack", "report", "rule_pack_digest"),
    DigestDependency("adapter-lock", "effective-profile", "adapters[*]"),
    DigestDependency("standard-pack", "effective-profile", "pack_digests[*]"),
    DigestDependency("toolchain", "effective-profile", "toolchain_digest"),
    DigestDependency("report", "review", "report_digest"),
    DigestDependency("inventory", "campaign", "tracked_content_digest"),
    DigestDependency("git-provenance", "campaign", "git_provenance"),
    DigestDependency("policy", "campaign", "policy_digest"),
    DigestDependency("rule-pack", "campaign", "rule_pack_digest"),
    DigestDependency("toolchain", "campaign", "toolchain"),
    DigestDependency("campaign", "comparison", "input_contract_digest"),
    DigestDependency("inventory", "task", "baseline_tracked_content_digest"),
    DigestDependency("policy", "task", "source_policy_digest"),
    DigestDependency("rule-pack", "task", "source_rule_pack_digest"),
    DigestDependency("report", "task", "source_report_digest + candidate"),
    DigestDependency("review", "task", "review_digest"),
    DigestDependency("task", "closure", "definition_digest"),
)

_NODE_INDEX = {node.name: index for index, node in enumerate(DIGEST_NODES)}


def direct_dependents(node: DigestNode) -> tuple[DigestNode, ...]:
    """Return directly bound downstream identities in normative node order.

    Parameters
    ----------
    node:
        Upstream identity to query.

    Returns
    -------
    tuple[DigestNode, ...]
        Direct downstream identities.

    """
    if node not in _NODE_INDEX:
        raise ValueError(f"unsupported digest node: {node}")
    dependents = {edge.downstream for edge in DIGEST_DEPENDENCIES if edge.upstream == node}
    return tuple(sorted(dependents, key=_NODE_INDEX.__getitem__))


def transitive_dependents(node: DigestNode) -> tuple[DigestNode, ...]:
    """Return every identity transitively bound to ``node``.

    Parameters
    ----------
    node:
        Upstream identity to query.

    Returns
    -------
    tuple[DigestNode, ...]
        All reachable downstream identities in normative node order.

    """
    pending = list(direct_dependents(node))
    reached: set[DigestNode] = set()
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(direct_dependents(current))
    return tuple(sorted(reached, key=_NODE_INDEX.__getitem__))


def digest_dependency_graph() -> dict[str, object]:
    """Return the versioned, machine-readable normative graph document."""
    return {
        "schema_version": DIGEST_DEPENDENCY_SCHEMA_VERSION,
        "nodes": [node.to_dict() for node in DIGEST_NODES],
        "dependencies": [edge.to_dict() for edge in DIGEST_DEPENDENCIES],
    }


def digest_dependency_graph_digest() -> str:
    """Return the canonical identity of the normative graph document."""
    return canonical_digest(digest_dependency_graph())


def validate_digest_dependency_graph(
    nodes: tuple[DigestNodeSpec, ...] = DIGEST_NODES,
    dependencies: tuple[DigestDependency, ...] = DIGEST_DEPENDENCIES,
) -> tuple[str, ...]:
    """Return structural errors in a digest graph declaration.

    Parameters
    ----------
    nodes:
        Versioned identity nodes to validate.
    dependencies:
        Direct identity bindings to validate.

    Returns
    -------
    tuple[str, ...]
        Deterministically ordered structural errors.

    """
    errors: list[str] = []
    names = tuple(node.name for node in nodes)
    if len(names) != len(set(names)):
        errors.append("digest node names must be unique")
    identities = tuple(node.identity_field for node in nodes)
    if len(identities) != len(set(identities)):
        errors.append("digest identity fields must be unique")
    node_index = {name: index for index, name in enumerate(names)}
    edge_pairs = tuple((edge.upstream, edge.downstream) for edge in dependencies)
    if len(edge_pairs) != len(set(edge_pairs)):
        errors.append("digest dependency edges must be unique")
    adjacency: dict[DigestNode, set[DigestNode]] = {name: set() for name in names}
    for edge in dependencies:
        if edge.upstream not in node_index or edge.downstream not in node_index:
            errors.append("digest dependency references an unknown node")
        else:
            adjacency[edge.upstream].add(edge.downstream)
        if edge.upstream == edge.downstream:
            errors.append(f"digest dependency self-cycle: {edge.upstream}")
        if not edge.binding.strip():
            errors.append(
                f"digest dependency binding is empty: {edge.upstream}->{edge.downstream}"
            )
    for name in names:
        pending = list(adjacency[name])
        reached: set[DigestNode] = set()
        while pending:
            current = pending.pop()
            if current in reached:
                continue
            reached.add(current)
            pending.extend(adjacency[current])
        if name in reached:
            errors.append(f"digest dependency cycle reaches {name}")
    return tuple(errors)
