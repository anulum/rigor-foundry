# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — remediation graph invariants
"""Provide graph, path-overlap, and adapter-command invariants for remediation."""

from pathlib import PurePosixPath
from typing import Protocol

from .effective_profile import AdapterLock
from .models import canonical_digest


class ProcedureCommand(Protocol):
    """Structural command fields required by locked-procedure validation."""

    @property
    def adapter_id(self) -> str:
        """Return the forward adapter identifier."""
        ...

    @property
    def argv(self) -> tuple[str, ...]:
        """Return the exact forward argv."""
        ...

    @property
    def rollback_adapter_id(self) -> str:
        """Return the rollback adapter identifier, if configured."""
        ...

    @property
    def rollback_argv(self) -> tuple[str, ...]:
        """Return the exact rollback argv."""
        ...


def argv_digest(argv: tuple[str, ...]) -> str:
    """Return the canonical digest bound by ``AdapterLock.command_digest``."""
    return canonical_digest({"argv": list(argv)})


def assert_locked_commands(
    adapters: tuple[AdapterLock, ...],
    procedures: tuple[ProcedureCommand, ...],
) -> None:
    """Require every procedure and rollback argv to match one exact adapter lock."""
    locked = {item.adapter_id: item for item in adapters}
    for procedure in procedures:
        commands = (
            (procedure.adapter_id, procedure.argv, "procedure"),
            (procedure.rollback_adapter_id, procedure.rollback_argv, "rollback"),
        )
        for adapter_id, argv, label in commands:
            if not adapter_id:
                continue
            adapter = locked.get(adapter_id)
            if adapter is None:
                raise ValueError(f"plan {label} references unlocked adapter: {adapter_id}")
            if adapter.command_digest != argv_digest(argv):
                raise ValueError(f"plan {label} argv does not match locked command digest")


def paths_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """Return whether either path set contains an equal, parent, or child path."""
    pairs = ((PurePosixPath(a), PurePosixPath(b)) for a in left for b in right)
    return any(a == b or a in b.parents or b in a.parents for a, b in pairs)


def assert_dag(nodes: set[str], edges: dict[str, tuple[str, ...]], field: str) -> None:
    """Reject unknown dependencies and directed cycles."""
    unknown = {dependency for values in edges.values() for dependency in values}.difference(nodes)
    if unknown:
        raise ValueError(f"{field} contains unknown dependencies: " + ", ".join(sorted(unknown)))
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError(f"{field} contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for dependency in edges[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(nodes):
        visit(node)
