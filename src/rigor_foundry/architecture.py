# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — architecture candidate scanner
"""Collect import-graph, facade, ownership, and duplication candidates."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath

from .candidate_anchor import (
    RepositoryTreeAnchor,
    TrackedBlobAnchor,
    bounded_candidate_evidence,
)
from .git_inventory import GitInventory, TrackedFile
from .language_capabilities import (
    owning_repository_root,
    repository_path_under_roots,
)
from .models import AuditPolicy, Candidate
from .python_architecture_observations import PythonDefinition, observe_python_architecture


@dataclass(frozen=True)
class _PythonModule:
    """Bounded first-party Python module metadata."""

    name: str
    file: TrackedFile
    edges: tuple[str, ...]
    wildcard_imports: tuple[tuple[int, str], ...]
    broad_import_lines: tuple[int, ...]
    definitions: tuple[PythonDefinition, ...]
    has_imports: bool


def _module_name(path: str, policy: AuditPolicy) -> str | None:
    """Return the import name represented by one Python path."""
    pure = PurePosixPath(path)
    if pure.suffix != ".py":
        return None
    root = owning_repository_root(path, policy.source_roots)
    if root is None:
        return None
    parts = list(pure.with_suffix("").parts)
    if root == "src" or root.endswith("/src"):
        parts = parts[len(PurePosixPath(root).parts) :]
    if parts[-1] == "__init__":
        parts.pop()
    if not parts:
        return None
    return ".".join(parts)


def _match_known_module(name: str, known: frozenset[str]) -> str | None:
    """Return the longest known module prefix for an import name."""
    parts = name.split(".")
    for length in range(len(parts), 0, -1):
        candidate = ".".join(parts[:length])
        if candidate in known:
            return candidate
    return None


def _import_edges(module: str, imports: tuple[str, ...], known: frozenset[str]) -> tuple[str, ...]:
    """Resolve import observations against the complete current module names."""
    return tuple(
        sorted(
            {
                match
                for name in imports
                if (match := _match_known_module(name, known)) is not None and match != module
            }
        )
    )


def _python_modules(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[_PythonModule, ...]:
    """Parse tracked first-party Python modules and resolve their edges."""
    named_files = tuple(
        (name, item)
        for item in inventory.files
        if item.text is not None
        for name in [_module_name(item.path, policy)]
        if name is not None
    )
    known = frozenset(name for name, _item in named_files)
    policy_digest = policy.policy_digest
    modules: list[_PythonModule] = []
    for name, item in named_files:
        facts = observe_python_architecture(item, name, policy_digest)
        if facts is None:
            continue
        modules.append(
            _PythonModule(
                name=name,
                file=item,
                edges=_import_edges(name, facts.imports, known),
                wildcard_imports=facts.wildcard_imports,
                broad_import_lines=facts.broad_import_lines,
                definitions=facts.definitions,
                has_imports=facts.has_top_level_imports,
            )
        )
    return tuple(modules)


def _strongly_connected_components(
    graph: dict[str, tuple[str, ...]],
) -> tuple[tuple[str, ...], ...]:
    """Return deterministic non-trivial Tarjan components."""
    next_index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal next_index
        indexes[node] = next_index
        lowlinks[node] = next_index
        next_index += 1
        stack.append(node)
        on_stack.add(node)
        for target in graph.get(node, ()):
            if target not in indexes:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if lowlinks[node] != indexes[node]:
            return
        component = [node]
        while (member := stack.pop()) != node:
            on_stack.remove(member)
            component.append(member)
        on_stack.remove(node)
        if len(component) > 1:
            components.append(tuple(sorted(component)))

    for node in sorted(graph):
        if node not in indexes:
            visit(node)
    return tuple(sorted(components))


def _cycle_candidates(modules: tuple[_PythonModule, ...]) -> tuple[Candidate, ...]:
    """Return one candidate per non-trivial first-party import cycle."""
    graph = {module.name: module.edges for module in modules}
    by_name = {module.name: module for module in modules}
    candidates: list[Candidate] = []
    for component in _strongly_connected_components(graph):
        owner = by_name[component[0]]
        candidates.append(
            Candidate.build(
                category="architecture",
                rule_id="AR001-first-party-import-cycle",
                anchor=TrackedBlobAnchor.build(owner.file, line_start=1),
                symbol=" -> ".join((*component, component[0])),
                evidence=bounded_candidate_evidence("cycle members", component),
                confidence="high",
                rationale="A first-party import cycle can invert ownership and obscure initialisation.",
                verification=(
                    "Trace runtime import order and public ownership for every edge; dismiss only if "
                    "the cycle is type-only or otherwise absent from the production execution graph."
                ),
            )
        )
    return tuple(candidates)


def _wildcard_candidates(modules: tuple[_PythonModule, ...]) -> tuple[Candidate, ...]:
    """Return wildcard-import boundary candidates."""
    candidates: list[Candidate] = []
    for module in modules:
        for line, evidence in module.wildcard_imports:
            candidates.append(
                Candidate.build(
                    category="architecture",
                    rule_id="AR002-wildcard-import-boundary",
                    anchor=TrackedBlobAnchor.build(module.file, line_start=line),
                    symbol=module.name,
                    evidence=evidence,
                    confidence="medium",
                    rationale="A wildcard import hides the explicit API and dependency boundary.",
                    verification=(
                        "Enumerate the intended compatibility exports, downstream consumers, "
                        "and generated API ownership; replace with explicit lazy or static exports "
                        "unless the facade contract is documented and drift-gated."
                    ),
                )
            )
    return tuple(candidates)


def _broad_import_candidates(modules: tuple[_PythonModule, ...]) -> tuple[Candidate, ...]:
    """Return broad optional-import exception candidates."""
    candidates: list[Candidate] = []
    for module in modules:
        for line in module.broad_import_lines:
            candidates.append(
                Candidate.build(
                    category="architecture",
                    rule_id="AR003-broad-optional-import-boundary",
                    anchor=TrackedBlobAnchor.build(module.file, line_start=line),
                    symbol=module.name,
                    evidence="import guarded by bare Exception/BaseException handler",
                    confidence="high",
                    rationale="A broad import guard can mask dependency defects as optional absence.",
                    verification=(
                        "Run the real import with the dependency present, absent, and broken inside "
                        "its package; catch only the expected absence and surface nested failures."
                    ),
                )
            )
    return tuple(candidates)


def _facade_candidates(modules: tuple[_PythonModule, ...]) -> tuple[Candidate, ...]:
    """Return facades that also own executable function bodies."""
    candidates: list[Candidate] = []
    for module in modules:
        name = PurePosixPath(module.file.path).name
        facade_named = name == "__init__.py" or "facade" in name.lower()
        if not facade_named:
            continue
        if not module.has_imports or not module.definitions:
            continue
        first = module.definitions[0]
        candidates.append(
            Candidate.build(
                category="architecture",
                rule_id="AR004-executable-facade",
                anchor=TrackedBlobAnchor.build(
                    module.file,
                    line_start=first.line,
                    line_end=first.end_line,
                ),
                symbol=f"{module.name}; functions={len(module.definitions)}",
                evidence=first.name,
                confidence="medium",
                rationale="A compatibility facade also owns executable function bodies.",
                verification=(
                    "Classify every body as import/lazy-export plumbing or independent execution; "
                    "extract mixed lifecycle or algorithm ownership behind the stable facade."
                ),
            )
        )
    return tuple(candidates)


def _test_stems(inventory: GitInventory, policy: AuditPolicy) -> frozenset[str]:
    """Return normalised module stems represented by tracked test owners."""
    stems: set[str] = set()
    for item in inventory.files:
        pure = PurePosixPath(item.path)
        if not pure.name.endswith(".py"):
            continue
        if not (
            pure.name.startswith("test_")
            or pure.name.endswith("_test.py")
            or repository_path_under_roots(item.path, policy.test_roots)
        ):
            continue
        stem = pure.stem
        if stem.startswith("test_"):
            stem = stem.removeprefix("test_")
        if stem.endswith("_test"):
            stem = stem.removesuffix("_test")
        stems.add(stem)
    return frozenset(stems)


def _ownership_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
    modules: tuple[_PythonModule, ...],
) -> tuple[Candidate, ...]:
    """Return production modules without an obvious module-named test owner."""
    stems = _test_stems(inventory, policy)
    candidates: list[Candidate] = []
    for module in modules:
        pure = PurePosixPath(module.file.path)
        if pure.name == "__init__.py":
            continue
        if pure.stem.startswith("_") or pure.stem in stems:
            continue
        candidates.append(
            Candidate.build(
                category="architecture",
                rule_id="AR005-no-module-named-test-owner",
                anchor=RepositoryTreeAnchor.build(inventory, path=module.file.path),
                symbol=module.name,
                evidence=f"no tracked test stem matches {pure.stem}",
                confidence="low",
                rationale="The production module has no obvious dedicated module-named test owner.",
                verification=(
                    "Search integration and public-contract tests for this module's actual production "
                    "surface; either record the named owner or add a dedicated real-surface test."
                ),
            )
        )
    return tuple(candidates)


def _duplicate_definition_candidates(
    modules: tuple[_PythonModule, ...],
) -> tuple[Candidate, ...]:
    """Return exact duplicated non-trivial top-level implementation bodies."""
    owners: dict[str, list[tuple[_PythonModule, PythonDefinition]]] = defaultdict(list)
    for module in modules:
        for definition in module.definitions:
            if definition.body_digest is not None:
                owners[definition.body_digest].append((module, definition))
    candidates: list[Candidate] = []
    for digest, definitions in sorted(owners.items()):
        if len(definitions) < 2:
            continue
        locations = tuple(
            sorted(f"{module.name}.{definition.name}" for module, definition in definitions)
        )
        module, definition = min(
            definitions,
            key=lambda item: (item[0].file.path, item[1].line),
        )
        candidates.append(
            Candidate.build(
                category="architecture",
                rule_id="AR006-duplicate-python-implementation",
                anchor=TrackedBlobAnchor.build(
                    module.file,
                    line_start=definition.line,
                    line_end=definition.end_line,
                ),
                symbol=definition.name,
                evidence=bounded_candidate_evidence(
                    f"duplicate body {digest[:16]} owners",
                    locations,
                ),
                confidence="medium",
                rationale="Multiple first-party functions own an exact non-trivial implementation body.",
                verification=(
                    "Confirm whether the definitions are intentional independent protocol adapters, "
                    "generated outputs, or duplicated ownership; consolidate only when dependencies "
                    "and public identities permit it."
                ),
            )
        )
    return tuple(candidates)


def scan_architecture(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return static architecture candidates for one tracked inventory.

    Parameters
    ----------
    inventory:
        Exact Git-tracked repository inventory.
    policy:
        Repository-local source roots and package configuration.

    Returns
    -------
    tuple[Candidate, ...]
        Import, facade, ownership, and duplicate-body signals requiring review.

    """
    modules = _python_modules(inventory, policy)
    return (
        *_cycle_candidates(modules),
        *_wildcard_candidates(modules),
        *_broad_import_candidates(modules),
        *_facade_candidates(modules),
        *_ownership_candidates(inventory, policy, modules),
        *_duplicate_definition_candidates(modules),
    )
