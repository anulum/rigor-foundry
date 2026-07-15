# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — non-Python dependency and test-owner scanner
"""Collect cross-language relative-cycle and dedicated-test ownership signals."""

from __future__ import annotations

import posixpath
import re
from pathlib import PurePosixPath

from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate

_SOURCE_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".jl",
        ".js",
        ".jsx",
        ".lean",
        ".mojo",
        ".rs",
        ".sv",
        ".ts",
        ".tsx",
        ".v",
    }
)

_JS_IMPORT = re.compile(
    r"(?:\bfrom\s*|\bimport\s*|\brequire\s*\()"
    r"[\"'](?P<path>\.{1,2}/[^\"']+)[\"']"
)
_C_INCLUDE = re.compile(r"^\s*#\s*include\s*[\"<](?P<path>[^\">]+)[\">]")
_JULIA_INCLUDE = re.compile(r"\binclude\s*\(\s*[\"'](?P<path>[^\"']+)[\"']\s*\)")
_RUST_MODULE = re.compile(r"^\s*(?:pub\s+)?mod\s+(?P<path>[A-Za-z_][A-Za-z0-9_]*)\s*;")


def _is_test_path(path: str, policy: AuditPolicy) -> bool:
    """Return whether a non-Python path belongs to a recognised test surface."""
    pure = PurePosixPath(path)
    name = pure.name.lower()
    return (
        any(root in pure.parts for root in policy.test_roots)
        or ".test." in name
        or ".spec." in name
        or name.startswith("test_")
        or name.endswith(("_test" + pure.suffix.lower(), "_tests" + pure.suffix.lower()))
    )


def _candidate_paths(owner: str, dependency: str) -> tuple[str, ...]:
    """Return normalised repository paths that may own one relative import."""
    base = PurePosixPath(owner).parent.as_posix()
    joined = posixpath.normpath(posixpath.join(base, dependency))
    if joined == ".." or joined.startswith("../"):
        return ()
    pure = PurePosixPath(joined)
    if pure.suffix:
        return (pure.as_posix(),)
    return (
        tuple(
            f"{pure.as_posix()}{suffix}"
            for suffix in (".ts", ".tsx", ".js", ".jsx", ".rs", ".jl", ".c", ".cpp", ".h", ".hpp")
        )
        + tuple(f"{pure.as_posix()}/index{suffix}" for suffix in (".ts", ".tsx", ".js", ".jsx"))
        + (f"{pure.as_posix()}/mod.rs",)
    )


def _relative_dependencies(item: TrackedFile) -> tuple[str, ...]:
    """Return textual relative dependency references from one source file."""
    if item.text is None:
        return ()
    suffix = PurePosixPath(item.path).suffix.lower()
    references: list[str] = []
    for line in item.text.splitlines():
        if suffix in {".js", ".jsx", ".ts", ".tsx"}:
            references.extend(match.group("path") for match in _JS_IMPORT.finditer(line))
        elif suffix in {".c", ".cc", ".cpp", ".h", ".hpp"}:
            match = _C_INCLUDE.match(line)
            if match is not None and not match.group("path").startswith(("/", "sys/")):
                references.append(match.group("path"))
        elif suffix == ".jl":
            references.extend(match.group("path") for match in _JULIA_INCLUDE.finditer(line))
        elif suffix == ".rs":
            match = _RUST_MODULE.match(line)
            if match is not None:
                references.append(match.group("path"))
    return tuple(references)


def _dependency_graph(inventory: GitInventory) -> dict[str, tuple[str, ...]]:
    """Return resolved non-Python relative dependency edges."""
    tracked = {item.path for item in inventory.files}
    graph: dict[str, tuple[str, ...]] = {}
    for item in inventory.files:
        if PurePosixPath(item.path).suffix.lower() not in _SOURCE_EXTENSIONS or item.text is None:
            continue
        targets: set[str] = set()
        for dependency in _relative_dependencies(item):
            for candidate in _candidate_paths(item.path, dependency):
                if candidate in tracked and candidate != item.path:
                    targets.add(candidate)
                    break
        graph[item.path] = tuple(sorted(targets))
    return graph


def _components(graph: dict[str, tuple[str, ...]]) -> tuple[tuple[str, ...], ...]:
    """Return deterministic non-trivial strongly connected components."""
    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    active: set[str] = set()
    found: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        active.add(node)
        for target in graph.get(node, ()):
            if target not in indexes:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in active:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if indexes[node] != lowlinks[node]:
            return
        component: list[str] = []
        while stack:
            member = stack.pop()
            active.remove(member)
            component.append(member)
            if member == node:
                break
        if len(component) > 1:
            found.append(tuple(sorted(component)))

    for node in sorted(graph):
        if node not in indexes:
            visit(node)
    return tuple(sorted(found))


def _cycle_candidates(inventory: GitInventory) -> tuple[Candidate, ...]:
    """Return non-Python relative dependency cycle candidates."""
    candidates: list[Candidate] = []
    for component in _components(_dependency_graph(inventory)):
        candidates.append(
            Candidate.build(
                category="architecture",
                rule_id="AR007-relative-dependency-cycle",
                path=component[0],
                line=1,
                symbol=" -> ".join((*component, component[0])),
                evidence=", ".join(component),
                confidence="medium",
                rationale="Relative dependencies form a non-trivial cross-file cycle.",
                verification=(
                    "Trace build/runtime direction and generated ownership for every edge; break "
                    "mixed lifecycle or inverted dependencies while preserving public API/ABI."
                ),
            )
        )
    return tuple(candidates)


def _normalised_test_stems(inventory: GitInventory, policy: AuditPolicy) -> frozenset[str]:
    """Return source-like stems represented by non-Python test owners."""
    stems: set[str] = set()
    for item in inventory.files:
        pure = PurePosixPath(item.path)
        if pure.suffix.lower() not in _SOURCE_EXTENSIONS or not _is_test_path(item.path, policy):
            continue
        stem = pure.stem.lower()
        for prefix in ("test_", "tests_"):
            if stem.startswith(prefix):
                stem = stem.removeprefix(prefix)
        for suffix in ("_test", "_tests", ".test", ".spec"):
            if stem.endswith(suffix):
                stem = stem.removesuffix(suffix)
        stems.add(stem)
    return frozenset(stems)


def _ownership_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return non-Python source owners with no obvious source-named test."""
    test_stems = _normalised_test_stems(inventory, policy)
    candidates: list[Candidate] = []
    for item in inventory.files:
        pure = PurePosixPath(item.path)
        if (
            item.text is None
            or pure.suffix.lower() not in _SOURCE_EXTENSIONS
            or _is_test_path(item.path, policy)
            or pure.stem.lower() in test_stems
        ):
            continue
        candidates.append(
            Candidate.build(
                category="architecture",
                rule_id="AR008-no-polyglot-test-owner",
                path=item.path,
                line=1,
                symbol=pure.stem,
                evidence=f"no tracked non-Python test stem matches {pure.stem}",
                confidence="low",
                rationale="The production owner has no obvious dedicated source-named test surface.",
                verification=(
                    "Trace language-native unit tests and cross-language parity/integration tests; "
                    "record the real owner or add a dedicated public ABI, FFI, or executable contract."
                ),
            )
        )
    return tuple(candidates)


def scan_polyglot_architecture(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return non-Python dependency and test-ownership candidates."""
    return (*_cycle_candidates(inventory), *_ownership_candidates(inventory, policy))
