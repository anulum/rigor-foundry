# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed language and path capability registry
"""Centralise language support and component-aware path classification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal

LanguageName = Literal[
    "c",
    "go",
    "julia",
    "javascript",
    "lean",
    "mojo",
    "python",
    "rust",
    "shell",
    "systemverilog",
    "typescript",
    "verilog",
    "yaml",
]
DependencyFamily = Literal["c", "javascript", "julia", "rust"]
TestNamingProfile = Literal["generic", "polyglot"]


@dataclass(frozen=True)
class LanguageCapability:
    """Describe scanner support for one lower-case file suffix.

    Parameters
    ----------
    suffix:
        Lower-case suffix including its leading dot.
    language:
        Stable language-family name used by scanner projections.
    scope_scannable:
        Whether unreadable tracked content opens the portable scope rule.
    responsibility_metrics:
        Whether the responsibility-size scanner owns the suffix.
    polyglot_ownership:
        Whether the non-Python ownership scanner owns the suffix.
    dependency_family:
        Relative-dependency parser family, when one exists.
    extensionless_priority:
        Resolution order for imports that omit an extension.
    index_priority:
        Resolution order for imports that target a directory index.
    """

    suffix: str
    language: LanguageName
    scope_scannable: bool
    responsibility_metrics: bool
    polyglot_ownership: bool
    dependency_family: DependencyFamily | None = None
    extensionless_priority: int | None = None
    index_priority: int | None = None


_CAPABILITIES = (
    LanguageCapability(".c", "c", True, True, True, "c", 6),
    LanguageCapability(".cc", "c", True, True, True, "c"),
    LanguageCapability(".cpp", "c", True, True, True, "c", 7),
    LanguageCapability(".h", "c", True, True, True, "c", 8),
    LanguageCapability(".hpp", "c", True, True, True, "c", 9),
    LanguageCapability(".go", "go", True, True, True),
    LanguageCapability(".jl", "julia", True, True, True, "julia", 5),
    LanguageCapability(".js", "javascript", True, True, True, "javascript", 2, 2),
    LanguageCapability(".jsx", "javascript", True, True, True, "javascript", 3, 3),
    LanguageCapability(".lean", "lean", True, True, True),
    LanguageCapability(".mojo", "mojo", True, True, True),
    LanguageCapability(".py", "python", True, True, False),
    LanguageCapability(".pyi", "python", True, True, False),
    LanguageCapability(".rs", "rust", True, True, True, "rust", 4),
    LanguageCapability(".sh", "shell", True, True, False),
    LanguageCapability(".sv", "systemverilog", True, True, True),
    LanguageCapability(".ts", "typescript", True, True, True, "javascript", 0, 0),
    LanguageCapability(".tsx", "typescript", True, True, True, "javascript", 1, 1),
    LanguageCapability(".v", "verilog", True, True, True),
    LanguageCapability(".yaml", "yaml", True, False, False),
    LanguageCapability(".yml", "yaml", True, False, False),
)

_CAPABILITY_MAP = {item.suffix: item for item in _CAPABILITIES}
if len(_CAPABILITY_MAP) != len(_CAPABILITIES):
    raise RuntimeError("language capability suffixes must be unique")
if any(not suffix.startswith(".") or suffix != suffix.lower() for suffix in _CAPABILITY_MAP):
    raise RuntimeError("language capability suffixes must be lower-case dotted values")
LANGUAGE_CAPABILITIES: Mapping[str, LanguageCapability] = MappingProxyType(_CAPABILITY_MAP)
"""Read-only mapping from a unique lower-case suffix to scanner capabilities."""


def suffixes_with(capability: Literal["scope", "responsibility", "polyglot"]) -> frozenset[str]:
    """Return suffixes enabled for one scanner capability projection.

    Parameters
    ----------
    capability:
        Supported projection name.

    Returns
    -------
    frozenset[str]
        Exact suffix set owned by the selected scanner surface.
    """
    if capability == "scope":
        return frozenset(
            suffix for suffix, item in LANGUAGE_CAPABILITIES.items() if item.scope_scannable
        )
    if capability == "responsibility":
        return frozenset(
            suffix for suffix, item in LANGUAGE_CAPABILITIES.items() if item.responsibility_metrics
        )
    return frozenset(
        suffix for suffix, item in LANGUAGE_CAPABILITIES.items() if item.polyglot_ownership
    )


def dependency_family_for(path: str) -> DependencyFamily | None:
    """Return the relative-dependency parser family for ``path`` when supported."""
    capability = LANGUAGE_CAPABILITIES.get(PurePosixPath(path).suffix.lower())
    return capability.dependency_family if capability is not None else None


def extensionless_dependency_suffixes() -> tuple[str, ...]:
    """Return deterministic suffixes used to resolve extensionless dependencies."""
    return tuple(
        suffix
        for _priority, suffix in sorted(
            (item.extensionless_priority, suffix)
            for suffix, item in LANGUAGE_CAPABILITIES.items()
            if item.extensionless_priority is not None
        )
    )


def index_dependency_suffixes() -> tuple[str, ...]:
    """Return deterministic suffixes used to resolve directory index dependencies."""
    return tuple(
        suffix
        for _priority, suffix in sorted(
            (item.index_priority, suffix)
            for suffix, item in LANGUAGE_CAPABILITIES.items()
            if item.index_priority is not None
        )
    )


def _parts(value: str) -> tuple[str, ...]:
    """Return normalised non-empty repository-relative components."""
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        return ()
    return tuple(part for part in pure.parts if part not in {"", "."})


def repository_path_under_roots(path: str, roots: tuple[str, ...]) -> bool:
    """Return whether a repository-relative path has one configured root prefix."""
    path_parts = _parts(path)
    return any(
        path_parts[: len(root_parts)] == root_parts
        for root in roots
        if (root_parts := _parts(root))
    )


def repository_path_has_root(path: str, roots: tuple[str, ...]) -> bool:
    """Return whether a path contains one configured root as whole components."""
    path_parts = _parts(path)
    for root in roots:
        root_parts = _parts(root)
        if not root_parts:
            continue
        width = len(root_parts)
        if any(
            path_parts[index : index + width] == root_parts
            for index in range(len(path_parts) - width + 1)
        ):
            return True
    return False


def owning_repository_root(path: str, roots: tuple[str, ...]) -> str | None:
    """Return the most specific configured root prefix that owns ``path``."""
    matches = tuple(
        (len(root_parts), root.rstrip("/"))
        for root in roots
        if (root_parts := _parts(root)) and _parts(path)[: len(root_parts)] == root_parts
    )
    if not matches:
        return None
    return max(matches)[1]


def filesystem_path_within(path: Path, root: Path) -> bool:
    """Return whether resolved ``path`` is contained by resolved ``root``.

    This lexical helper does not replace descriptor-bound no-follow filesystem
    operations used by security-sensitive inventory collection.
    """
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def is_test_path(
    path: str,
    test_roots: tuple[str, ...],
    *,
    profile: TestNamingProfile = "generic",
) -> bool:
    """Return whether ``path`` matches configured roots or test naming rules.

    ``polyglot`` additionally recognises singular and plural native suffixes,
    while ``generic`` preserves GodFile and authenticity scanner behaviour.
    """
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if repository_path_has_root(path, test_roots):
        return True
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    if ".test." in name or ".spec." in name:
        return True
    suffix = pure.suffix.lower()
    return profile == "polyglot" and name.endswith((f"_test{suffix}", f"_tests{suffix}"))
