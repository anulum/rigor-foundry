# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository path confinement properties
"""Exercise lexical and resolved path confinement through public helpers."""

from __future__ import annotations

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
from property_strategies import REPOSITORY_COMPONENTS

from rigor_foundry.language_capabilities import (
    filesystem_path_within,
    owning_repository_root,
    repository_path_has_root,
    repository_path_under_roots,
)

_PROPERTY_SETTINGS = settings(max_examples=100, deadline=None)
_COMPONENT_LISTS = st.lists(REPOSITORY_COMPONENTS, min_size=1, max_size=5)


@_PROPERTY_SETTINGS
@given(_COMPONENT_LISTS, _COMPONENT_LISTS)
def test_repository_root_matching_is_component_exact(
    root_parts: list[str],
    child_parts: list[str],
) -> None:
    """Generated descendants match their root and prefix siblings do not."""
    root = "/".join(root_parts)
    path = "/".join((*root_parts, *child_parts))
    assert repository_path_under_roots(path, (root,))
    assert repository_path_has_root(path, (root,))
    assert owning_repository_root(path, (root,)) == root
    sibling = "/".join((f"{root_parts[0]}-sibling", *root_parts[1:], *child_parts))
    assert not repository_path_under_roots(sibling, (root,))


@_PROPERTY_SETTINGS
@given(_COMPONENT_LISTS)
def test_absolute_and_parent_traversal_paths_fail_closed(parts: list[str]) -> None:
    """Absolute and parent-traversing candidates cannot match a repository root."""
    root = parts[0]
    suffix = "/".join(parts)
    assert not repository_path_under_roots(f"/{suffix}", (root,))
    assert not repository_path_under_roots(f"{root}/../{suffix}", (root,))
    assert owning_repository_root(f"{root}/../{suffix}", (root,)) is None


def test_resolved_filesystem_confinement_rejects_real_symlink_escape(tmp_path: Path) -> None:
    """A real filesystem symlink cannot turn an external file into a descendant."""
    root = tmp_path / "repository"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    target = outside / "record.json"
    target.write_text("{}\n", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    assert not filesystem_path_within(root / "escape" / target.name, root)
