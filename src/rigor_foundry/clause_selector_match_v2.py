# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — concrete clause selector matching
"""Match concrete v2 selectors against sealed adapter target triples."""

from __future__ import annotations

from .clause_semantics_scope_v2 import validate_clause_target_v2
from .effect_target_render_v2 import render_target_v2
from .effect_target_table_v2 import EffectTargetTableV2

_WIDE_KINDS = {
    "any-repository": "repository",
    "any-send-channel": "send-channel",
    "any-cloud-resource": "cloud-resource",
}


def _segments(path: str) -> tuple[str, ...]:
    """Split an already validated POSIX absolute path by components."""
    return () if path == "/" else tuple(path[1:].split("/"))


def _path_covers(selector_path: str, target_path: str) -> bool:
    """Match a subtree by components, never by a shared string prefix."""
    selector_parts = _segments(selector_path)
    target_parts = _segments(target_path)
    return target_parts[: len(selector_parts)] == selector_parts


def match_clause_selector_v2(
    *,
    selector: str,
    subject: str,
    exclusion: bool,
    effect_class: str,
    project_id: str,
    target_kind: str,
    target_form: str,
    target_value: str,
    target_table: EffectTargetTableV2,
) -> bool:
    """Match one concrete selector to a previously extracted action target.

    Parameters
    ----------
    selector
        Concrete path, repository, glob, remote, endpoint or host selector.
        Registry templates must be expanded before matching.
    subject, exclusion
        Clause subject and whether this selector is an exclusion; both select
        the grammar and breadth restrictions applied to the selector.
    effect_class, project_id
        Extracted effect class and selected project identity.
    target_kind, target_form, target_value
        Sealed adapter classification and actual independently extracted target.
    target_table
        Exact selected canonical table of permitted class/kind/form triples.

    Returns
    -------
    bool
        Whether the selector covers the target, using path component boundaries
        or exact labels rather than lexical prefix matching.

    Raises
    ------
    ValueError
        A selector or action target violates its closed grammar.
    PermissionError
        The table differs from its canonical body or rejects the target triple.

    Notes
    -----
    The protected caller authenticates adapter custody and resolves filesystem
    targets without following symlinks. Matching supplies no effect permission;
    authorization, clause composition and final revalidation remain separate.
    """
    if EffectTargetTableV2.from_bytes(target_table.body_bytes) != target_table:
        raise PermissionError("effect target table differs from selected exact body")
    if not target_table.allows(effect_class, target_kind, target_form):
        raise PermissionError("adapter target triple is not in the selected table")
    action_selector = render_target_v2({"form": target_form, "value": target_value}, target_kind)
    validate_clause_target_v2(
        action_selector,
        subject="admit",
        effect_class=effect_class,
        project_id=project_id,
        exclusion=False,
    )
    validate_clause_target_v2(
        selector,
        subject=subject,
        effect_class=effect_class,
        project_id=project_id,
        exclusion=exclusion,
    )
    if selector in {"any-remote", "any-endpoint"}:
        return target_form == selector[4:]
    if selector in _WIDE_KINDS:
        return target_kind == _WIDE_KINDS[selector]
    form, separator, value = selector.partition(":")
    if separator != ":" or form not in {
        "path",
        "repo",
        "path-glob",
        "remote",
        "endpoint",
        "host",
    }:
        raise ValueError("template reached the concrete clause matcher")
    if form in {"path", "repo"}:
        return target_form == "path" and _path_covers(value, target_value)
    if form == "path-glob":
        pattern = _segments(value)
        target = _segments(target_value) if target_form == "path" else ()
        return (
            target_form == "path"
            and len(target) >= len(pattern)
            and all(part == "*" or part == target[index] for index, part in enumerate(pattern))
        )
    if form == "host":
        return target_kind == "compute-host" and target_value == selector
    return target_form == form and target_value == value
