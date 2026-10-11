# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — clause-scope target grammar
"""Validate the closed Stage-B target strings before registry expansion."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit

from .effect_target_grammar_v2 import TARGET_VARIANT_V2

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_VARIANT: Final = TARGET_VARIANT_V2
_SCHEME: Final = re.compile(r"[a-z][a-z0-9+.-]*\Z")
_ONE_ID: Final = frozenset(
    {
        "project-root",
        "project-coordination",
        "group-projects",
        "group-project-records",
        "group-memory",
        "group-exchange-state",
        "group-exchange-inbox",
    }
)
_ANY: Final = frozenset(
    {
        "any-remote",
        "any-endpoint",
        "any-send-channel",
        "any-cloud-resource",
        "any-repository",
    }
)


def _path(value: str, *, glob: bool) -> None:
    """Reject path aliases and restrict a glob star to one full segment."""
    if (
        not value.startswith("/")
        or (value != "/" and value.endswith("/"))
        or (value != "/" and any(part in {"", ".", ".."} for part in value[1:].split("/")))
        or any(ord(char) < 0x20 for char in value)
    ):
        raise ValueError("semantics path is not canonical absolute POSIX")
    parts = [] if value == "/" else value[1:].split("/")
    if any("*" in part and (not glob or part != "*") for part in parts):
        raise ValueError("semantics path glob must use full segments in exclusions")
    if glob and any(any(char in part for char in "?[]") for part in parts):
        raise ValueError("semantics path glob contains a forbidden wildcard")


def _remote(value: str) -> None:
    """Apply the journal-v4 remote URL shape before adapter query checks."""
    scheme, separator, remainder = value.partition("://")
    parsed = urlsplit(value)
    if (
        separator != "://"
        or not remainder
        or _SCHEME.fullmatch(scheme) is None
        or parsed.scheme != scheme
        or not parsed.netloc
        or "@" in parsed.netloc
        or "%40" in parsed.netloc.lower()
        or parsed.fragment
        or "#" in value
        or any(ord(char) <= 0x20 for char in value)
    ):
        raise ValueError("semantics remote URL is malformed")


def _one_id(value: str) -> None:
    """Check a substituted canonical-id shape, without registry authority."""
    if _ID.fullmatch(value) is None:
        raise ValueError("semantics target id is malformed")


def validate_clause_target_v2(
    target: str, *, subject: str, effect_class: str, project_id: str, exclusion: bool
) -> None:
    """Validate one selector string for its clause role.

    Parameters
    ----------
    target : str
        Concrete selector, with canonical path, URL or identifier syntax.
    subject : str
        Parsed clause subject, such as admit or veto.
    effect_class : str
        Parsed effect class used by read and inbox selectors.
    project_id : str
        Exact project identifier required by project selectors.
    exclusion : bool
        Whether this selector is an exclusion rather than a target.

    Raises
    ------
    ValueError
        Selector syntax or its role-specific restrictions differ.

    Notes
    -----
    Registry resolution and effect applicability remain consumer-owned.
    """
    if not target or "{" in target or "}" in target:
        raise ValueError("semantics target has a placeholder or is empty")
    if target in _ANY:
        if exclusion or subject != "veto":
            raise ValueError("semantics any target is veto-only")
        return
    if target == "monorepo-read-root":
        if exclusion or subject not in {"admit", "veto"} or effect_class != "read":
            raise ValueError("semantics monorepo-read-root differs")
        return
    form, separator, value = target.partition(":")
    if separator != ":" or not value:
        raise ValueError("semantics target form differs")
    if form == "path-glob":
        if not exclusion or subject == "veto":
            raise ValueError("semantics path-glob is exclusion-only, never veto")
        _path(value, glob=True)
        return
    if form in {"path", "repo"}:
        _path(value, glob=False)
        return
    if form == "remote":
        _remote(value)
        return
    if form == "endpoint":
        service, colon, resource = value.partition(":")
        if (
            colon != ":"
            or service == "host"
            or _VARIANT.fullmatch(service) is None
            or _VARIANT.fullmatch(resource) is None
        ):
            raise ValueError("semantics endpoint is malformed")
        return
    if form == "host":
        if _VARIANT.fullmatch(value) is None:
            raise ValueError("semantics host id is malformed")
        return
    if form == "group-workspace":
        ids = value.split("/")
        if len(ids) not in (1, 2):
            raise ValueError("semantics group-workspace arity differs")
        for item in ids:
            _one_id(item)
        if len(ids) == 2 and ids[1] != project_id:
            raise ValueError("semantics group-workspace project differs")
        return
    if form in _ONE_ID:
        _one_id(value)
        if form in {"project-root", "project-coordination"} and value != project_id:
            raise ValueError("semantics project target differs")
        if form == "group-exchange-inbox" and (
            subject not in {"admit", "veto"} or effect_class != "exchange-record-create"
        ):
            raise ValueError("semantics group-exchange-inbox class differs")
        return
    raise ValueError("semantics target form is unknown")


def validate_clause_scope_v2(
    scope: Mapping[str, object], *, subject: str, effect_class: str, project_id: str
) -> None:
    """Validate target and exclusion arrays for one clause.

    Parameters
    ----------
    scope : Mapping[str, object]
        Parsed scope containing targets and exclusions arrays.
    subject : str
        Parsed clause subject.
    effect_class : str
        Parsed effect class.
    project_id : str
        Exact project identifier.

    Raises
    ------
    ValueError
        Arrays or their selector strings violate scope syntax.
    KeyError
        The supplied scope omits a required array.
    """
    for key, exclusion in (("targets", False), ("exclusions", True)):
        values = scope[key]
        if not isinstance(values, list):
            raise ValueError("semantics scope values must be arrays")
        for target in values:
            if not isinstance(target, str):
                raise ValueError("semantics scope target must be text")
            validate_clause_target_v2(
                target,
                subject=subject,
                effect_class=effect_class,
                project_id=project_id,
                exclusion=exclusion,
            )


def bind_clause_scope_groups_v2(
    scope: Mapping[str, object],
    *,
    owning_group_id: str,
    registered_group_ids: frozenset[str],
) -> None:
    """Check group references against a selected registry group set.

    Parameters
    ----------
    scope : Mapping[str, object]
        Previously parsed scope with targets and exclusions arrays.
    owning_group_id : str
        Selected project owner group.
    registered_group_ids : frozenset[str]
        Complete group set supplied by the host registry consumer.

    Raises
    ------
    PermissionError
        Owner is absent, a selector names another owner, or an inbox is not foreign.
    ValueError
        Target or exclusion arrays contain non-text values.
    KeyError
        The scope omits a required array.

    Notes
    -----
    The caller authenticates the registry source; this check grants no authority.
    """
    if owning_group_id not in registered_group_ids:
        raise PermissionError("semantics owning group is absent from selected registry")
    own_forms = {
        "group-projects",
        "group-project-records",
        "group-workspace",
        "group-memory",
        "group-exchange-state",
    }
    for key in ("targets", "exclusions"):
        values = scope[key]
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            raise ValueError("semantics scope group targets must be text arrays")
        for target in values:
            form, separator, value = target.partition(":")
            if separator and form in own_forms and value.split("/")[0] != owning_group_id:
                raise PermissionError("semantics group target differs from selected project")
            if form == "group-exchange-inbox" and (
                value == owning_group_id or value not in registered_group_ids
            ):
                raise PermissionError("semantics exchange inbox group is not a foreign group")
