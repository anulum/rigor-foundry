# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — first-operation extracted invocation binding
"""Compare all caller declarations with protected first-operation extraction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from . import extract_content_byte_count, extract_fixed_variant, extract_path_target
from .atomic_file_replace_invocation import AtomicFileReplaceInvocationV2
from .path_admission_v2 import PinnedPathScopeV2, canonicalize_atomic_path_v2


@dataclass(frozen=True)
class ExtractedAtomicFileReplaceV2:
    """One checked target, byte count, variant and original content.

    Attributes
    ----------
    target_ref : dict[str, str]
        Exact path reference returned by the host canonicalizer.
    byte_count : int
        Length of the actual decoded replacement content.
    operation_variant : str
        Fixed replace-or-create variant.
    content : bytes
        Original decoded content whose length and declarations were checked.

    Notes
    -----
    This value grants no write permission and retains no filesystem descriptor.
    A protected executor must repeat admission under its own effect lease.
    """

    target_ref: dict[str, str]
    byte_count: int
    operation_variant: str
    content: bytes


def extract_atomic_file_replace_v2(
    payload: bytes, *, canonicalize_path: Callable[[str], object]
) -> ExtractedAtomicFileReplaceV2:
    """Compare extracted values, without granting filesystem authority.

    The protected binder must inject its own pinned no-follow canonicaliser;
    a caller-supplied callback is never an admission proof. It must treat any
    exception from that callback as a refusal.

    Parameters
    ----------
    payload : bytes
        Canonical bounded atomic-replacement invocation.
    canonicalize_path : Callable[[str], object]
        Host-selected callback that verifies the exact requested path.

    Returns
    -------
    ExtractedAtomicFileReplaceV2
        Content and extracted values after all declarations agree.

    Raises
    ------
    ValueError
        If invocation or returned target-reference validation fails.
    PermissionError
        If any declaration or returned path differs.
    OSError
        Propagated from the host's filesystem canonicalizer.
    """
    invocation = AtomicFileReplaceInvocationV2.from_bytes(payload)
    target = extract_path_target.extract(payload, canonicalize_path=canonicalize_path)
    count = extract_content_byte_count.extract(payload)
    variant = extract_fixed_variant.extract(payload)
    if (
        target != invocation.declared_target_ref
        or count != invocation.declared_byte_count
        or variant != invocation.declared_operation_variant
    ):
        raise PermissionError("atomic replacement declared values differ from extraction")
    return ExtractedAtomicFileReplaceV2(target, count, variant, invocation.content)


def extract_atomic_file_replace_for_scope_v2(
    payload: bytes, *, scope: PinnedPathScopeV2
) -> ExtractedAtomicFileReplaceV2:
    """Extract through the descriptor-bound check for a protected selected scope.

    The protected binder must construct ``scope`` from its pinned registry;
    arbitrary caller-provided scopes are not admission evidence.

    Parameters
    ----------
    payload : bytes
        Canonical bounded atomic-replacement invocation.
    scope : PinnedPathScopeV2
        Scope derived from the protected selected registry. Lexical paths
        alone do not establish protected custody or an execution permit.

    Returns
    -------
    ExtractedAtomicFileReplaceV2
        Matching declarations checked through the real no-follow path API.
        The observation's descriptors close before this function returns.

    Raises
    ------
    PermissionError
        If parsing, path admission or declaration comparison fails. The
        original exception is retained as the chained cause.
    """
    try:
        return extract_atomic_file_replace_v2(
            payload,
            canonicalize_path=lambda path: canonicalize_atomic_path_v2(path, scope),
        )
    except Exception as exc:
        raise PermissionError("Tier-0 atomic replacement extraction refused") from exc
