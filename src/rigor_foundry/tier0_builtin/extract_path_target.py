# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected path target extractor
"""Extract an atomic replacement target through the host's no-follow check."""

from __future__ import annotations

from collections.abc import Callable

from ..effect_journal_records_v2 import parse_effect_target_ref_v2
from .atomic_file_replace_invocation import AtomicFileReplaceInvocationV2


def extract(payload: bytes, *, canonicalize_path: Callable[[str], object]) -> dict[str, str]:
    """Require the host canonicaliser to return the exact safe path target.

    The protected host supplies a canonicaliser that refuses symlinks, unsafe
    repository segments, directories and absent parents. This extractor has
    no independent filesystem, environment, clock or network access.

    Parameters
    ----------
    payload : bytes
        Canonical bounded atomic-replacement invocation.
    canonicalize_path : Callable[[str], object]
        Host callback for the actual requested path. The protected consumer
        supplies its selected-scope no-follow canonicalizer and treats every
        callback exception as a refusal. Arbitrary callbacks have no authority.

    Returns
    -------
    dict[str, str]
        Exact path target reference matching the requested path.

    Raises
    ------
    ValueError
        If the invocation or returned target reference is malformed.
    PermissionError
        If the callback returns a different path or target form.
    OSError
        Propagated when the host's real filesystem observation fails.
    """
    invocation = AtomicFileReplaceInvocationV2.from_bytes(payload)
    form, value = parse_effect_target_ref_v2(canonicalize_path(invocation.path))
    if form != "path" or value != invocation.path:
        raise PermissionError("atomic replacement canonical path differs from invocation")
    return {"form": form, "value": value}
