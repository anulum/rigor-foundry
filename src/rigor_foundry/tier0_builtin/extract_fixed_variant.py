# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed atomic replacement variant extractor
"""Bind the first operation to one reviewed variant independent of disk state."""

from __future__ import annotations

from .atomic_file_replace_invocation import (
    ATOMIC_FILE_REPLACE_VARIANT,
    AtomicFileReplaceInvocationV2,
)


def extract(payload: bytes) -> str:
    """Return the fixed variant after validating the exact invocation wire.

    Parameters
    ----------
    payload : bytes
        Canonical bounded atomic-replacement invocation.

    Returns
    -------
    str
        The fixed replace-or-create variant; the declaration and disk state
        do not determine this value.

    Raises
    ------
    ValueError
        If any part of the invocation fails public wire validation.
    """
    AtomicFileReplaceInvocationV2.from_bytes(payload)
    return ATOMIC_FILE_REPLACE_VARIANT
