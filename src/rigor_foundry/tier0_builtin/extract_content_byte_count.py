# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — content byte count extractor
"""Derive a byte count from the decoded first-operation invocation."""

from __future__ import annotations

from .atomic_file_replace_invocation import AtomicFileReplaceInvocationV2


def extract(payload: bytes) -> int:
    """Count decoded bytes without consulting the caller's declared count.

    Parameters
    ----------
    payload : bytes
        Canonical bounded atomic-replacement invocation.

    Returns
    -------
    int
        Decoded content length, independent of the caller's declared count.

    Raises
    ------
    ValueError
        If any part of the invocation fails public wire validation.
    """
    return len(AtomicFileReplaceInvocationV2.from_bytes(payload).content)
