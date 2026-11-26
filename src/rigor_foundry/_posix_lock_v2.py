# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the POSIX advisory lock call the v2 durable stores use
"""Resolve the POSIX advisory lock call of the v2 durable stores, or refuse by name.

The v2 effect journal, permit anchor store, permit consumption ledger and recovery evidence
store are POSIX-only by design. ``fcntl`` is resolved when a lock is about to be taken, never
when those modules are imported, so the package imports on every platform. Where POSIX file
locks are missing, the lock request is refused before any lock is attempted. The caller makes
the lock call itself, so the lock is taken in the caller's own frame.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

LockCall = Callable[[int, int], None]
_REFUSAL: Final = "the v2 durable stores require POSIX advisory file locks"


def posix_lock_call() -> tuple[LockCall, int, int]:
    """Return the blocking lock call with its shared and exclusive operations.

    Returns
    -------
    tuple[LockCall, int, int]
        ``fcntl.flock``, ``fcntl.LOCK_SH`` and ``fcntl.LOCK_EX``.

    Raises
    ------
    RuntimeError
        If the platform or interpreter has no POSIX advisory file locks.
    """
    try:
        import fcntl
    except ImportError as error:
        raise RuntimeError(_REFUSAL) from error
    if not all(hasattr(fcntl, name) for name in ("flock", "LOCK_EX", "LOCK_SH")):
        raise RuntimeError(_REFUSAL)
    return fcntl.flock, fcntl.LOCK_SH, fcntl.LOCK_EX
