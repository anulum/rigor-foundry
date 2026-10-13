# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effect journal descriptor I/O
"""Retain owner-mode descriptor checks and complete bounded journal I/O."""

from __future__ import annotations

import os
import stat


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    """Record file identity while permitting only expected append-size changes."""
    return value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid


def _owner_only(value: os.stat_result, *, directory: bool) -> bool:
    """Require service-owned regular-file or directory custody."""
    kind_ok = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    return kind_ok and value.st_uid == os.geteuid() and value.st_mode & 0o077 == 0


def _write_all(descriptor: int, payload: bytes) -> None:
    """Write all selected bytes or fail before an effect may be invoked."""
    offset = 0
    while offset < len(payload):
        count = os.write(descriptor, payload[offset:])
        if count <= 0:
            raise OSError("effect journal append made no progress")
        offset += count


def _read_exact(descriptor: int, length: int) -> bytes:
    """Read a full selected span despite short regular-file system reads."""
    parts: list[bytes] = []
    remaining = length
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise PermissionError("effect journal record is torn")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)
