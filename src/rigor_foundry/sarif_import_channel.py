# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the inherited memory file that carries a sandboxed second output
"""Carry a sandboxed tool's second output to the host without any writable mount.

The host creates one anonymous memory file, close-on-exec, and passes it to the sandboxed
tool only through the process's inherited descriptors. The tool writes its second output to
``/dev/fd/N``. After the run the host reads the file from offset zero, once, refusing it
when it is larger than the whole-file limit, and then closes it.
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Final, final

from .sarif_import_document import MAX_SARIF_BYTES, SarifImportRefused

_NAME: Final = "rigor-second-output"


@final
class SecondOutputChannel:
    """One close-on-exec memory file that a sandboxed tool writes its second output to."""

    def __init__(self, limit: int = MAX_SARIF_BYTES) -> None:
        """Create the memory file.

        Parameters
        ----------
        limit : int
            The largest second output accepted, in bytes.

        Raises
        ------
        RuntimeError
            If the platform has no anonymous memory files.
        """
        create = getattr(os, "memfd_create", None)
        if create is None:
            raise RuntimeError("a second output channel needs anonymous memory files")
        self._descriptor: int | None = create(_NAME, os.MFD_CLOEXEC)
        self.limit = limit

    @property
    def descriptor(self) -> int:
        """Return the descriptor to pass to the tool, while the channel is open."""
        if self._descriptor is None:
            raise ValueError("the second output channel is closed")
        return self._descriptor

    @property
    def path(self) -> str:
        """Return the ``/dev/fd/N`` path the tool writes to."""
        return f"/dev/fd/{self.descriptor}"

    def read(self) -> bytes:
        """Return the whole second output, once, from offset zero.

        Returns
        -------
        bytes
            The exact bytes the tool wrote.

        Raises
        ------
        SarifImportRefused
            With ``too-large`` if the output exceeds the limit.
        ValueError
            If the output changed while it was read.
        """
        size = os.fstat(self.descriptor).st_size
        if size > self.limit:
            raise SarifImportRefused("too-large", f"the second output exceeds {self.limit} bytes")
        data = bytearray()
        while len(data) < size:
            chunk = os.pread(self.descriptor, size - len(data), len(data))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != size or os.fstat(self.descriptor).st_size != size:
            raise ValueError("the second output changed while it was read")
        return bytes(data)

    def close(self) -> None:
        """Close the memory file; closing twice is harmless."""
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def __enter__(self) -> SecondOutputChannel:
        """Return the open channel."""
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        """Close the channel on every exit."""
        self.close()
