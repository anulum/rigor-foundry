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
``/dev/fd/N``. After the run the host seals the file against every further write, growth and
shrink, then reads it from offset zero, refusing it when it is larger than the whole-file
limit, and closes it.
"""

from __future__ import annotations

import fcntl
import os
from types import TracebackType
from typing import TYPE_CHECKING, Final, Protocol, final

from .sarif_import_document import MAX_SARIF_BYTES, SarifImportRefused

if TYPE_CHECKING:
    from .adapter_profiles import AdapterProfileEvidence

_NAME: Final = "rigor-second-output"
_SEALS: Final = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


class SecondOutput(Protocol):
    """The typed hook through which one profile run also writes a second output."""

    def command_arguments(
        self, configuration_path: str, target_paths: tuple[str, ...]
    ) -> tuple[str, ...]:
        """Return the run's arguments, with relative targets and the channel's path."""

    def wrap(
        self, launch: tuple[str, ...], descriptors: tuple[int, ...]
    ) -> tuple[tuple[str, ...], tuple[int, ...]]:
        """Return the launch vector behind its bound, and the descriptors it inherits."""

    def complete(self, evidence: AdapterProfileEvidence, stdout: bytes, stderr: bytes) -> None:
        """Receive the run's evidence and output once the run has ended."""


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
        self._descriptor: int | None = create(_NAME, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
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
        """Seal the second output, then return all of it from offset zero.

        Returns
        -------
        bytes
            The exact bytes the tool wrote.

        Raises
        ------
        SarifImportRefused
            With ``too-large`` if the output exceeds the limit.
        ValueError
            If the file cannot be sealed, for example because a writable mapping of it
            exists, or if the read ends short.
        """
        try:
            if fcntl.fcntl(self.descriptor, fcntl.F_GET_SEALS) & _SEALS != _SEALS:
                fcntl.fcntl(self.descriptor, fcntl.F_ADD_SEALS, _SEALS)
        except OSError as error:
            raise ValueError("the second output cannot be sealed against writes") from error
        size = os.fstat(self.descriptor).st_size
        if size > self.limit:
            raise SarifImportRefused("too-large", f"the second output exceeds {self.limit} bytes")
        data = bytearray()
        while len(data) < size:
            chunk = os.pread(self.descriptor, size - len(data), len(data))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != size:
            raise ValueError("the second output ended before its sealed size")
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
