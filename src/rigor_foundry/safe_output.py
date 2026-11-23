# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exclusive explicit-output writer
"""Create caller-requested output files without following links or overwriting bytes."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .stable_reads import require_no_follow_descriptor_traversal


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    """Return the filesystem identity fields used for race revalidation."""
    return metadata.st_dev, metadata.st_ino


def _open_directory_no_follow(path: Path) -> int:
    """Open an absolute directory through component-wise no-follow descriptors."""
    require_no_follow_descriptor_traversal(
        "exclusive output creation is unavailable on this platform"
    )
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(
        absolute.anchor,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def write_new_output(path: Path, text: str) -> None:
    """Write UTF-8 text only when ``path`` is a new no-follow regular file.

    Every parent component is opened without following links. The final file is
    created relative to that bound parent with ``O_EXCL`` and ``O_NOFOLLOW``;
    the parent and created inode are revalidated before success is reported.

    UTF-8 is validated before creation. On POSIX, a failed write may leave its
    empty or partial output: cleanup closes descriptors without removing names
    that another writer could have replaced. Windows cleanup uses the retained
    created handle instead of deleting a pathname.

    Parameters
    ----------
    path : pathlib.Path
        Explicit new output below an existing no-follow parent.
    text : str
        Complete UTF-8 output to create without overwriting an existing file.

    Raises
    ------
    ValueError
        If a path component is missing or unsafe, the output already exists,
        or an operating-system error prevents exclusive creation.
    RuntimeError
        If required native capabilities are unavailable or the bound file or
        parent changes during creation.
    UnicodeEncodeError
        If the supplied text cannot be encoded as UTF-8.
    """
    if os.name == "nt":
        from .windows_file_io import write_new_file

        write_new_file(Path(os.path.abspath(path)), text)
        return
    if not path.name:
        raise ValueError("output path has no filename")
    parent_path = Path(os.path.abspath(path.parent))
    parent_descriptor: int | None = None
    recheck_descriptor: int | None = None
    output_descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_no_follow(parent_path)
        parent_before = _identity(os.fstat(parent_descriptor))
        payload = text.encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        output_descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        created = os.fstat(output_descriptor)
        created_identity = _identity(created)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise RuntimeError("new output is not a single-link regular file")
        written = 0
        while written < len(payload):
            count = os.write(output_descriptor, payload[written:])
            if count <= 0:
                raise OSError("output write made no progress")
            written += count
        os.fsync(output_descriptor)
        file_after = os.fstat(output_descriptor)
        path_after = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            _identity(file_after) != created_identity
            or _identity(path_after) != created_identity
            or not stat.S_ISREG(path_after.st_mode)
            or path_after.st_nlink != 1
            or path_after.st_size != len(payload)
        ):
            raise RuntimeError("new output identity changed during creation")
        recheck_descriptor = _open_directory_no_follow(parent_path)
        if _identity(os.fstat(recheck_descriptor)) != parent_before:
            raise RuntimeError("output parent identity changed during creation")
        os.fsync(parent_descriptor)
    except FileExistsError as exc:
        raise ValueError(f"output path already exists: {path}") from exc
    except NotADirectoryError as exc:
        raise ValueError(f"output parent is not a no-follow directory: {path.parent}") from exc
    except FileNotFoundError as exc:
        if parent_descriptor is None:
            raise ValueError(f"output parent does not exist: {path.parent}") from exc
        raise ValueError(f"output path or parent does not exist: {path}") from exc
    except OSError as exc:
        raise ValueError(f"cannot create output safely: {path}") from exc
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if recheck_descriptor is not None:
            os.close(recheck_descriptor)
