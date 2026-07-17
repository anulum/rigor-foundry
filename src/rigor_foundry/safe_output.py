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


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    """Return the filesystem identity fields used for race revalidation."""
    return metadata.st_dev, metadata.st_ino


def _open_directory_no_follow(path: Path) -> int:
    """Open an absolute directory through component-wise no-follow descriptors."""
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("exclusive output creation is unavailable on this platform")
    if os.open not in os.supports_dir_fd:
        raise RuntimeError("descriptor-relative output creation is unavailable on this platform")
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
    """
    if not path.name:
        raise ValueError("output path has no filename")
    parent_path = Path(os.path.abspath(path.parent))
    parent_descriptor: int | None = None
    recheck_descriptor: int | None = None
    output_descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    succeeded = False
    try:
        parent_descriptor = _open_directory_no_follow(parent_path)
        parent_before = _identity(os.fstat(parent_descriptor))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        output_descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        created = os.fstat(output_descriptor)
        created_identity = _identity(created)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise RuntimeError("new output is not a single-link regular file")
        payload = text.encode("utf-8")
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
        succeeded = True
    except FileExistsError as exc:
        raise ValueError(f"output path already exists: {path}") from exc
    except NotADirectoryError as exc:
        raise ValueError(f"output parent is not a no-follow directory: {path.parent}") from exc
    except FileNotFoundError as exc:
        raise ValueError(f"output parent does not exist: {path.parent}") from exc
    except OSError as exc:
        raise ValueError(f"cannot create output safely: {path}") from exc
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)
        if parent_descriptor is not None:
            if created_identity is not None and not succeeded:
                try:
                    current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
                    if _identity(current) == created_identity:
                        os.unlink(path.name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            os.close(parent_descriptor)
        if recheck_descriptor is not None:
            os.close(recheck_descriptor)
