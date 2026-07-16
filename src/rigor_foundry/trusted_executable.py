# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — component-safe trusted executable runner
"""Open, hash, and run trusted executables through bounded descriptors."""

from __future__ import annotations

import hashlib
import os
import selectors
import signal
import stat
import subprocess  # nosec B404
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final

_READ_SIZE: Final = 8192


@dataclass(frozen=True)
class ExecutableSnapshot:
    """Stable filesystem and content identity for one trusted executable."""

    device: int
    inode: int
    mode: int
    owner_uid: int
    group_gid: int
    link_count: int
    size: int
    modified_ns: int
    digest: str


@dataclass(frozen=True)
class BoundedProcessResult:
    """Bounded output and exit status from one descriptor-pinned command."""

    returncode: int
    stdout: bytes
    stderr: bytes


class TrustedExecutable:
    """One validated executable held open until all pinned calls finish."""

    def __init__(self, path: Path, descriptor: int, snapshot: ExecutableSnapshot) -> None:
        """Retain the exact descriptor and its validated snapshot."""
        self.path = path
        self._descriptor: int | None = descriptor
        self.snapshot = snapshot

    @property
    def descriptor(self) -> int:
        """Return the live descriptor or reject use after close."""
        if self._descriptor is None:
            raise RuntimeError("trusted executable descriptor is closed")
        return self._descriptor

    @property
    def execution_path(self) -> str:
        """Return the Linux descriptor path used for pinned execution."""
        descriptor_root = Path("/proc/self/fd")
        if not descriptor_root.is_dir():
            raise RuntimeError("descriptor-pinned executable execution is unavailable")
        return f"{descriptor_root}/{self.descriptor}"

    def close(self) -> None:
        """Close the retained descriptor exactly once."""
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def __enter__(self) -> TrustedExecutable:
        """Return this live handle."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the descriptor on every context exit."""
        del exc_type, exc_value, traceback
        self.close()


def _open_parent(path: Path) -> int:
    """Open an absolute parent through descriptor-relative no-follow steps."""
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if no_follow is None or directory is None or os.open not in os.supports_dir_fd:
        raise RuntimeError("component-safe executable inspection is unavailable")
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise RuntimeError("trusted executable path must be an absolute file path")
    descriptor = os.open("/", os.O_RDONLY | directory | close_on_exec)
    try:
        for component in path.parts[1:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | directory | no_follow | close_on_exec,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _snapshot_descriptor(
    descriptor: int,
    *,
    path: Path,
    required_owner_uid: int,
    forbidden_mode_bits: int,
    require_single_link: bool,
) -> ExecutableSnapshot:
    """Validate and hash the exact open executable descriptor."""
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"trusted sandbox executable is not a regular file: {path}")
    if metadata.st_uid != required_owner_uid:
        raise RuntimeError(f"trusted sandbox executable has an untrusted owner: {path}")
    if stat.S_IMODE(metadata.st_mode) & forbidden_mode_bits:
        raise RuntimeError(f"trusted sandbox executable has unsafe mode bits: {path}")
    if require_single_link and metadata.st_nlink != 1:
        raise RuntimeError(f"trusted sandbox executable must have one link: {path}")
    if not metadata.st_mode & stat.S_IXUSR:
        raise RuntimeError(f"trusted sandbox executable is not owner-executable: {path}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return ExecutableSnapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        owner_uid=metadata.st_uid,
        group_gid=metadata.st_gid,
        link_count=metadata.st_nlink,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        digest=digest.hexdigest(),
    )


def open_trusted_executable(
    path: Path,
    *,
    required_owner_uid: int,
    forbidden_mode_bits: int,
    require_single_link: bool,
) -> TrustedExecutable:
    """Open one executable without following any path component."""
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_parent(path)
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            raise RuntimeError("component-safe executable inspection is unavailable")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise RuntimeError(f"trusted sandbox executable is unavailable: {path}") from exc
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    live_descriptor = descriptor
    try:
        snapshot = _snapshot_descriptor(
            live_descriptor,
            path=path,
            required_owner_uid=required_owner_uid,
            forbidden_mode_bits=forbidden_mode_bits,
            require_single_link=require_single_link,
        )
    except Exception:
        os.close(live_descriptor)
        raise
    return TrustedExecutable(path, live_descriptor, snapshot)


def snapshot_executable(
    path: Path,
    *,
    required_owner_uid: int,
    forbidden_mode_bits: int,
    require_single_link: bool,
) -> ExecutableSnapshot:
    """Return one closed-after-use trusted executable snapshot."""
    with open_trusted_executable(
        path,
        required_owner_uid=required_owner_uid,
        forbidden_mode_bits=forbidden_mode_bits,
        require_single_link=require_single_link,
    ) as executable:
        return executable.snapshot


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the entire command process group and reap its leader."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    if process.poll() is None:
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.25)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait(timeout=2)


def run_trusted_command(
    executable: TrustedExecutable,
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    output_limit: int,
) -> BoundedProcessResult:
    """Run a pinned descriptor with streaming output and process-tree bounds."""
    if timeout_seconds < 1 or output_limit < 1:
        raise ValueError("trusted command bounds must be positive")
    try:
        process = subprocess.Popen(  # nosec B603
            (executable.execution_path, *arguments),
            env=environment,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=(executable.descriptor,),
        )
    except OSError as exc:
        raise RuntimeError("trusted executable metadata query failed") from exc
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        raise RuntimeError("trusted executable output pipes were not created")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    exceeded = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_group(process)
                break
            for key, _mask in selector.select(timeout=min(remaining, 0.1)):
                total = sum(len(buffer) for buffer in buffers.values())
                allowed = output_limit - total
                chunk = os.read(key.fd, min(_READ_SIZE, allowed + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                label = str(key.data)
                buffers[label].extend(chunk[:allowed])
                if len(chunk) > allowed:
                    exceeded = True
                    _terminate_process_group(process)
                    break
            if exceeded:
                break
        if process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_group(process)
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _terminate_process_group(process)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            _terminate_process_group(process)
        else:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
    if timed_out:
        raise RuntimeError("trusted executable metadata query timed out")
    if exceeded:
        raise RuntimeError("trusted executable metadata query exceeded output limit")
    return BoundedProcessResult(
        returncode=int(process.returncode),
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
    )
