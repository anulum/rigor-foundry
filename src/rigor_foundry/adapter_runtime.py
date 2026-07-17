# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native-adapter sandbox runtime
"""Build and execute bounded native-adapter sandbox contracts."""

from __future__ import annotations

import hashlib
import os
import selectors
import signal
import subprocess  # nosec B404
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .models import canonical_digest
from .sandbox_provenance import BubblewrapProvenance, inspect_bubblewrap
from .trusted_executable import TrustedExecutable, open_trusted_executable

OUTPUT_LIMIT = 65_536
READ_SIZE = 8_192
BWRAP = Path("/usr/bin/bwrap")
CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
PACKAGE_SOURCE = Path(__file__).resolve().parents[1]
SANDBOX_VERSION = "rigor-foundry-bwrap-v2"
SANDBOX_TOOL = "/run/rigor-adapter-tool"
# This path is a private tmpfs created inside the bubblewrap mount namespace.
SANDBOX_TMP = "/tmp"  # nosec B108
CHILD_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "OTEL_SDK_DISABLED": "true",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "SEMGREP_LOG_FILE": "/dev/null",
    "TMPDIR": SANDBOX_TMP,
    "TRIVY_CACHE_DIR": f"{SANDBOX_TMP}/trivy-cache",
    "XDG_CACHE_HOME": f"{SANDBOX_TMP}/.cache",
}


def file_digest(path: Path) -> str:
    """Return SHA-256 for one regular file without loading it at once."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise ValueError(f"cannot hash native audit executable: {path}") from exc
    return digest.hexdigest()


def contained(path: Path, roots: tuple[Path, ...]) -> bool:
    """Return whether a lexical path is within an explicitly trusted root."""
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def resolved_executable(root: Path, value: str) -> Path:
    """Resolve an executable from fixed roots, never the ambient ``PATH``."""
    trusted_roots = (root, Path(sys.prefix).absolute(), Path("/usr"))
    if value == "{python}":
        candidate = Path(sys.executable).absolute()
    elif Path(value).is_absolute():
        candidate = Path(value)
    elif "/" in value:
        candidate = root / value
    else:
        candidates = (
            Path(sys.prefix) / "bin" / value,
            Path("/usr/bin") / value,
            Path("/bin") / value,
        )
        candidate = next((item for item in candidates if item.exists()), candidates[0])
    absolute = candidate.absolute()
    if not contained(absolute, trusted_roots):
        raise ValueError("native audit executable is outside trusted runtime roots")
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise ValueError(f"native audit executable is unavailable: {value}") from exc
    if not contained(resolved, trusted_roots):
        raise ValueError("native audit executable symlink escapes trusted runtime roots")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"native audit executable is not executable: {value}")
    return absolute


def working_directory(root: Path, relative: str) -> Path:
    """Return a resolved repository-contained working directory."""
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("native audit working directory escapes repository")
    try:
        candidate = (root / relative_path).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("native audit working directory escapes repository") from exc
    if not candidate.is_dir():
        raise ValueError("native audit working directory is not a directory")
    return candidate


def _minimal_mounts(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    """Collapse read-only mount roots already covered by an ancestor."""
    selected: list[Path] = []
    for path in sorted(
        {item.resolve(strict=True) for item in paths}, key=lambda item: len(item.parts)
    ):
        if contained(path, (Path("/usr"),)):
            continue
        if not contained(path, tuple(selected)):
            selected.append(path)
    return tuple(selected)


def _mount_parent_arguments(mounts: tuple[Path, ...]) -> tuple[str, ...]:
    """Create empty ancestors needed for same-path read-only bind mounts."""
    excluded = {Path("/"), Path("/usr"), Path(SANDBOX_TMP)}
    parents: set[Path] = set()
    for mount in mounts:
        parent = mount.parent
        while parent not in excluded:
            parents.add(parent)
            parent = parent.parent
    arguments: list[str] = []
    for parent in sorted(parents, key=lambda item: (len(item.parts), str(item))):
        arguments.extend(("--dir", str(parent)))
    return tuple(arguments)


def sandbox_contract(
    repository: Path,
    executable: Path,
    cwd: Path,
    *,
    repository_destination: Path | None = None,
    repository_identity: str | None = None,
    executable_digest: str | None = None,
    executable_descriptor: int | None = None,
) -> tuple[
    tuple[str, ...],
    dict[str, str],
    BubblewrapProvenance,
    str,
    TrustedExecutable,
]:
    """Build a fixed bubblewrap contract and its canonical identity digest."""
    if not BWRAP.is_file() or not os.access(BWRAP, os.X_OK):
        raise RuntimeError("native audits require /usr/bin/bwrap for read-only isolation")
    provenance = inspect_bubblewrap()
    if provenance.executable_path != str(BWRAP):
        raise RuntimeError("Bubblewrap provenance does not match the sandbox launcher")
    destination = repository if repository_destination is None else repository_destination
    profile_mounts = (CA_BUNDLE,) if executable_descriptor is not None else ()
    mounts = _minimal_mounts((Path(sys.prefix), PACKAGE_SOURCE, *profile_mounts))
    child_environment = {
        **CHILD_ENVIRONMENT,
        "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
    }
    policy = provenance.policy
    launcher = open_trusted_executable(
        BWRAP,
        required_owner_uid=policy.required_owner_uid,
        forbidden_mode_bits=policy.forbidden_mode_bits,
        require_single_link=policy.require_single_link,
    )
    try:
        if launcher.snapshot.digest != provenance.executable_digest:
            raise RuntimeError("Bubblewrap executable changed after provenance inspection")
        arguments: list[str] = [
            launcher.execution_path,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--assert-userns-disabled",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            SANDBOX_TMP,
            *_mount_parent_arguments(
                (*mounts, repository) if destination == repository else mounts
            ),
        ]
        for mount in mounts:
            arguments.extend(("--ro-bind", str(mount), str(mount)))
        if destination != repository:
            arguments.extend(("--dir", str(destination)))
        arguments.extend(("--ro-bind", str(repository), str(destination)))
        if executable_descriptor is not None:
            arguments.extend(
                ("--dir", "/run", "--ro-bind-fd", str(executable_descriptor), SANDBOX_TOOL)
            )
        sandbox_cwd = destination / cwd.relative_to(repository)
        arguments.extend(("--chdir", str(sandbox_cwd), "--clearenv"))
        for key, value in sorted(child_environment.items()):
            arguments.extend(("--setenv", key, value))
        sandbox_body = {
            "version": SANDBOX_VERSION,
            "bubblewrap_provenance_identity": provenance.identity_digest,
            "bubblewrap_policy_digest": provenance.policy_digest,
            "bubblewrap_arguments_digest": canonical_digest(
                [
                    "<tracked-workspace>"
                    if repository_identity is not None and item == str(repository)
                    else "<adapter-fd>"
                    if executable_descriptor is not None
                    and index > 0
                    and arguments[index - 1] == "--ro-bind-fd"
                    else item
                    for index, item in enumerate(arguments[1:], start=1)
                ]
            ),
            "mounts_digest": canonical_digest(
                [
                    {
                        "path": str(item),
                        "content_digest": file_digest(item) if item.is_file() else None,
                    }
                    for item in mounts
                ]
                + [
                    {
                        "destination": str(destination),
                        "identity": repository_identity or str(repository),
                    }
                ]
            ),
            "working_directory_digest": canonical_digest(str(sandbox_cwd)),
            "executable_digest": executable_digest or file_digest(executable),
            "environment_digest": canonical_digest(child_environment),
            "network": "unshared",
            "repository": "read-only",
            "uid": 65534,
            "gid": 65534,
        }
        launcher_environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
        }
        return (
            tuple(arguments),
            launcher_environment,
            provenance,
            canonical_digest(sandbox_body),
            launcher,
        )
    except Exception:
        launcher.close()
        raise


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate the bubblewrap process group, escalating if it does not exit."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    if process.poll() is None:
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.5)
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait(timeout=2)


@dataclass(frozen=True)
class ProcessOutput:
    """Bounded raw output and its content-addressed execution state."""

    returncode: int
    output_digest: str
    output_bytes: int
    truncated: bool
    timed_out: bool
    stdout: bytes
    stderr: bytes


def stream_process(
    command: tuple[str, ...],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    pass_fds: tuple[int, ...] = (),
) -> ProcessOutput:
    """Execute one process with a streaming aggregate output hard cap."""
    process = subprocess.Popen(  # nosec B603
        command,
        env=environment,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        pass_fds=pass_fds,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_process_tree(process)
        raise RuntimeError("native audit output pipes were not created")
    stream_digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    stream_bytes = {"stdout": 0, "stderr": 0}
    stream_buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout_seconds
    truncated = False
    timed_out = False
    try:
        while selector.get_map():
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                _terminate_process_tree(process)
                break
            for key, _mask in selector.select(timeout=min(remaining_time, 0.1)):
                total = sum(stream_bytes.values())
                allowed = OUTPUT_LIMIT - total
                chunk = os.read(key.fd, min(READ_SIZE, allowed + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                label = str(key.data)
                accepted = chunk[:allowed]
                stream_digests[label].update(accepted)
                stream_bytes[label] += len(accepted)
                stream_buffers[label].extend(accepted)
                if len(chunk) > allowed:
                    truncated = True
                    _terminate_process_tree(process)
                    break
            if truncated:
                break
        if process.poll() is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                _terminate_process_tree(process)
            else:
                try:
                    process.wait(timeout=remaining_time)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _terminate_process_tree(process)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            _terminate_process_tree(process)
    returncode = 124 if timed_out else 125 if truncated else int(process.returncode)
    output_body = {
        "stdout_digest": stream_digests["stdout"].hexdigest(),
        "stdout_bytes": stream_bytes["stdout"],
        "stderr_digest": stream_digests["stderr"].hexdigest(),
        "stderr_bytes": stream_bytes["stderr"],
        "truncated": truncated,
        "timed_out": timed_out,
    }
    return ProcessOutput(
        returncode=returncode,
        output_digest=canonical_digest(output_body),
        output_bytes=sum(stream_bytes.values()),
        truncated=truncated,
        timed_out=timed_out,
        stdout=bytes(stream_buffers["stdout"]),
        stderr=bytes(stream_buffers["stderr"]),
    )
