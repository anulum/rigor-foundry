# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository-native audit adapters
"""Run consented repository audits in a read-only, credential-free sandbox."""

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
from typing import Literal, cast

from .models import (
    AdapterSpec,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
)
from .sandbox_provenance import BubblewrapProvenance, inspect_bubblewrap
from .trusted_executable import TrustedExecutable, open_trusted_executable

ExecutionScope = Literal["staged", "full"]
ADAPTER_RESULT_SCHEMA_VERSION = "1.0"
_OUTPUT_LIMIT = 65_536
_READ_SIZE = 8_192
_BWRAP = Path("/usr/bin/bwrap")
_PACKAGE_SOURCE = Path(__file__).resolve().parents[1]
_SANDBOX_VERSION = "rigor-foundry-bwrap-v2"
# This path is a private tmpfs created inside the bubblewrap mount namespace.
_SANDBOX_TMP = "/tmp"  # nosec B108
_CHILD_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "TMPDIR": _SANDBOX_TMP,
}


def _digest(value: object, field: str) -> str:
    """Return one lowercase SHA-256 digest."""
    result = require_string(value, field)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return result


def _file_digest(path: Path) -> str:
    """Return SHA-256 for one regular file without loading it at once."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise ValueError(f"cannot hash native audit executable: {path}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class AdapterResult:
    """Content-addressed, secret-free evidence from one native audit."""

    name: str
    returncode: int
    output_digest: str
    output_bytes: int
    output_truncated: bool
    timed_out: bool
    required: bool
    spec_digest: str
    executable_digest: str
    command_digest: str
    environment_digest: str
    sandbox_digest: str
    sandbox_provenance: BubblewrapProvenance

    @property
    def passed(self) -> bool:
        """Return whether the native audit exited within every bound."""
        return self.returncode == 0 and not self.timed_out and not self.output_truncated

    def to_dict(self) -> dict[str, object]:
        """Serialise without adapter argv, repository paths, environment, or raw output."""
        return {
            "schema_version": ADAPTER_RESULT_SCHEMA_VERSION,
            "name": self.name,
            "returncode": self.returncode,
            "output_digest": self.output_digest,
            "output_bytes": self.output_bytes,
            "output_truncated": self.output_truncated,
            "timed_out": self.timed_out,
            "required": self.required,
            "spec_digest": self.spec_digest,
            "executable_digest": self.executable_digest,
            "command_digest": self.command_digest,
            "environment_digest": self.environment_digest,
            "sandbox_digest": self.sandbox_digest,
            "sandbox_provenance": self.sandbox_provenance.to_dict(),
            "passed": self.passed,
        }

    @classmethod
    def from_dict(cls, value: object, index: int = 0) -> AdapterResult:
        """Parse and validate one secret-free native evidence record."""
        field = f"adapter_results[{index}]"
        data = require_mapping(value, field)
        expected = {
            "schema_version",
            "name",
            "returncode",
            "output_digest",
            "output_bytes",
            "output_truncated",
            "timed_out",
            "required",
            "spec_digest",
            "executable_digest",
            "command_digest",
            "environment_digest",
            "sandbox_digest",
            "sandbox_provenance",
            "passed",
        }
        if set(data) != expected:
            raise ValueError(f"{field} fields are invalid")
        if data.get("schema_version") != ADAPTER_RESULT_SCHEMA_VERSION:
            raise ValueError(f"{field} schema version is unsupported")
        boolean_names = ("output_truncated", "timed_out", "required", "passed")
        if not all(isinstance(data.get(name), bool) for name in boolean_names):
            raise ValueError(f"{field} boolean fields are invalid")
        result = cls(
            name=require_string(data.get("name"), f"{field}.name"),
            returncode=require_integer(data.get("returncode"), f"{field}.returncode"),
            output_digest=_digest(data.get("output_digest"), f"{field}.output_digest"),
            output_bytes=require_integer(
                data.get("output_bytes"),
                f"{field}.output_bytes",
                minimum=0,
            ),
            output_truncated=cast(bool, data["output_truncated"]),
            timed_out=cast(bool, data["timed_out"]),
            required=cast(bool, data["required"]),
            spec_digest=_digest(data.get("spec_digest"), f"{field}.spec_digest"),
            executable_digest=_digest(
                data.get("executable_digest"),
                f"{field}.executable_digest",
            ),
            command_digest=_digest(data.get("command_digest"), f"{field}.command_digest"),
            environment_digest=_digest(
                data.get("environment_digest"),
                f"{field}.environment_digest",
            ),
            sandbox_digest=_digest(data.get("sandbox_digest"), f"{field}.sandbox_digest"),
            sandbox_provenance=BubblewrapProvenance.from_dict(data.get("sandbox_provenance")),
        )
        if result.passed is not data["passed"]:
            raise ValueError(f"{field}.passed does not match native evidence")
        return result


def _contained(path: Path, roots: tuple[Path, ...]) -> bool:
    """Return whether a lexical path is within an explicitly trusted root."""
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def _resolved_executable(root: Path, value: str) -> Path:
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
    if not _contained(absolute, trusted_roots):
        raise ValueError("native audit executable is outside trusted runtime roots")
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise ValueError(f"native audit executable is unavailable: {value}") from exc
    if not _contained(resolved, trusted_roots):
        raise ValueError("native audit executable symlink escapes trusted runtime roots")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"native audit executable is not executable: {value}")
    return absolute


def _working_directory(root: Path, relative: str) -> Path:
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
        if _contained(path, (Path("/usr"),)):
            continue
        if not _contained(path, tuple(selected)):
            selected.append(path)
    return tuple(selected)


def _mount_parent_arguments(mounts: tuple[Path, ...]) -> tuple[str, ...]:
    """Create empty ancestors needed for same-path read-only bind mounts."""
    excluded = {Path("/"), Path("/usr"), Path(_SANDBOX_TMP)}
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


def _sandbox_contract(
    repository: Path,
    executable: Path,
    cwd: Path,
) -> tuple[
    tuple[str, ...],
    dict[str, str],
    BubblewrapProvenance,
    str,
    TrustedExecutable,
]:
    """Build a fixed bubblewrap contract and its canonical identity digest."""
    if not _BWRAP.is_file() or not os.access(_BWRAP, os.X_OK):
        raise RuntimeError("native audits require /usr/bin/bwrap for read-only isolation")
    provenance = inspect_bubblewrap()
    if provenance.executable_path != str(_BWRAP):
        raise RuntimeError("Bubblewrap provenance does not match the sandbox launcher")
    mounts = _minimal_mounts((repository, Path(sys.prefix), _PACKAGE_SOURCE))
    child_environment = {
        **_CHILD_ENVIRONMENT,
        "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
    }
    policy = provenance.policy
    launcher = open_trusted_executable(
        _BWRAP,
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
            _SANDBOX_TMP,
            *_mount_parent_arguments(mounts),
        ]
        for mount in mounts:
            arguments.extend(("--ro-bind", str(mount), str(mount)))
        arguments.extend(("--chdir", str(cwd), "--clearenv"))
        for key, value in sorted(child_environment.items()):
            arguments.extend(("--setenv", key, value))
        sandbox_body = {
            "version": _SANDBOX_VERSION,
            "bubblewrap_provenance_identity": provenance.identity_digest,
            "bubblewrap_policy_digest": provenance.policy_digest,
            "bubblewrap_arguments_digest": canonical_digest(arguments[1:]),
            "mounts_digest": canonical_digest([str(item) for item in mounts]),
            "working_directory_digest": canonical_digest(str(cwd)),
            "executable_digest": _file_digest(executable),
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


def _stream_process(
    command: tuple[str, ...],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    pass_fds: tuple[int, ...] = (),
) -> tuple[int, str, int, bool, bool]:
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
                allowed = _OUTPUT_LIMIT - total
                chunk = os.read(key.fd, min(_READ_SIZE, allowed + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                label = str(key.data)
                accepted = chunk[:allowed]
                stream_digests[label].update(accepted)
                stream_bytes[label] += len(accepted)
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
    return (
        returncode,
        canonical_digest(output_body),
        sum(stream_bytes.values()),
        truncated,
        timed_out,
    )


def run_adapter(root: Path, spec: AdapterSpec, *, trusted: bool = False) -> AdapterResult:
    """Run one explicitly consented adapter inside a read-only sandbox."""
    if not trusted:
        raise ValueError("native audit execution requires explicit trusted consent")
    repository = root.resolve(strict=True)
    executable = _resolved_executable(repository, spec.command[0])
    command = (str(executable), *spec.command[1:])
    cwd = _working_directory(repository, spec.working_directory)
    sandbox, environment, sandbox_provenance, sandbox_digest, launcher = _sandbox_contract(
        repository,
        executable,
        cwd,
    )
    try:
        returncode, output_digest, output_bytes, truncated, timed_out = _stream_process(
            (*sandbox, "--", *command),
            environment=environment,
            timeout_seconds=spec.timeout_seconds,
            pass_fds=(launcher.descriptor,),
        )
    finally:
        launcher.close()
    observed_after = inspect_bubblewrap(sandbox_provenance.policy)
    if observed_after.identity_digest != sandbox_provenance.identity_digest:
        raise RuntimeError("Bubblewrap provenance changed during native audit execution")
    child_environment = {
        **_CHILD_ENVIRONMENT,
        "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
    }
    return AdapterResult(
        name=spec.name,
        returncode=returncode,
        output_digest=output_digest,
        output_bytes=output_bytes,
        output_truncated=truncated,
        timed_out=timed_out,
        required=spec.required,
        spec_digest=canonical_digest(spec.to_dict()),
        executable_digest=_file_digest(executable),
        command_digest=canonical_digest(command),
        environment_digest=canonical_digest(child_environment),
        sandbox_digest=sandbox_digest,
        sandbox_provenance=sandbox_provenance,
    )


def run_native_audits(
    root: Path,
    specs: tuple[AdapterSpec, ...],
    scope: ExecutionScope,
    *,
    trusted: bool = False,
) -> tuple[AdapterResult, ...]:
    """Run applicable adapters only after explicit trusted execution consent."""
    selected = tuple(spec for spec in specs if spec.scope in {scope, "both"})
    names = tuple(spec.name for spec in selected)
    if len(names) != len(set(names)):
        raise ValueError("native audit adapter names must be unique")
    if selected and not trusted:
        raise ValueError("native audit execution requires explicit trusted consent")
    return tuple(run_adapter(root, spec, trusted=True) for spec in selected)
