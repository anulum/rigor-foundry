# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository-native audit adapters
"""Run declared repository audits with argv-only, time-bounded execution."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .models import AdapterSpec

ExecutionScope = Literal["staged", "full"]
_OUTPUT_LIMIT = 16_384


@dataclass(frozen=True)
class AdapterResult:
    """Observed result of one repository-native audit command.

    Parameters
    ----------
    name:
        Stable adapter identifier.
    command:
        Resolved argument vector used for execution.
    returncode:
        Process exit status, or 124 for a hard timeout.
    output_digest:
        SHA-256 of complete standard output and standard error bytes.
    output_excerpt:
        Bounded UTF-8 replacement-decoded output for diagnostics.
    timed_out:
        Whether the configured wall-clock limit expired.
    required:
        Whether failure blocks repository conformance.

    """

    name: str
    command: tuple[str, ...]
    returncode: int
    output_digest: str
    output_excerpt: str
    timed_out: bool
    required: bool

    @property
    def passed(self) -> bool:
        """Return whether the native audit exited successfully."""
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict[str, object]:
        """Serialise observed adapter evidence."""
        return {
            "name": self.name,
            "command": list(self.command),
            "returncode": self.returncode,
            "output_digest": self.output_digest,
            "output_excerpt": self.output_excerpt,
            "timed_out": self.timed_out,
            "required": self.required,
            "passed": self.passed,
        }


def _resolved_executable(value: str) -> str:
    """Return an absolute executable for one declared command token."""
    if value == "{python}":
        # Preserve the active virtual-environment launcher. Resolving this
        # symlink to the base interpreter discards the environment's package
        # search path and makes an adapter execute under a different toolchain.
        executable = Path(sys.executable).absolute()
    else:
        if Path(value).is_absolute():
            candidate = Path(value)
        else:
            located = shutil.which(value)
            if located is None:
                raise ValueError(f"native audit executable is unavailable: {value}")
            candidate = Path(located)
        try:
            executable = candidate.resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise ValueError(f"native audit executable cannot be resolved: {value}") from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError(f"native audit executable is not executable: {executable}")
    return str(executable)


def _working_directory(root: Path, relative: str) -> Path:
    """Return a resolved repository-contained working directory."""
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("native audit working directory escapes repository")
    try:
        candidate = (root / relative_path).resolve(strict=True)
    except OSError as exc:
        raise ValueError("native audit working directory is unavailable") from exc
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("native audit working directory escapes repository") from exc
    if not candidate.is_dir():
        raise ValueError("native audit working directory is not a directory")
    return candidate


def _digest_output(stdout: bytes, stderr: bytes) -> tuple[str, str]:
    """Return complete-output digest and a bounded diagnostic excerpt."""
    combined = stdout + b"\n--- stderr ---\n" + stderr
    digest = hashlib.sha256(combined).hexdigest()
    if len(combined) <= _OUTPUT_LIMIT:
        excerpt_bytes = combined
    else:
        half = _OUTPUT_LIMIT // 2
        excerpt_bytes = combined[:half] + b"\n... output truncated ...\n" + combined[-half:]
    return digest, excerpt_bytes.decode("utf-8", errors="replace")


def run_adapter(root: Path, spec: AdapterSpec) -> AdapterResult:
    """Run one declared native audit without shell expansion.

    Parameters
    ----------
    root:
        Resolved repository root.
    spec:
        Validated adapter specification.

    Returns
    -------
    AdapterResult
        Exit status and content-addressed bounded output evidence.

    """
    repository = root.resolve(strict=True)
    command = (_resolved_executable(spec.command[0]), *spec.command[1:])
    cwd = _working_directory(repository, spec.working_directory)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(  # nosec B603
            command,
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            shell=False,
            timeout=spec.timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        digest, excerpt = _digest_output(stdout, stderr)
        return AdapterResult(
            name=spec.name,
            command=command,
            returncode=124,
            output_digest=digest,
            output_excerpt=excerpt,
            timed_out=True,
            required=spec.required,
        )
    digest, excerpt = _digest_output(completed.stdout, completed.stderr)
    return AdapterResult(
        name=spec.name,
        command=command,
        returncode=completed.returncode,
        output_digest=digest,
        output_excerpt=excerpt,
        timed_out=False,
        required=spec.required,
    )


def run_native_audits(
    root: Path,
    specs: tuple[AdapterSpec, ...],
    scope: ExecutionScope,
) -> tuple[AdapterResult, ...]:
    """Run declared adapters applicable to one verification scope."""
    selected = tuple(spec for spec in specs if spec.scope in {scope, "both"})
    names = tuple(spec.name for spec in selected)
    if len(names) != len(set(names)):
        raise ValueError("native audit adapter names must be unique")
    return tuple(run_adapter(root, spec) for spec in selected)
