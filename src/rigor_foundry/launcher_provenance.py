# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the attested resource-limit launcher in front of the sandbox
"""Attest the util-linux ``prlimit`` launcher before it bounds a sandboxed tool's file writes.

The launcher is trusted exactly as the Bubblewrap launcher is: one fixed absolute path, a
root-owned executable without group or world write or set-id bits, a single link, the dpkg
association of that path with ``util-linux``, an installed package record, a version
interval, and the options the limit needs. Every observation is made through descriptor-bound
handles, and the executable and the package query must be unchanged after the inspection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .audit_primitives import canonical_digest
from .sandbox_provenance import (
    _ARCHITECTURE,
    _PACKAGE_STATUS,
    _PACKAGE_VERSION,
    _canonical_absolute_path,
    _metadata_command,
    _stable_version_tuple,
)
from .trusted_executable import (
    ExecutableSnapshot,
    TrustedExecutable,
    open_trusted_executable,
    snapshot_executable,
)

PRLIMIT_PROVENANCE_SCHEMA_VERSION: Final = "1.0"
_VERSION_LINE: Final = re.compile(r"(?:prlimit|[0-9]+) from util-linux (\S+)")
_PROGRAM_TOKEN: Final = re.compile(r"^( )[0-9]+( )", re.MULTILINE)


@dataclass(frozen=True)
class PrlimitCompatibilityPolicy:
    """The trust and feature contract of the resource-limit launcher."""

    executable_path: str = "/usr/bin/prlimit"
    package_query_path: str = "/usr/bin/dpkg-query"
    package_name: str = "util-linux"
    minimum_version: str = "2.37.0"
    maximum_version_exclusive: str = "3.0.0"
    required_options: tuple[str, ...] = ("--fsize",)
    required_owner_uid: int = 0
    forbidden_mode_bits: int = 0o6022
    require_single_link: bool = True

    def __post_init__(self) -> None:
        """Refuse an ambiguous path, package, version interval or feature contract."""
        _canonical_absolute_path(self.executable_path, "prlimit executable path")
        _canonical_absolute_path(self.package_query_path, "package query path")
        if self.package_name != "util-linux":
            raise ValueError("the prlimit package must be util-linux")
        minimum = _stable_version_tuple(self.minimum_version, "minimum prlimit version")
        maximum = _stable_version_tuple(self.maximum_version_exclusive, "maximum prlimit version")
        if minimum >= maximum:
            raise ValueError("the prlimit version interval must be non-empty")
        if (
            not self.required_options
            or tuple(sorted(set(self.required_options))) != self.required_options
        ):
            raise ValueError("the prlimit required options must be sorted and unique")
        if any(not option.startswith("--") for option in self.required_options):
            raise ValueError("the prlimit required options must be long option names")
        if (
            isinstance(self.required_owner_uid, bool)
            or not isinstance(self.required_owner_uid, int)
            or self.required_owner_uid < 0
            or isinstance(self.forbidden_mode_bits, bool)
            or not isinstance(self.forbidden_mode_bits, int)
            or not 0 <= self.forbidden_mode_bits <= 0o7777
        ):
            raise ValueError("the prlimit owner and mode mask must be valid integers")
        if not isinstance(self.require_single_link, bool):
            raise ValueError("the prlimit single-link policy must be Boolean")

    def to_dict(self) -> dict[str, object]:
        """Serialise the policy in a stable order."""
        return {
            "executable_path": self.executable_path,
            "package_query_path": self.package_query_path,
            "package_name": self.package_name,
            "minimum_version": self.minimum_version,
            "maximum_version_exclusive": self.maximum_version_exclusive,
            "required_options": list(self.required_options),
            "required_owner_uid": self.required_owner_uid,
            "forbidden_mode_bits": self.forbidden_mode_bits,
            "require_single_link": self.require_single_link,
        }

    @property
    def policy_digest(self) -> str:
        """Return the digest of the complete policy."""
        return canonical_digest(self.to_dict())


@dataclass(frozen=True)
class PrlimitProvenance:
    """What one inspection observed of the resource-limit launcher and its package."""

    policy: PrlimitCompatibilityPolicy
    executable_digest: str
    semantic_version: str
    package_query_digest: str
    package_version: str
    package_architecture: str
    capability_digest: str

    def to_dict(self) -> dict[str, object]:
        """Serialise the provenance."""
        return {
            "schema_version": PRLIMIT_PROVENANCE_SCHEMA_VERSION,
            "policy": self.policy.to_dict(),
            "policy_digest": self.policy.policy_digest,
            "executable_digest": self.executable_digest,
            "semantic_version": self.semantic_version,
            "package_query_digest": self.package_query_digest,
            "package_version": self.package_version,
            "package_architecture": self.package_architecture,
            "capability_digest": self.capability_digest,
        }

    @property
    def identity_digest(self) -> str:
        """Return the digest of the complete provenance."""
        return canonical_digest(self.to_dict())


def prlimit_version(output: str, policy: PrlimitCompatibilityPolicy) -> str:
    """Return the util-linux version that one ``--version`` response names, within the policy.

    Parameters
    ----------
    output : str
        The launcher's exact ``--version`` output. Run through a descriptor, it names its
        program by the descriptor number instead of ``prlimit``.
    policy : PrlimitCompatibilityPolicy
        The version interval.

    Returns
    -------
    str
        The ``MAJOR.MINOR.PATCH`` version.

    Raises
    ------
    RuntimeError
        If the response is not one version line inside the interval.
    """
    lines = output.splitlines()
    match = _VERSION_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        raise RuntimeError("the prlimit version response is invalid")
    version = match.group(1)
    try:
        observed = _stable_version_tuple(version, "observed prlimit version")
    except ValueError as error:
        raise RuntimeError("the prlimit version is not a stable release") from error
    if not (
        _stable_version_tuple(policy.minimum_version, "minimum")
        <= observed
        < _stable_version_tuple(policy.maximum_version_exclusive, "maximum")
    ):
        raise RuntimeError("the prlimit version is outside the supported interval")
    return version


def canonical_help(output: str) -> str:
    """Replace the descriptor-number program token of each usage line with ``prlimit``.

    Parameters
    ----------
    output : str
        The launcher's exact ``--help`` output.

    Returns
    -------
    str
        The help text as a path invocation would print it.
    """
    return _PROGRAM_TOKEN.sub(r"\1prlimit\2", output)


def package_identity(
    owner: str, record: str, policy: PrlimitCompatibilityPolicy
) -> tuple[str, str]:
    """Return the package version and architecture after checking the dpkg association.

    Parameters
    ----------
    owner : str
        The ``dpkg-query --search`` response for the executable path.
    record : str
        The ``dpkg-query --show`` response for the package.
    policy : PrlimitCompatibilityPolicy
        The required package and path.

    Returns
    -------
    tuple[str, str]
        The installed package version and architecture.

    Raises
    ------
    RuntimeError
        If the path is not owned by the package, or the package is not installed exactly.
    """
    owner_lines, record_lines = owner.splitlines(), record.splitlines()
    if owner_lines != [f"{policy.package_name}: {policy.executable_path}"]:
        raise RuntimeError("the prlimit executable lacks the required dpkg association")
    parts = record_lines[0].split("|") if len(record_lines) == 1 else []
    if len(parts) != 4 or parts[0].partition(":")[0] != policy.package_name:
        raise RuntimeError("the prlimit package record is invalid")
    _, version, architecture, status = parts
    if (
        _PACKAGE_VERSION.fullmatch(version) is None
        or _ARCHITECTURE.fullmatch(architecture) is None
    ):
        raise RuntimeError("the prlimit package record has an invalid version or architecture")
    if status != _PACKAGE_STATUS:
        raise RuntimeError("the prlimit package is not installed in the required state")
    return version, architecture


def _handle(path: Path, policy: PrlimitCompatibilityPolicy) -> TrustedExecutable:
    """Open one launcher or query executable, descriptor-bound, under the policy's trust rules."""
    return open_trusted_executable(
        path,
        required_owner_uid=policy.required_owner_uid,
        forbidden_mode_bits=policy.forbidden_mode_bits,
        require_single_link=policy.require_single_link,
    )


def _snapshot(path: Path, policy: PrlimitCompatibilityPolicy) -> ExecutableSnapshot:
    """Snapshot one launcher or query executable under the policy's trust rules."""
    return snapshot_executable(
        path,
        required_owner_uid=policy.required_owner_uid,
        forbidden_mode_bits=policy.forbidden_mode_bits,
        require_single_link=policy.require_single_link,
    )


def inspect_prlimit(policy: PrlimitCompatibilityPolicy | None = None) -> PrlimitProvenance:
    """Inspect the trusted resource-limit launcher and refuse replacement or incompatibility.

    Parameters
    ----------
    policy : PrlimitCompatibilityPolicy | None
        The compatibility policy; the default when None.

    Returns
    -------
    PrlimitProvenance
        The observed launcher identity.

    Raises
    ------
    RuntimeError
        If the launcher, its package or its features do not satisfy the policy, or changed
        during the inspection.
    """
    active = policy or PrlimitCompatibilityPolicy()
    executable, query = Path(active.executable_path), Path(active.package_query_path)
    record_arguments = (
        "--show",
        "--showformat=${binary:Package}|${Version}|${Architecture}|${Status}\\n",
        active.package_name,
    )
    with (
        _handle(executable, active) as launcher,
        _handle(query, active) as package_query,
    ):
        before = (launcher.snapshot, package_query.snapshot)
        owner = _metadata_command(package_query, "--search", active.executable_path)
        record = _metadata_command(package_query, *record_arguments)
        version = prlimit_version(_metadata_command(launcher, "--version"), active)
        help_text = canonical_help(_metadata_command(launcher, "--help"))
        if any(option not in help_text.split() for option in active.required_options):
            raise RuntimeError("a required prlimit option is unavailable")
    after = (_snapshot(executable, active), _snapshot(query, active))
    if before != after:
        raise RuntimeError("the prlimit launcher or the package query changed during inspection")
    package_version, architecture = package_identity(owner, record, active)
    return PrlimitProvenance(
        policy=active,
        executable_digest=before[0].digest,
        semantic_version=version,
        package_query_digest=before[1].digest,
        package_version=package_version,
        package_architecture=architecture,
        capability_digest=canonical_digest(help_text),
    )
