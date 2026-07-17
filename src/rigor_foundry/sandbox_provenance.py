# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native sandbox executable provenance
"""Attest Bubblewrap identity, dpkg association, and compatibility policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from .audit_primitives import (
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)
from .model_primitives import require_digest, require_semantic_version
from .trusted_executable import (
    ExecutableSnapshot,
    TrustedExecutable,
    open_trusted_executable,
    run_trusted_command,
    snapshot_executable,
)

BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION: Final = "1.0"
DEFAULT_MINIMUM_BUBBLEWRAP_VERSION: Final = "0.9.0"
DEFAULT_MAXIMUM_BUBBLEWRAP_VERSION_EXCLUSIVE: Final = "1.0.0"
_OUTPUT_LIMIT: Final = 8192
_COMMAND_TIMEOUT_SECONDS: Final = 5
_PACKAGE_STATUS: Final = "install ok installed"
_ARCHITECTURE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_PACKAGE_VERSION = re.compile(r"(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9.+~-]{0,126}\Z")
_METADATA_ENVIRONMENT: Final = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
_REQUIRED_OPTIONS: Final = tuple(
    sorted(
        {
            "--assert-userns-disabled",
            "--chdir",
            "--clearenv",
            "--dev",
            "--die-with-parent",
            "--dir",
            "--disable-userns",
            "--gid",
            "--new-session",
            "--proc",
            "--ro-bind",
            "--setenv",
            "--symlink",
            "--tmpfs",
            "--uid",
            "--unshare-all",
            "--unshare-user",
        }
    )
)


def _stable_version_tuple(value: object, field: str) -> tuple[int, int, int]:
    """Return one stable three-part semantic version as an ordered tuple."""
    version = require_semantic_version(value, field)
    parts = version.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise ValueError(f"{field} must be a stable three-part semantic version")
    return cast(tuple[int, int, int], tuple(int(part) for part in parts))


def _canonical_absolute_path(value: object, field: str) -> str:
    """Return one canonical absolute POSIX path."""
    text = require_string(value, field)
    path = Path(text)
    if not path.is_absolute() or ".." in path.parts or path.as_posix() != text:
        raise ValueError(f"{field} must be a canonical absolute POSIX path")
    return text


def _strict_fields(
    data: dict[str, object],
    expected: frozenset[str],
    field: str,
) -> None:
    """Reject missing or unrecognised fields in a versioned record."""
    observed = frozenset(data)
    if observed != expected:
        missing = ", ".join(sorted(expected - observed)) or "none"
        extra = ", ".join(sorted(observed - expected)) or "none"
        raise ValueError(f"{field} fields are invalid; missing={missing}; extra={extra}")


@dataclass(frozen=True)
class BubblewrapCompatibilityPolicy:
    """Versioned trust and feature contract for the native sandbox launcher."""

    executable_path: str = "/usr/bin/bwrap"
    package_query_path: str = "/usr/bin/dpkg-query"
    package_provider: str = "dpkg"
    package_name: str = "bubblewrap"
    minimum_version: str = DEFAULT_MINIMUM_BUBBLEWRAP_VERSION
    maximum_version_exclusive: str = DEFAULT_MAXIMUM_BUBBLEWRAP_VERSION_EXCLUSIVE
    required_options: tuple[str, ...] = _REQUIRED_OPTIONS
    required_package_status: str = _PACKAGE_STATUS
    required_owner_uid: int = 0
    forbidden_mode_bits: int = 0o6022
    require_single_link: bool = True

    def __post_init__(self) -> None:
        """Reject ambiguous executable, package, version, and feature policy."""
        _canonical_absolute_path(self.executable_path, "bubblewrap executable path")
        _canonical_absolute_path(self.package_query_path, "package query path")
        if self.package_provider != "dpkg":
            raise ValueError("bubblewrap package provider must be dpkg")
        if self.package_name != "bubblewrap":
            raise ValueError("bubblewrap package name must be bubblewrap")
        minimum = _stable_version_tuple(self.minimum_version, "minimum Bubblewrap version")
        maximum = _stable_version_tuple(
            self.maximum_version_exclusive,
            "maximum Bubblewrap version",
        )
        if minimum >= maximum:
            raise ValueError("Bubblewrap version interval must be non-empty")
        if (
            not self.required_options
            or not all(isinstance(option, str) for option in self.required_options)
            or tuple(sorted(set(self.required_options))) != self.required_options
        ):
            raise ValueError("Bubblewrap required options must be sorted and unique")
        if any(
            not option.startswith("--") or option.strip() != option
            for option in self.required_options
        ):
            raise ValueError("Bubblewrap required options must be long option names")
        if self.required_package_status != _PACKAGE_STATUS:
            raise ValueError("Bubblewrap required package status must be install ok installed")
        if (
            isinstance(self.required_owner_uid, bool)
            or not isinstance(self.required_owner_uid, int)
            or self.required_owner_uid < 0
        ):
            raise ValueError("Bubblewrap required owner UID must be a non-negative integer")
        if (
            isinstance(self.forbidden_mode_bits, bool)
            or not isinstance(self.forbidden_mode_bits, int)
            or self.forbidden_mode_bits < 0
            or self.forbidden_mode_bits > 0o7777
        ):
            raise ValueError("Bubblewrap forbidden mode bits must be a valid mode mask")
        if not isinstance(self.require_single_link, bool):
            raise ValueError("Bubblewrap single-link policy must be Boolean")

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete compatibility policy."""
        return {
            "schema_version": BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION,
            "executable_path": self.executable_path,
            "package_query_path": self.package_query_path,
            "package_provider": self.package_provider,
            "package_name": self.package_name,
            "minimum_version": self.minimum_version,
            "maximum_version_exclusive": self.maximum_version_exclusive,
            "required_options": list(self.required_options),
            "required_package_status": self.required_package_status,
            "required_owner_uid": self.required_owner_uid,
            "forbidden_mode_bits": self.forbidden_mode_bits,
            "require_single_link": self.require_single_link,
        }

    @property
    def policy_digest(self) -> str:
        """Return the canonical policy identity."""
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> BubblewrapCompatibilityPolicy:
        """Parse a complete compatibility policy without host-dependent defaults."""
        data = require_mapping(value, "bubblewrap_policy")
        expected = frozenset(
            {
                "schema_version",
                "executable_path",
                "package_query_path",
                "package_provider",
                "package_name",
                "minimum_version",
                "maximum_version_exclusive",
                "required_options",
                "required_package_status",
                "required_owner_uid",
                "forbidden_mode_bits",
                "require_single_link",
            }
        )
        _strict_fields(data, expected, "bubblewrap_policy")
        if data.get("schema_version") != BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported Bubblewrap policy schema version")
        require_single_link = data.get("require_single_link")
        if not isinstance(require_single_link, bool):
            raise ValueError("bubblewrap_policy.require_single_link must be Boolean")
        return cls(
            executable_path=_canonical_absolute_path(
                data.get("executable_path"),
                "bubblewrap_policy.executable_path",
            ),
            package_query_path=_canonical_absolute_path(
                data.get("package_query_path"),
                "bubblewrap_policy.package_query_path",
            ),
            package_provider=require_string(
                data.get("package_provider"),
                "bubblewrap_policy.package_provider",
            ),
            package_name=require_string(
                data.get("package_name"),
                "bubblewrap_policy.package_name",
            ),
            minimum_version=require_string(
                data.get("minimum_version"),
                "bubblewrap_policy.minimum_version",
            ),
            maximum_version_exclusive=require_string(
                data.get("maximum_version_exclusive"),
                "bubblewrap_policy.maximum_version_exclusive",
            ),
            required_options=require_string_tuple(
                data.get("required_options"),
                "bubblewrap_policy.required_options",
            ),
            required_package_status=require_string(
                data.get("required_package_status"),
                "bubblewrap_policy.required_package_status",
            ),
            required_owner_uid=require_integer(
                data.get("required_owner_uid"),
                "bubblewrap_policy.required_owner_uid",
            ),
            forbidden_mode_bits=require_integer(
                data.get("forbidden_mode_bits"),
                "bubblewrap_policy.forbidden_mode_bits",
            ),
            require_single_link=require_single_link,
        )


@dataclass(frozen=True)
class BubblewrapProvenance:
    """Offline-verifiable executable and dpkg-database association evidence."""

    policy: BubblewrapCompatibilityPolicy
    policy_digest: str
    executable_path: str
    executable_digest: str
    semantic_version: str
    package_provider: str
    package_query_path: str
    package_query_digest: str
    package_name: str
    package_version: str
    package_architecture: str
    package_status: str
    capability_digest: str
    identity_digest: str

    @classmethod
    def build(
        cls,
        *,
        policy: BubblewrapCompatibilityPolicy,
        executable_digest: str,
        semantic_version: str,
        package_query_digest: str,
        package_name: str,
        package_version: str,
        package_architecture: str,
        package_status: str,
        capability_digest: str,
    ) -> BubblewrapProvenance:
        """Validate observations and dpkg-reported fields, then derive identity."""
        fields: dict[str, object] = {
            "schema_version": BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION,
            "policy": policy.to_dict(),
            "policy_digest": policy.policy_digest,
            "executable_path": policy.executable_path,
            "executable_digest": require_digest(
                executable_digest,
                "bubblewrap_provenance.executable_digest",
            ),
            "semantic_version": require_semantic_version(
                semantic_version,
                "bubblewrap_provenance.semantic_version",
            ),
            "package_provider": policy.package_provider,
            "package_query_path": policy.package_query_path,
            "package_query_digest": require_digest(
                package_query_digest,
                "bubblewrap_provenance.package_query_digest",
            ),
            "package_name": require_string(
                package_name,
                "bubblewrap_provenance.package_name",
            ),
            "package_version": require_string(
                package_version,
                "bubblewrap_provenance.package_version",
            ),
            "package_architecture": require_string(
                package_architecture,
                "bubblewrap_provenance.package_architecture",
            ),
            "package_status": require_string(
                package_status,
                "bubblewrap_provenance.package_status",
            ),
            "capability_digest": require_digest(
                capability_digest,
                "bubblewrap_provenance.capability_digest",
            ),
        }
        cls._validate_fields(fields)
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _validate_fields(cls, fields: dict[str, object]) -> None:
        """Validate observed compatibility and dpkg association evidence."""
        policy = BubblewrapCompatibilityPolicy.from_dict(fields["policy"])
        if fields["policy_digest"] != policy.policy_digest:
            raise ValueError("Bubblewrap policy digest does not match policy content")
        if fields["executable_path"] != policy.executable_path:
            raise ValueError("Bubblewrap executable path does not match policy")
        if fields["package_provider"] != policy.package_provider:
            raise ValueError("Bubblewrap package provider does not match policy")
        if fields["package_query_path"] != policy.package_query_path:
            raise ValueError("Bubblewrap package query path does not match policy")
        if fields["package_name"] != policy.package_name:
            raise ValueError("Bubblewrap package name does not match policy")
        if fields["package_status"] != policy.required_package_status:
            raise ValueError("Bubblewrap package is not installed in the required state")
        architecture = cast(str, fields["package_architecture"])
        if _ARCHITECTURE.fullmatch(architecture) is None:
            raise ValueError("Bubblewrap package architecture is invalid")
        if _PACKAGE_VERSION.fullmatch(cast(str, fields["package_version"])) is None:
            raise ValueError("Bubblewrap package version is invalid")
        observed = _stable_version_tuple(
            fields["semantic_version"],
            "bubblewrap_provenance.semantic_version",
        )
        minimum = _stable_version_tuple(policy.minimum_version, "minimum Bubblewrap version")
        maximum = _stable_version_tuple(
            policy.maximum_version_exclusive,
            "maximum Bubblewrap version",
        )
        if not minimum <= observed < maximum:
            raise ValueError("Bubblewrap semantic version is outside compatibility policy")

    @classmethod
    def _from_fields(
        cls,
        fields: dict[str, object],
        identity_digest: str,
    ) -> BubblewrapProvenance:
        """Construct a validated provenance record from canonical fields."""
        return cls(
            policy=BubblewrapCompatibilityPolicy.from_dict(fields["policy"]),
            policy_digest=cast(str, fields["policy_digest"]),
            executable_path=cast(str, fields["executable_path"]),
            executable_digest=cast(str, fields["executable_digest"]),
            semantic_version=cast(str, fields["semantic_version"]),
            package_provider=cast(str, fields["package_provider"]),
            package_query_path=cast(str, fields["package_query_path"]),
            package_query_digest=cast(str, fields["package_query_digest"]),
            package_name=cast(str, fields["package_name"]),
            package_version=cast(str, fields["package_version"]),
            package_architecture=cast(str, fields["package_architecture"]),
            package_status=cast(str, fields["package_status"]),
            capability_digest=cast(str, fields["capability_digest"]),
            identity_digest=identity_digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise complete, secret-free sandbox provenance."""
        return {
            "schema_version": BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION,
            "policy": self.policy.to_dict(),
            "policy_digest": self.policy_digest,
            "executable_path": self.executable_path,
            "executable_digest": self.executable_digest,
            "semantic_version": self.semantic_version,
            "package_provider": self.package_provider,
            "package_query_path": self.package_query_path,
            "package_query_digest": self.package_query_digest,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "package_architecture": self.package_architecture,
            "package_status": self.package_status,
            "capability_digest": self.capability_digest,
            "identity_digest": self.identity_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> BubblewrapProvenance:
        """Parse and verify a complete provenance record offline."""
        data = require_mapping(value, "bubblewrap_provenance")
        expected = frozenset(
            {
                "schema_version",
                "policy",
                "policy_digest",
                "executable_path",
                "executable_digest",
                "semantic_version",
                "package_provider",
                "package_query_path",
                "package_query_digest",
                "package_name",
                "package_version",
                "package_architecture",
                "package_status",
                "capability_digest",
                "identity_digest",
            }
        )
        _strict_fields(data, expected, "bubblewrap_provenance")
        if data.get("schema_version") != BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported Bubblewrap provenance schema version")
        policy = BubblewrapCompatibilityPolicy.from_dict(data.get("policy"))
        fields: dict[str, object] = {
            "schema_version": BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION,
            "policy": policy.to_dict(),
            "policy_digest": require_digest(
                data.get("policy_digest"),
                "bubblewrap_provenance.policy_digest",
            ),
            "executable_path": _canonical_absolute_path(
                data.get("executable_path"),
                "bubblewrap_provenance.executable_path",
            ),
            "executable_digest": require_digest(
                data.get("executable_digest"),
                "bubblewrap_provenance.executable_digest",
            ),
            "semantic_version": require_semantic_version(
                data.get("semantic_version"),
                "bubblewrap_provenance.semantic_version",
            ),
            "package_provider": require_string(
                data.get("package_provider"),
                "bubblewrap_provenance.package_provider",
            ),
            "package_query_path": _canonical_absolute_path(
                data.get("package_query_path"),
                "bubblewrap_provenance.package_query_path",
            ),
            "package_query_digest": require_digest(
                data.get("package_query_digest"),
                "bubblewrap_provenance.package_query_digest",
            ),
            "package_name": require_string(
                data.get("package_name"),
                "bubblewrap_provenance.package_name",
            ),
            "package_version": require_string(
                data.get("package_version"),
                "bubblewrap_provenance.package_version",
            ),
            "package_architecture": require_string(
                data.get("package_architecture"),
                "bubblewrap_provenance.package_architecture",
            ),
            "package_status": require_string(
                data.get("package_status"),
                "bubblewrap_provenance.package_status",
            ),
            "capability_digest": require_digest(
                data.get("capability_digest"),
                "bubblewrap_provenance.capability_digest",
            ),
        }
        cls._validate_fields(fields)
        recorded = require_digest(
            data.get("identity_digest"),
            "bubblewrap_provenance.identity_digest",
        )
        if recorded != canonical_digest(fields):
            raise ValueError("Bubblewrap provenance identity digest does not match content")
        return cls._from_fields(fields, recorded)


def _trusted_snapshot(
    path: Path,
    policy: BubblewrapCompatibilityPolicy,
) -> ExecutableSnapshot:
    """Snapshot one launcher under the complete compatibility policy."""
    return snapshot_executable(
        path,
        required_owner_uid=policy.required_owner_uid,
        forbidden_mode_bits=policy.forbidden_mode_bits,
        require_single_link=policy.require_single_link,
    )


def _trusted_handle(
    path: Path,
    policy: BubblewrapCompatibilityPolicy,
) -> TrustedExecutable:
    """Keep one component-safely opened launcher pinned for execution."""
    return open_trusted_executable(
        path,
        required_owner_uid=policy.required_owner_uid,
        forbidden_mode_bits=policy.forbidden_mode_bits,
        require_single_link=policy.require_single_link,
    )


def _metadata_command(executable: TrustedExecutable, *arguments: str) -> str:
    """Run one fixed metadata query with bounded time and output."""
    completed = run_trusted_command(
        executable,
        arguments,
        environment=_METADATA_ENVIRONMENT,
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT,
    )
    if completed.returncode != 0:
        raise RuntimeError("sandbox provenance metadata query returned failure")
    try:
        stdout = completed.stdout.decode("utf-8")
        stderr = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("sandbox provenance metadata query was not UTF-8") from exc
    if stderr.strip():
        raise RuntimeError("sandbox provenance metadata query wrote to stderr")
    return stdout


def _bubblewrap_version(output: str) -> str:
    """Parse the exact Bubblewrap version response."""
    lines = output.splitlines()
    if len(lines) != 1 or not lines[0].startswith("bubblewrap "):
        raise RuntimeError("Bubblewrap version response is invalid")
    version = lines[0].removeprefix("bubblewrap ")
    _stable_version_tuple(version, "observed Bubblewrap version")
    return version


def _canonical_help(output: str, executable_path: str) -> str:
    """Replace the descriptor-number invocation banner with the trusted path."""
    lines = output.splitlines(keepends=True)
    banner = (
        r"usage: /proc/self/fd/[0-9]+ \[OPTIONS\.\.\.\] "
        r"\[--\] COMMAND \[ARGS\.\.\.\]\n"
    )
    if lines and re.fullmatch(banner, lines[0]) is not None:
        lines[0] = f"usage: {executable_path} [OPTIONS...] [--] COMMAND [ARGS...]\n"
    return "".join(lines)


def _package_owner(output: str, policy: BubblewrapCompatibilityPolicy) -> str:
    """Parse and validate the dpkg association for the executable path."""
    lines = output.splitlines()
    if len(lines) != 1:
        raise RuntimeError("Bubblewrap package ownership response is invalid")
    owner, separator, path = lines[0].partition(": ")
    base_owner = owner.partition(":")[0]
    if separator != ": " or base_owner != policy.package_name or path != policy.executable_path:
        raise RuntimeError("Bubblewrap executable lacks the required dpkg association")
    return owner


def _package_record(
    output: str,
    policy: BubblewrapCompatibilityPolicy,
) -> tuple[str, str, str, str]:
    """Parse the exact dpkg package identity and installation state."""
    lines = output.splitlines()
    if len(lines) != 1:
        raise RuntimeError("Bubblewrap package record response is invalid")
    parts = lines[0].split("|")
    if len(parts) != 4:
        raise RuntimeError("Bubblewrap package record response is invalid")
    package_name, package_version, architecture, package_status = parts
    if package_name.partition(":")[0] != policy.package_name:
        raise RuntimeError("Bubblewrap package record has an unexpected package name")
    if (
        _PACKAGE_VERSION.fullmatch(package_version) is None
        or _ARCHITECTURE.fullmatch(architecture) is None
    ):
        raise RuntimeError("Bubblewrap package record has invalid version or architecture")
    if package_status != policy.required_package_status:
        raise RuntimeError("Bubblewrap package is not installed in the required state")
    return policy.package_name, package_version, architecture, package_status


def inspect_bubblewrap(
    policy: BubblewrapCompatibilityPolicy | None = None,
) -> BubblewrapProvenance:
    """Inspect trusted Bubblewrap and reject replacement or incompatible metadata."""
    active_policy = policy or BubblewrapCompatibilityPolicy()
    executable = Path(active_policy.executable_path)
    package_query = Path(active_policy.package_query_path)
    owner_arguments = ("--search", active_policy.executable_path)
    record_arguments = (
        "--show",
        "--showformat=${binary:Package}|${Version}|${Architecture}|${Status}\\n",
        active_policy.package_name,
    )
    with (
        _trusted_handle(executable, active_policy) as executable_handle,
        _trusted_handle(
            package_query,
            active_policy,
        ) as query_handle,
    ):
        executable_before = executable_handle.snapshot
        query_before = query_handle.snapshot
        owner = _metadata_command(query_handle, *owner_arguments)
        record = _metadata_command(query_handle, *record_arguments)
        version_output = _metadata_command(executable_handle, "--version")
        help_output = _canonical_help(
            _metadata_command(executable_handle, "--help"),
            active_policy.executable_path,
        )
        for option in active_policy.required_options:
            if option not in help_output.split():
                raise RuntimeError(f"Bubblewrap compatibility option is unavailable: {option}")
        if owner != _metadata_command(query_handle, *owner_arguments):
            raise RuntimeError("Bubblewrap package ownership changed during inspection")
        if record != _metadata_command(query_handle, *record_arguments):
            raise RuntimeError("Bubblewrap package record changed during inspection")
    executable_after = _trusted_snapshot(executable, active_policy)
    query_after = _trusted_snapshot(package_query, active_policy)
    if executable_before != executable_after or query_before != query_after:
        raise RuntimeError("sandbox provenance executable changed during inspection")
    _package_owner(owner, active_policy)
    package_name, package_version, architecture, package_status = _package_record(
        record,
        active_policy,
    )
    return BubblewrapProvenance.build(
        policy=active_policy,
        executable_digest=executable_before.digest,
        semantic_version=_bubblewrap_version(version_output),
        package_query_digest=query_before.digest,
        package_name=package_name,
        package_version=package_version,
        package_architecture=architecture,
        package_status=package_status,
        capability_digest=canonical_digest(help_output),
    )
