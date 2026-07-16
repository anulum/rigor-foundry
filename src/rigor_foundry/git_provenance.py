# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — trusted Git executable provenance
"""Resolve, constrain, execute, and attest one trusted Git binary."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Final

from .audit_primitives import canonical_digest, require_mapping, require_string

GIT_PROVENANCE_SCHEMA_VERSION: Final = "1.0"
DEFAULT_MINIMUM_GIT_VERSION: Final = "2.35.2"
DEFAULT_MAXIMUM_GIT_VERSION_EXCLUSIVE: Final = "3.0.0"
_VERSION = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_READ_SIZE = 1024 * 1024
_COMMAND_TIMEOUT_SECONDS = 30
_PROTECTED_CONFIG_KEYS: Final = frozenset({"core.fsmonitor", "core.hookspath"})


def _version_tuple(value: str, field: str) -> tuple[int, int, int]:
    """Return a strict three-part semantic version tuple."""
    match = _VERSION.fullmatch(value)
    if match is None:
        raise ValueError(f"{field} must be a three-part numeric version")
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


def _digest(value: object, field: str) -> str:
    """Return one lowercase SHA-256 digest."""
    result = require_string(value, field)
    if _DIGEST.fullmatch(result) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return result


def _portable_absolute_path(value: str, field: str) -> PurePath:
    """Parse one canonical absolute path independent of the current host."""
    posix = PurePosixPath(value)
    if posix.is_absolute():
        parsed: PurePath = posix
    else:
        windows = PureWindowsPath(value)
        if not windows.is_absolute():
            raise ValueError(f"{field} must be a normalised absolute POSIX or Windows path")
        parsed = windows
    if value != parsed.as_posix() or ".." in parsed.parts:
        raise ValueError(f"{field} must be a normalised canonical path")
    return parsed


def _is_portable_absolute(value: str) -> bool:
    """Return whether ``value`` is absolute in POSIX or Windows syntax."""
    return PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()


def _portable_roots() -> tuple[str, ...]:
    """Return fixed platform roots without consulting the ambient ``PATH``."""
    if os.name == "nt":
        return (
            "C:/Program Files/Git/cmd",
            "C:/Program Files/Git/bin",
        )
    if sys.platform == "darwin":
        return ("/usr/bin", "/opt/homebrew/bin", "/usr/local/bin")
    return ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin")


@dataclass(frozen=True)
class GitTrustPolicy:
    """Explicit executable roots and supported Git version interval.

    Relative executable names are searched only below ``trusted_roots`` in
    declared order. The ambient ``PATH`` is never an authority source.

    Parameters
    ----------
    executable:
        Absolute executable path or one basename searched below the roots.
    trusted_roots:
        Ordered normalised absolute directories trusted by the operator.
    minimum_version:
        Inclusive three-part Git version lower bound.
    maximum_version_exclusive:
        Exclusive three-part Git version upper bound.
    """

    executable: str = "git"
    trusted_roots: tuple[str, ...] = ()
    minimum_version: str = DEFAULT_MINIMUM_GIT_VERSION
    maximum_version_exclusive: str = DEFAULT_MAXIMUM_GIT_VERSION_EXCLUSIVE

    def __post_init__(self) -> None:
        """Reject ambiguous paths, empty roots, and invalid version ranges."""
        if not self.executable.strip():
            raise ValueError("git executable must be non-empty")
        if _is_portable_absolute(self.executable):
            _portable_absolute_path(self.executable, "absolute git executable")
        elif (
            PurePosixPath(self.executable).name != self.executable
            or PureWindowsPath(self.executable).name != self.executable
            or self.executable in {".", ".."}
        ):
            raise ValueError("relative git executable must be one basename")
        roots = self.trusted_roots or _portable_roots()
        parsed_roots = tuple(_portable_absolute_path(root, "git trusted root") for root in roots)
        if len(parsed_roots) != len(set(parsed_roots)):
            raise ValueError("git trusted roots must be unique")
        minimum = _version_tuple(self.minimum_version, "minimum Git version")
        maximum = _version_tuple(
            self.maximum_version_exclusive,
            "maximum Git version",
        )
        if minimum >= maximum:
            raise ValueError("Git version interval must be non-empty")
        object.__setattr__(self, "trusted_roots", roots)

    @property
    def policy_digest(self) -> str:
        """Return the canonical identity of this trust policy."""
        return canonical_digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        """Serialise the portable trust contract deterministically."""
        return {
            "schema_version": GIT_PROVENANCE_SCHEMA_VERSION,
            "executable": self.executable,
            "trusted_roots": list(self.trusted_roots),
            "minimum_version": self.minimum_version,
            "maximum_version_exclusive": self.maximum_version_exclusive,
        }

    @classmethod
    def from_dict(cls, value: object) -> GitTrustPolicy:
        """Parse one strict Git trust policy."""
        data = require_mapping(value, "git_trust_policy")
        if data.get("schema_version") != GIT_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported Git trust-policy schema version")
        roots = data.get("trusted_roots")
        if not isinstance(roots, list) or not all(isinstance(item, str) for item in roots):
            raise ValueError("git_trust_policy.trusted_roots must be a string array")
        if not roots:
            raise ValueError("git_trust_policy.trusted_roots must not be empty")
        return cls(
            executable=require_string(data.get("executable"), "git_trust_policy.executable"),
            trusted_roots=tuple(roots),
            minimum_version=require_string(
                data.get("minimum_version"),
                "git_trust_policy.minimum_version",
            ),
            maximum_version_exclusive=require_string(
                data.get("maximum_version_exclusive"),
                "git_trust_policy.maximum_version_exclusive",
            ),
        )


@dataclass(frozen=True)
class GitExecutableProvenance:
    """Content-addressed identity and version of the Git binary used.

    The record retains the resolved path, selected trust root, parsed version,
    exact executable SHA-256, complete versioned trust policy, derived policy
    SHA-256, and a digest over the full record. Paths are canonical POSIX or
    Windows absolute strings so reports remain verifiable on another platform.
    """

    resolved_path: str
    trusted_root: str
    version: str
    executable_digest: str
    trust_policy: GitTrustPolicy
    identity_digest: str

    @property
    def trust_policy_digest(self) -> str:
        """Return the verified digest of the embedded trust policy."""
        return self.trust_policy.policy_digest

    @classmethod
    def build(
        cls,
        *,
        resolved_path: str,
        trusted_root: str,
        version: str,
        executable_digest: str,
        trust_policy: GitTrustPolicy,
    ) -> GitExecutableProvenance:
        """Build provenance with a content-derived identity."""
        executable = _portable_absolute_path(
            resolved_path,
            "git_provenance.resolved_path",
        )
        root = _portable_absolute_path(trusted_root, "git_provenance.trusted_root")
        if type(executable) is not type(root):
            raise ValueError("Git provenance paths must use the same path format")
        try:
            executable.relative_to(root)
        except ValueError as exc:
            raise ValueError("Git provenance executable is outside its trusted root") from exc
        if trusted_root not in trust_policy.trusted_roots:
            raise ValueError("Git provenance trusted root is not declared by its trust policy")
        if _is_portable_absolute(trust_policy.executable):
            if resolved_path != trust_policy.executable:
                raise ValueError("Git provenance executable differs from its trust policy")
        else:
            allowed_names = {trust_policy.executable}
            if (
                isinstance(executable, PureWindowsPath)
                and not PureWindowsPath(trust_policy.executable).suffix
            ):
                allowed_names.add(f"{trust_policy.executable}.exe")
            if executable.name not in allowed_names:
                raise ValueError("Git provenance executable differs from its trust policy")
        validated_version = require_string(version, "git_provenance.version")
        parsed_version = _version_tuple(validated_version, "git_provenance.version")
        minimum = _version_tuple(trust_policy.minimum_version, "minimum Git version")
        maximum = _version_tuple(
            trust_policy.maximum_version_exclusive,
            "maximum Git version",
        )
        if not minimum <= parsed_version < maximum:
            raise ValueError("Git provenance version is outside its trust policy interval")
        validated_executable_digest = _digest(
            executable_digest,
            "git_provenance.executable_digest",
        )
        fields: dict[str, object] = {
            "schema_version": GIT_PROVENANCE_SCHEMA_VERSION,
            "resolved_path": resolved_path,
            "trusted_root": trusted_root,
            "version": validated_version,
            "executable_digest": validated_executable_digest,
            "trust_policy": trust_policy.to_dict(),
            "trust_policy_digest": trust_policy.policy_digest,
        }
        return cls(
            resolved_path=resolved_path,
            trusted_root=trusted_root,
            version=validated_version,
            executable_digest=validated_executable_digest,
            trust_policy=trust_policy,
            identity_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the executable provenance."""
        return {
            "schema_version": GIT_PROVENANCE_SCHEMA_VERSION,
            "resolved_path": self.resolved_path,
            "trusted_root": self.trusted_root,
            "version": self.version,
            "executable_digest": self.executable_digest,
            "trust_policy": self.trust_policy.to_dict(),
            "trust_policy_digest": self.trust_policy_digest,
            "identity_digest": self.identity_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> GitExecutableProvenance:
        """Parse and integrity-check executable provenance."""
        data = require_mapping(value, "git_provenance")
        if data.get("schema_version") != GIT_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported Git provenance schema version")
        trust_policy = GitTrustPolicy.from_dict(data.get("trust_policy"))
        recorded_policy_digest = _digest(
            data.get("trust_policy_digest"),
            "git_provenance.trust_policy_digest",
        )
        if trust_policy.policy_digest != recorded_policy_digest:
            raise ValueError("Git provenance trust-policy digest does not match its content")
        provenance = cls.build(
            resolved_path=require_string(
                data.get("resolved_path"),
                "git_provenance.resolved_path",
            ),
            trusted_root=require_string(
                data.get("trusted_root"),
                "git_provenance.trusted_root",
            ),
            version=require_string(data.get("version"), "git_provenance.version"),
            executable_digest=_digest(
                data.get("executable_digest"),
                "git_provenance.executable_digest",
            ),
            trust_policy=trust_policy,
        )
        recorded = _digest(data.get("identity_digest"), "git_provenance.identity_digest")
        if provenance.identity_digest != recorded:
            raise ValueError("Git provenance identity digest does not match its content")
        return provenance


@dataclass(frozen=True)
class _FileSnapshot:
    """Runtime-only identity used to detect executable replacement."""

    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    digest: str


class GitRunner:
    """Run fixed Git argv through one continuously revalidated executable.

    The runner excludes ambient Git configuration and credentials. On hosts
    exposing ``/proc/self/fd`` or ``/dev/fd``, each command executes the already
    validated descriptor so a concurrent pathname replacement cannot select
    different bytes. Every host retains the descriptor during execution and
    revalidates the pathname after completion.
    """

    def __init__(self, policy: GitTrustPolicy | None = None) -> None:
        """Resolve and attest one executable under ``policy``."""
        self.policy = policy or GitTrustPolicy()
        self._path, trusted_root = self._locate()
        self._snapshot = self._snapshot_file(self._path)
        version = self._read_version()
        parsed = _version_tuple(version, "observed Git version")
        minimum = _version_tuple(self.policy.minimum_version, "minimum Git version")
        maximum = _version_tuple(
            self.policy.maximum_version_exclusive,
            "maximum Git version",
        )
        if not minimum <= parsed < maximum:
            raise RuntimeError(
                f"Git version {version} is outside supported interval "
                f"[{self.policy.minimum_version}, {self.policy.maximum_version_exclusive})"
            )
        self.provenance = GitExecutableProvenance.build(
            resolved_path=self._path.as_posix(),
            trusted_root=trusted_root.as_posix(),
            version=version,
            executable_digest=self._snapshot.digest,
            trust_policy=self.policy,
        )

    def _locate(self) -> tuple[Path, Path]:
        """Select a candidate only from the declared roots."""
        executable = Path(self.policy.executable)
        if _is_portable_absolute(self.policy.executable):
            if not executable.is_absolute():
                raise RuntimeError("configured Git executable is not native to this platform")
            roots = tuple(Path(value) for value in self.policy.trusted_roots)
            containing = tuple(root for root in roots if _contained(executable, root))
            if not containing:
                raise RuntimeError("configured Git executable is outside trusted roots")
            root = max(containing, key=lambda item: len(item.parts))
            return self._validate_path(executable, root)
        executable_names = (executable,)
        if sys.platform == "win32" and not executable.suffix:
            executable_names = (executable.with_suffix(".exe"), executable)
        for value in self.policy.trusted_roots:
            root = Path(value)
            if not root.is_absolute():
                raise RuntimeError("configured Git trust root is not native to this platform")
            for executable_name in executable_names:
                candidate = root / executable_name
                if candidate.exists() or candidate.is_symlink():
                    return self._validate_path(candidate, root)
        raise RuntimeError("Git executable is unavailable below configured trusted roots")

    def _validate_path(self, candidate: Path, root: Path) -> tuple[Path, Path]:
        """Reject symlinks and non-executable files across the selected path."""
        try:
            resolved_root = root.resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Git trusted root is unavailable: {root}") from exc
        if resolved_root != root or root.is_symlink() or not root.is_dir():
            raise RuntimeError(f"Git trusted root must be a real directory, not a symlink: {root}")
        try:
            relative = candidate.relative_to(root)
        except ValueError as exc:
            raise RuntimeError("configured Git executable is outside trusted roots") from exc
        cursor = root
        for part in relative.parts:
            cursor /= part
            try:
                metadata = cursor.lstat()
            except OSError as exc:
                raise RuntimeError(f"Git executable path is unavailable: {candidate}") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(f"Git executable path must not contain symlinks: {candidate}")
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Git executable path cannot be resolved: {candidate}") from exc
        if resolved != candidate:
            raise RuntimeError(f"Git executable path must not contain symlinks: {candidate}")
        metadata = candidate.stat(follow_symlinks=False)
        self._validate_executable_metadata(candidate, metadata)
        return candidate, root

    @staticmethod
    def _validate_executable_metadata(path: Path, metadata: os.stat_result) -> None:
        """Reject unsafe executable type, link count, permissions, or mode."""
        unsafe_mode = 0
        executable_mode = True
        if os.name != "nt":
            unsafe_mode = metadata.st_mode & (
                stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID
            )
            executable_mode = bool(metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or unsafe_mode
            or not executable_mode
            or not os.access(path, os.X_OK)
        ):
            raise RuntimeError(
                "configured Git path must be a single-link executable without "
                f"group/world write or elevated-ID bits: {path}"
            )

    @staticmethod
    def _open_no_follow(path: Path) -> int:
        """Open one absolute file through descriptor-relative no-follow components."""
        if not path.is_absolute():
            raise RuntimeError("trusted Git executable path must be absolute")
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise RuntimeError("platform lacks component-safe no-follow file opening")
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory: int | None = None
        try:
            directory = os.open(path.anchor, directory_flags)
            for part in path.parts[1:-1]:
                child = os.open(part, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = child
            return os.open(path.name, file_flags, dir_fd=directory)
        except (NotImplementedError, OSError, TypeError) as exc:
            raise RuntimeError(f"cannot component-open trusted Git executable: {path}") from exc
        finally:
            if directory is not None:
                os.close(directory)

    @staticmethod
    def _snapshot_file(path: Path) -> _FileSnapshot:
        """Hash one no-follow descriptor and bind it back to its pathname."""
        try:
            descriptor = GitRunner._open_no_follow(path)
        except RuntimeError as exc:
            raise RuntimeError(f"cannot open trusted Git executable: {path}") from exc
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("trusted Git executable is not a regular file")
            while chunk := os.read(descriptor, _READ_SIZE):
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise RuntimeError("trusted Git executable changed while hashing")
        GitRunner._validate_executable_metadata(path, after)
        try:
            pathname = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("trusted Git executable disappeared while hashing") from exc
        pathname_identity = (
            pathname.st_dev,
            pathname.st_ino,
            pathname.st_mode,
            pathname.st_nlink,
            pathname.st_size,
            pathname.st_mtime_ns,
            pathname.st_ctime_ns,
        )
        if pathname_identity != after_identity:
            raise RuntimeError("trusted Git executable changed while hashing")
        return _FileSnapshot(
            device=after.st_dev,
            inode=after.st_ino,
            mode=after.st_mode,
            links=after.st_nlink,
            size=after.st_size,
            modified_ns=after.st_mtime_ns,
            changed_ns=after.st_ctime_ns,
            digest=digest.hexdigest(),
        )

    def _verify_unchanged(self) -> None:
        """Fail before or after execution if the trusted binary changed."""
        if self._snapshot_file(self._path) != self._snapshot:
            raise RuntimeError("trusted Git executable was replaced after provenance capture")

    def _environment(self) -> dict[str, str]:
        """Return a credential-free deterministic environment for Git plumbing."""
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": os.devnull,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.pathsep.join(self.policy.trusted_roots),
        }
        if os.name == "nt":
            environment["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "C:/Windows")
        return environment

    def _execute(
        self,
        arguments: tuple[str, ...],
        *,
        cwd: Path,
        check: bool,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[bytes]:
        """Execute argv and verify the executable on both sides of the call."""
        if timeout_seconds <= 0:
            raise ValueError("Git command timeout must be positive")
        self._verify_unchanged()
        descriptor: int | None = None
        try:
            try:
                descriptor = self._open_no_follow(self._path)
            except RuntimeError as exc:
                raise RuntimeError("trusted Git executable disappeared before execution") from exc
            metadata = os.fstat(descriptor)
            descriptor_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            expected_identity = (
                self._snapshot.device,
                self._snapshot.inode,
                self._snapshot.mode,
                self._snapshot.links,
                self._snapshot.size,
                self._snapshot.modified_ns,
                self._snapshot.changed_ns,
            )
            if descriptor_identity != expected_identity:
                raise RuntimeError("trusted Git executable changed before descriptor pinning")
            descriptor_root = next(
                (root for root in (Path("/proc/self/fd"), Path("/dev/fd")) if root.is_dir()),
                None,
            )
            if descriptor_root is None:
                raise RuntimeError("platform cannot execute a pinned Git descriptor")
            command_path = str(descriptor_root / str(descriptor))
            try:
                return subprocess.run(  # nosec B603
                    [command_path, *arguments],
                    cwd=cwd,
                    check=check,
                    capture_output=True,
                    env=self._environment(),
                    pass_fds=(descriptor,),
                    shell=False,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"trusted Git command exceeded the {timeout_seconds}-second limit"
                ) from exc
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(
                    f"trusted Git command failed with exit status {exc.returncode}"
                ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            self._verify_unchanged()

    def _read_version(self) -> str:
        """Read and parse the exact binary's machine-comparable version."""
        completed = self._execute(
            ("--version",),
            cwd=self._path.parent,
            check=True,
            timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        )
        try:
            output = completed.stdout.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeError("Git returned a non-UTF-8 version") from exc
        match = re.fullmatch(r"git version (\d+\.\d+\.\d+)(?:[. +(-].*)?", output)
        if match is None:
            raise RuntimeError("Git returned an unsupported version format")
        return match.group(1)

    def run(
        self,
        cwd: Path,
        *arguments: str,
        check: bool = True,
        timeout_seconds: int = _COMMAND_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run one fixed Git argv from ``cwd`` without shell or ambient PATH.

        Parameters
        ----------
        cwd:
            Existing working directory for the Git command.
        *arguments:
            Fixed Git arguments.
        check:
            Raise when Git returns a non-zero exit status.
        timeout_seconds:
            Positive hard wall-clock deadline for the child process.
        """
        self._reject_protected_config_overrides(arguments)
        hooks = Path(self.provenance.trusted_root) / ".rigor-foundry-disabled-hooks"
        if hooks.exists() or hooks.is_symlink():
            raise RuntimeError("reserved disabled-hooks path exists inside Git trust root")
        hooks_path = str(hooks)
        guarded_arguments = (
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={hooks_path}",
            *arguments,
        )
        return self._execute(
            guarded_arguments,
            cwd=cwd,
            check=check,
            timeout_seconds=timeout_seconds,
        )

    @staticmethod
    def _reject_protected_config_overrides(arguments: tuple[str, ...]) -> None:
        """Reject later argv that could reactivate repository-side execution."""
        for index, argument in enumerate(arguments):
            assignment: str | None = None
            if argument == "-c" and index + 1 < len(arguments):
                assignment = arguments[index + 1]
            elif argument.startswith("-c") and argument != "-c":
                assignment = argument[2:]
            elif argument.startswith("--config-env="):
                assignment = argument.removeprefix("--config-env=")
            if assignment is None:
                continue
            key = assignment.partition("=")[0].lower()
            if key in _PROTECTED_CONFIG_KEYS:
                raise ValueError(f"Git config override for {key} is reserved")


def _contained(path: Path, root: Path) -> bool:
    """Return whether one lexical absolute path is within ``root``."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
