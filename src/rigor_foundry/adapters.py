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
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .adapter_profiles import (
    AdapterProfileEvidence,
    interpret_profile_output,
    normalise_version_output,
    profile_by_name,
)
from .adapter_runtime import (
    CHILD_ENVIRONMENT,
    SANDBOX_TOOL,
    SANDBOX_VERSION,
    file_digest,
    resolved_executable,
    sandbox_contract,
    stream_process,
    working_directory,
)
from .adapter_workspace import AdapterWorkspace, create_adapter_workspace
from .git_provenance import GitTrustPolicy
from .models import (
    AdapterSpec,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
)
from .sandbox_provenance import BubblewrapProvenance, inspect_bubblewrap
from .trusted_executable import TrustedExecutable, open_trusted_executable, run_trusted_command

ExecutionScope = Literal["staged", "full"]
ADAPTER_RESULT_SCHEMA_VERSION = "2.0"


def _digest(value: object, field: str) -> str:
    """Return one lowercase SHA-256 digest."""
    result = require_string(value, field)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return result


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
    profile_evidence: AdapterProfileEvidence | None = None

    @property
    def passed(self) -> bool:
        """Return whether the native audit exited within every bound."""
        if self.profile_evidence is not None:
            return self.profile_evidence.passed
        return self.returncode == 0 and not self.timed_out and not self.output_truncated

    @property
    def complete(self) -> bool:
        """Return whether the execution produced complete interpretable evidence."""
        if self.profile_evidence is not None:
            return self.profile_evidence.complete
        return not self.timed_out and not self.output_truncated

    def _validate_profile_relation(self, field: str) -> None:
        """Validate exact outer-execution relations for nested profile evidence."""
        evidence = self.profile_evidence
        if evidence is None:
            return
        if evidence.output_digest != self.output_digest:
            raise ValueError(f"{field}.profile_evidence output digest does not match execution")
        if evidence.status == "unavailable":
            observed = (
                self.returncode,
                self.output_bytes,
                self.output_truncated,
                self.timed_out,
            )
            if observed != (126, 0, False, False):
                raise ValueError(f"{field} unavailable profile execution fields are invalid")
            return
        if evidence.reason == "timed-out":
            if self.returncode != 124 or not self.timed_out or self.output_truncated:
                raise ValueError(f"{field} timed-out profile execution fields are invalid")
            return
        if evidence.reason == "output-truncated":
            if self.returncode != 125 or not self.output_truncated or self.timed_out:
                raise ValueError(f"{field} truncated profile execution fields are invalid")
            return
        if self.timed_out or self.output_truncated:
            raise ValueError(f"{field} profile execution bounds contradict evidence")
        if evidence.reason == "invalid-returncode":
            expected_returncode = 1 if evidence.finding_count else 0
            if self.returncode == expected_returncode:
                raise ValueError(
                    f"{field} invalid-returncode profile evidence agrees with findings"
                )
        if evidence.status == "clean" and self.returncode != 0:
            raise ValueError(f"{field} clean profile return code is invalid")
        if evidence.status == "findings" and self.returncode != 1:
            raise ValueError(f"{field} findings profile return code is invalid")

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
            "profile_evidence": (
                None if self.profile_evidence is None else self.profile_evidence.to_dict()
            ),
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
            "profile_evidence",
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
            profile_evidence=(
                None
                if data.get("profile_evidence") is None
                else AdapterProfileEvidence.from_dict(data.get("profile_evidence"))
            ),
        )
        result._validate_profile_relation(field)
        if result.passed is not data["passed"]:
            raise ValueError(f"{field}.passed does not match native evidence")
        return result


def _trusted_adapter_executable(path: Path) -> TrustedExecutable:
    """Open one root- or operator-owned adapter executable by descriptor."""
    try:
        owner = path.stat(follow_symlinks=False).st_uid
    except OSError as exc:
        raise ValueError(f"native audit executable is unavailable: {path.name}") from exc
    if owner not in {0, os.getuid()}:
        raise ValueError("native audit executable owner is not trusted")
    try:
        return open_trusted_executable(
            path,
            required_owner_uid=owner,
            forbidden_mode_bits=stat.S_IWGRP | stat.S_IWOTH,
            require_single_link=False,
        )
    except RuntimeError as exc:
        raise ValueError(
            f"native audit executable cannot be descriptor-bound: {path.name}"
        ) from exc


def _verify_adapter_executable(executable: TrustedExecutable) -> None:
    """Fail if the retained executable bytes or descriptor identity changed."""
    metadata = os.fstat(executable.descriptor)
    snapshot = executable.snapshot
    observed = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )
    expected = (
        snapshot.device,
        snapshot.inode,
        snapshot.mode,
        snapshot.owner_uid,
        snapshot.group_gid,
        snapshot.link_count,
        snapshot.size,
        snapshot.modified_ns,
    )
    os.lseek(executable.descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(executable.descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(executable.descriptor, 0, os.SEEK_SET)
    if observed != expected or digest.hexdigest() != snapshot.digest:
        raise RuntimeError("native audit executable changed during execution")


def _profile_unavailable_result(
    spec: AdapterSpec,
    workspace: AdapterWorkspace,
    *,
    reason: Literal["executable-unavailable", "version-unavailable"],
    executable_digest: str,
    version_output_digest: str,
) -> AdapterResult:
    """Return durable fail-closed evidence when a built-in tool cannot run."""
    if spec.profile is None:
        raise ValueError("profile evidence requires a built-in adapter")
    profile = profile_by_name(spec.profile)
    provenance = inspect_bubblewrap()
    output_digest = canonical_digest(
        {
            "stdout_digest": hashlib.sha256(b"").hexdigest(),
            "stderr_digest": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "truncated": False,
            "timed_out": False,
        }
    )
    evidence = AdapterProfileEvidence.build(
        profile=profile,
        status="unavailable",
        reason=reason,
        tool_version="",
        version_output_digest=version_output_digest,
        configuration_digest=workspace.configuration_digest,
        input_digest=workspace.input_digest,
        output_digest=output_digest,
        finding_count=0,
        scanned_target_count=0,
    )
    child_environment = {
        **CHILD_ENVIRONMENT,
        "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
    }
    command_arguments = profile.command_arguments(
        f"/workspace/{workspace.configuration_path}",
        tuple(f"/workspace/{target}" for target in workspace.target_paths),
    )
    return AdapterResult(
        name=spec.name,
        returncode=126,
        output_digest=output_digest,
        output_bytes=0,
        output_truncated=False,
        timed_out=False,
        required=spec.required,
        spec_digest=canonical_digest(spec.to_dict()),
        executable_digest=executable_digest,
        command_digest=canonical_digest((profile.executable, *command_arguments)),
        environment_digest=canonical_digest(child_environment),
        sandbox_digest=canonical_digest(
            {
                "version": SANDBOX_VERSION,
                "state": "unavailable-before-launch",
                "workspace_input_digest": workspace.input_digest,
                "bubblewrap_provenance_identity": provenance.identity_digest,
            }
        ),
        sandbox_provenance=provenance,
        profile_evidence=evidence,
    )


def _run_profile_adapter(
    repository: Path,
    spec: AdapterSpec,
    *,
    git_trust_policy: GitTrustPolicy | None,
    expected_tracked_content_digest: str | None,
) -> AdapterResult:
    """Run one built-in profile against an exact tracked-only workspace."""
    if spec.profile is None or spec.configuration_path is None:
        raise ValueError("built-in adapter profile declaration is incomplete")
    profile = profile_by_name(spec.profile)
    with create_adapter_workspace(
        repository,
        configuration_path=spec.configuration_path,
        target_paths=spec.target_paths,
        git_trust_policy=git_trust_policy,
        expected_tracked_content_digest=expected_tracked_content_digest,
    ) as workspace:
        try:
            executable_path = resolved_executable(repository, profile.executable).resolve(
                strict=True
            )
            executable = _trusted_adapter_executable(executable_path)
        except ValueError:
            return _profile_unavailable_result(
                spec,
                workspace,
                reason="executable-unavailable",
                executable_digest=hashlib.sha256(b"").hexdigest(),
                version_output_digest=hashlib.sha256(b"").hexdigest(),
            )
        command_arguments = profile.command_arguments(
            f"/workspace/{workspace.configuration_path}",
            tuple(f"/workspace/{target}" for target in workspace.target_paths),
        )
        sandbox, environment, provenance, sandbox_digest, launcher = sandbox_contract(
            workspace.root,
            executable_path,
            workspace.root,
            repository_destination=Path("/workspace"),
            repository_identity=workspace.input_digest,
            executable_digest=executable.snapshot.digest,
            executable_descriptor=executable.descriptor,
        )
        version_output_digest = hashlib.sha256(b"").hexdigest()
        try:
            try:
                version_result = run_trusted_command(
                    executable,
                    profile.version_arguments,
                    environment={
                        **CHILD_ENVIRONMENT,
                        "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
                        "SEMGREP_ENABLE_VERSION_CHECK": "0",
                        "SEMGREP_SEND_METRICS": "off",
                    },
                    timeout_seconds=min(spec.timeout_seconds, 30),
                    output_limit=8192,
                )
            except RuntimeError:
                return _profile_unavailable_result(
                    spec,
                    workspace,
                    reason="version-unavailable",
                    executable_digest=executable.snapshot.digest,
                    version_output_digest=version_output_digest,
                )
            version_output_digest = canonical_digest(
                {
                    "stdout": hashlib.sha256(version_result.stdout).hexdigest(),
                    "stderr": hashlib.sha256(version_result.stderr).hexdigest(),
                }
            )
            if version_result.returncode != 0:
                return _profile_unavailable_result(
                    spec,
                    workspace,
                    reason="version-unavailable",
                    executable_digest=executable.snapshot.digest,
                    version_output_digest=version_output_digest,
                )
            try:
                tool_version = normalise_version_output(version_result.stdout)
            except ValueError:
                return _profile_unavailable_result(
                    spec,
                    workspace,
                    reason="version-unavailable",
                    executable_digest=executable.snapshot.digest,
                    version_output_digest=version_output_digest,
                )
            process = stream_process(
                (*sandbox, "--", SANDBOX_TOOL, *command_arguments),
                environment=environment,
                timeout_seconds=spec.timeout_seconds,
                pass_fds=(launcher.descriptor, executable.descriptor),
            )
            _verify_adapter_executable(executable)
        finally:
            launcher.close()
            executable.close()
        observed_after = inspect_bubblewrap(provenance.policy)
        if observed_after.identity_digest != provenance.identity_digest:
            changed = tuple(
                key
                for key, value in provenance.to_dict().items()
                if observed_after.to_dict().get(key) != value
            )
            raise RuntimeError(
                "Bubblewrap provenance changed during native audit execution: "
                f"{', '.join(changed)}"
            )
        status, reason, findings, scanned = interpret_profile_output(
            profile,
            stdout=process.stdout,
            returncode=process.returncode,
            timed_out=process.timed_out,
            truncated=process.truncated,
        )
        evidence = AdapterProfileEvidence.build(
            profile=profile,
            status=status,
            reason=reason,
            tool_version=tool_version,
            version_output_digest=version_output_digest,
            configuration_digest=workspace.configuration_digest,
            input_digest=workspace.input_digest,
            output_digest=process.output_digest,
            finding_count=findings,
            scanned_target_count=scanned,
        )
        child_environment = {
            **CHILD_ENVIRONMENT,
            "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
        }
        return AdapterResult(
            name=spec.name,
            returncode=process.returncode,
            output_digest=process.output_digest,
            output_bytes=process.output_bytes,
            output_truncated=process.truncated,
            timed_out=process.timed_out,
            required=spec.required,
            spec_digest=canonical_digest(spec.to_dict()),
            executable_digest=executable.snapshot.digest,
            command_digest=canonical_digest((profile.executable, *command_arguments)),
            environment_digest=canonical_digest(child_environment),
            sandbox_digest=sandbox_digest,
            sandbox_provenance=provenance,
            profile_evidence=evidence,
        )


def run_adapter(
    root: Path,
    spec: AdapterSpec,
    *,
    trusted: bool = False,
    git_trust_policy: GitTrustPolicy | None = None,
    expected_tracked_content_digest: str | None = None,
) -> AdapterResult:
    """Run one explicitly consented adapter inside a read-only sandbox."""
    if not trusted:
        raise ValueError("native audit execution requires explicit trusted consent")
    repository = root.resolve(strict=True)
    if spec.profile is not None:
        validated = AdapterSpec.from_dict(spec.to_dict(), 0)
        if validated != spec:
            raise ValueError("built-in adapter specification is not canonical")
        return _run_profile_adapter(
            repository,
            spec,
            git_trust_policy=git_trust_policy,
            expected_tracked_content_digest=expected_tracked_content_digest,
        )
    executable = resolved_executable(repository, spec.command[0])
    command = (str(executable), *spec.command[1:])
    cwd = working_directory(repository, spec.working_directory)
    sandbox, environment, sandbox_provenance, sandbox_digest, launcher = sandbox_contract(
        repository,
        executable,
        cwd,
    )
    try:
        process = stream_process(
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
        **CHILD_ENVIRONMENT,
        "PATH": f"{Path(sys.prefix) / 'bin'}:/usr/bin:/bin",
    }
    return AdapterResult(
        name=spec.name,
        returncode=process.returncode,
        output_digest=process.output_digest,
        output_bytes=process.output_bytes,
        output_truncated=process.truncated,
        timed_out=process.timed_out,
        required=spec.required,
        spec_digest=canonical_digest(spec.to_dict()),
        executable_digest=file_digest(executable),
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
    git_trust_policy: GitTrustPolicy | None = None,
    expected_tracked_content_digest: str | None = None,
) -> tuple[AdapterResult, ...]:
    """Run applicable adapters only after explicit trusted execution consent."""
    selected = tuple(spec for spec in specs if spec.scope in {scope, "both"})
    names = tuple(spec.name for spec in selected)
    if len(names) != len(set(names)):
        raise ValueError("native audit adapter names must be unique")
    if selected and not trusted:
        raise ValueError("native audit execution requires explicit trusted consent")
    return tuple(
        run_adapter(
            root,
            spec,
            trusted=True,
            git_trust_policy=git_trust_policy,
            expected_tracked_content_digest=expected_tracked_content_digest,
        )
        for spec in selected
    )
