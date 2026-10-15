# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Git provenance race contracts
"""Schedule real fixture mutations around public Git executable identity checks."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace

from rigor_foundry.git_provenance import GitExecutableProvenance, GitRunner, GitTrustPolicy


@pytest.fixture(scope="module")
def installed_provenance() -> GitExecutableProvenance:
    """Capture the installed Git's actual public provenance for format rejection tests.

    Returns
    -------
    GitExecutableProvenance
        Native executable, trust policy and content-derived identities.
    """
    return GitRunner().provenance


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "2.0", "unsupported Git trust-policy schema"),
        ("executable", "", "must be a non-empty string"),
        ("executable", "tools/git", "one basename"),
        ("executable", "../git", "one basename"),
        ("executable", "tools\\git", "one basename"),
        ("trusted_roots", "not-an-array", "string array"),
        ("trusted_roots", [1], "string array"),
        ("trusted_roots", [], "must not be empty"),
        ("trusted_roots", ["/usr/../bin"], "normalised canonical path"),
        ("minimum_version", "2.35", "three-part numeric"),
        ("minimum_version", "3.0.0", "interval must be non-empty"),
        ("maximum_version_exclusive", "2.35.2", "interval must be non-empty"),
    ],
)
def test_policy_document_rejects_ambiguous_inputs(
    installed_provenance: GitExecutableProvenance,
    field: str,
    value: object,
    message: str,
) -> None:
    """Actual policy documents reject malformed executable, root and version inputs."""
    document = installed_provenance.trust_policy.to_dict()
    document[field] = value
    with pytest.raises(ValueError, match=message):
        GitTrustPolicy.from_dict(document)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "2.0", "unsupported Git provenance schema"),
        ("executable_digest", "A" * 64, "lowercase SHA-256"),
        ("trust_policy_digest", "A" * 64, "lowercase SHA-256"),
        ("trust_policy_digest", "0" * 64, "trust-policy digest does not match"),
        ("identity_digest", "A" * 64, "lowercase SHA-256"),
        ("resolved_path", "C:/Program Files/Git/cmd/git.exe", "same path format"),
        ("resolved_path", "/outside/git", "outside its trusted root"),
        ("trusted_root", "/", "not declared by its trust policy"),
        ("version", "3.0.0", "outside its trust policy interval"),
    ],
)
def test_provenance_document_rejects_identity_and_relationship_drift(
    installed_provenance: GitExecutableProvenance,
    field: str,
    value: object,
    message: str,
) -> None:
    """Tampering with actual provenance cannot change its embedded trust relations."""
    document = installed_provenance.to_dict()
    document[field] = value
    with pytest.raises(ValueError, match=message):
        GitExecutableProvenance.from_dict(document)


def test_absolute_executable_policy_binds_the_exact_provenance_path(
    installed_provenance: GitExecutableProvenance,
) -> None:
    """An absolute policy cannot attest another executable beneath the same root."""
    policy = GitTrustPolicy(
        executable=installed_provenance.resolved_path,
        trusted_roots=installed_provenance.trust_policy.trusted_roots,
    )
    document = installed_provenance.to_dict()
    document["trust_policy"] = policy.to_dict()
    document["trust_policy_digest"] = policy.policy_digest
    document["resolved_path"] = str(
        Path(installed_provenance.resolved_path).with_name("other-git")
    )
    with pytest.raises(ValueError, match="executable differs from its trust policy"):
        GitExecutableProvenance.from_dict(document)


def test_direct_policy_rejects_an_empty_executable() -> None:
    """The constructor itself rejects an empty executable before root discovery."""
    with pytest.raises(ValueError, match="git executable must be non-empty"):
        GitTrustPolicy(executable="")


@pytest.fixture
def git_fixture(tmp_path: Path) -> Path:
    """Copy the real installed Git into an explicitly trusted owned fixture root.

    Parameters
    ----------
    tmp_path : Path
        Owned pytest fixture allocation.

    Returns
    -------
    Path
        Fixture root containing the actual executable bytes under tools/git.
    """
    tools = tmp_path / "tools"
    tools.mkdir(mode=0o700)
    shutil.copyfile("/usr/bin/git", tools / "git")
    (tools / "git").chmod(0o755)
    return tmp_path


def _observe(
    root: Path, operation: str, callback: Callable[[SyscallStop], bool]
) -> dict[str, object]:
    """Retain an actual trace and report the public worker outcome."""
    result = run_traced(
        [
            sys.executable,
            "-B",
            str(Path(__file__).with_name("filesystem_refusal_worker.py")),
            operation,
            str(root),
        ],
        callback,
        timeout=90,
    )
    write_trace(root / "git-trace.json", result)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


@pytest.mark.parametrize("operation", ["git-hashing", "git-pinning"])
def test_native_git_control_uses_actual_executable(git_fixture: Path, operation: str) -> None:
    """Observation preserves actual executable hashing and native Git execution."""
    result = _observe(git_fixture, operation, lambda _stop: False)
    assert result["accepted"] is True
    if operation == "git-hashing":
        expected = hashlib.sha256((git_fixture / "tools/git").read_bytes()).hexdigest()
        assert result["outcome"] == expected
    else:
        assert str(result["outcome"]).startswith("git version ")


@pytest.mark.parametrize("phase", ["descriptor-samples", "pathname-sample"])
def test_actual_metadata_change_during_hashing_refuses(git_fixture: Path, phase: str) -> None:
    """Real metadata changes invalidate both descriptor and pathname samples."""
    executable = git_fixture / "tools/git"
    original = executable.read_bytes()
    before = executable.stat()
    changed = False
    finished_read = False

    def mutate(stop: SyscallStop) -> bool:
        """Change actual metadata at the selected native hash boundary."""
        nonlocal changed, finished_read
        if stop.number == 0 and not stop.entering and stop.path == str(executable):
            finished_read |= stop.result == 0
        descriptor_sample = phase == "descriptor-samples" and stop.number == 0
        pathname_sample = phase == "pathname-sample" and finished_read and stop.number == 262
        if (
            not changed
            and stop.entering
            and stop.path == str(executable)
            and (descriptor_sample or pathname_sample)
        ):
            os.utime(executable, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            changed = True
        return False

    result = _observe(git_fixture, "git-hashing", mutate)
    assert changed
    assert result["accepted"] is False
    assert "trusted Git executable changed while hashing" in str(result["error"])
    assert executable.read_bytes() == original
    assert executable.stat().st_mtime_ns != before.st_mtime_ns


def test_replacement_before_descriptor_pinning_never_executes(git_fixture: Path) -> None:
    """An actual replacement after preverification cannot run its delegating bytes."""
    executable = git_fixture / "tools/git"
    retained = git_fixture / "retained-git"
    marker = git_fixture / "replacement-executed"
    original = executable.read_bytes()
    opens = 0
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Install marked delegating bytes before the execution open."""
        nonlocal opens, changed
        if stop.number == 257 and stop.entering and stop.path == str(executable):
            opens += 1
            if opens == 2:
                executable.rename(retained)
                executable.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' 'replacement ran' > " + shlex.quote(str(marker)) + "\n"
                    'exec /usr/bin/git "$@"\n',
                    encoding="utf-8",
                )
                executable.chmod(0o755)
                changed = True
        return False

    result = _observe(git_fixture, "git-pinning", mutate)
    assert changed
    assert result["accepted"] is False
    # The post-call verification also refuses and supersedes the earlier error.
    assert "replaced after provenance capture" in str(result["error"])
    assert not marker.exists(), "the replacement ran before the final refusal"
    assert retained.read_bytes() == original
    assert executable.read_bytes() != original


@pytest.mark.parametrize(
    ("phase", "message"),
    [
        ("lstat-disappearance", "Git executable path is unavailable"),
        ("resolve-disappearance", "Git executable path cannot be resolved"),
        ("resolve-symlink", "Git executable path must not contain symlinks"),
        ("snapshot-directory", "trusted Git executable is not a regular file"),
        ("hash-disappearance", "trusted Git executable disappeared while hashing"),
    ],
)
def test_native_constructor_filesystem_changes_refuse(
    git_fixture: Path, phase: str, message: str
) -> None:
    """Real disappearance and type changes cannot become executable provenance."""
    executable = git_fixture / "tools/git"
    retained = git_fixture / "retained-git"
    original = executable.read_bytes()
    samples = 0
    finished_read = False
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Replace the leaf at the selected actual validation step."""
        nonlocal samples, finished_read, changed
        if stop.number == 0 and not stop.entering and stop.path == str(executable):
            finished_read |= stop.result == 0
        target_sample = stop.number == 262 and stop.entering and stop.path == str(executable)
        if target_sample:
            samples += 1
        selected = (
            (phase == "lstat-disappearance" and target_sample and samples == 2)
            or (phase.startswith("resolve-") and target_sample and samples == 3)
            or (phase == "hash-disappearance" and target_sample and finished_read)
            or (
                phase == "snapshot-directory"
                and stop.number == 257
                and stop.entering
                and stop.path == str(executable)
            )
        )
        if not changed and selected:
            executable.rename(retained)
            if phase == "resolve-symlink":
                executable.symlink_to(retained)
            elif phase == "snapshot-directory":
                executable.mkdir(mode=0o700)
            changed = True
        return False

    result = _observe(git_fixture, "git-hashing", mutate)
    assert changed
    assert result["accepted"] is False
    assert message in str(result["error"])
    assert retained.read_bytes() == original


def test_disappearance_before_descriptor_pinning_refuses(git_fixture: Path) -> None:
    """An actual missing execution leaf cannot bypass final descriptor cleanup."""
    executable = git_fixture / "tools/git"
    retained = git_fixture / "retained-git"
    original = executable.read_bytes()
    opens = 0
    changed = False

    def mutate(stop: SyscallStop) -> bool:
        """Remove the fixture leaf before its execution open."""
        nonlocal opens, changed
        if stop.number == 257 and stop.entering and stop.path == str(executable):
            opens += 1
            if opens == 2:
                executable.rename(retained)
                changed = True
        return False

    result = _observe(git_fixture, "git-pinning", mutate)
    assert changed
    assert result["accepted"] is False
    assert "cannot open trusted Git executable" in str(result["error"])
    assert retained.read_bytes() == original
    assert not executable.exists()
