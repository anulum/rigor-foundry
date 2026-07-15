# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — trusted Git executable provenance tests
"""Exercise real executable discovery, identity, version, and replacement boundaries."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry.git_provenance as provenance_module
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.git_provenance import (
    GitExecutableProvenance,
    GitRunner,
    GitTrustPolicy,
)
from tools._repository import run as run_repository_tool


def _git_script(
    path: Path,
    version: str,
    *,
    marker: Path | None = None,
    delegate: bool = False,
) -> Path:
    """Create one real executable that reports a selected Git version."""
    lines = ["#!/bin/sh"]
    if marker is not None:
        lines.append(f"printf invoked > '{marker}'")
    lines.extend(
        (
            'if [ "$1" = "--version" ]; then',
            f"  printf '%s\\n' 'git version {version}'",
            "  exit 0",
            "fi",
        )
    )
    lines.append('exec /usr/bin/git "$@"' if delegate else "exit 64")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _policy(root: Path, *, version: str = "2.35.2") -> GitTrustPolicy:
    """Return an explicit test-root policy with an adjustable lower bound."""
    return GitTrustPolicy(
        trusted_roots=(str(root),),
        minimum_version=version,
        maximum_version_exclusive="3.0.0",
    )


def test_default_policy_ignores_path_shadowing_and_records_real_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hostile PATH entry is never selected or executed by inventory loading."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    marker = tmp_path / "shadow-invoked"
    fsmonitor_marker = tmp_path / "fsmonitor-invoked"
    fsmonitor = tmp_path / "fsmonitor-hook"
    fsmonitor.write_text(
        f"#!/bin/sh\nprintf invoked > '{fsmonitor_marker}'\nprintf '%s\\n' 2\n",
        encoding="utf-8",
    )
    fsmonitor.chmod(0o755)
    repository.git_command("config", "core.fsmonitor", str(fsmonitor))
    shadow = tmp_path / "shadow-bin"
    _git_script(shadow / "git", "2.43.0", marker=marker)
    monkeypatch.setenv("PATH", str(shadow))

    inventory = load_git_inventory(repository.root)

    assert inventory.git_provenance.resolved_path != str(shadow / "git")
    assert Path(inventory.git_provenance.resolved_path).is_absolute()
    assert tuple(int(part) for part in inventory.git_provenance.version.split(".")) >= (2, 35, 2)
    assert len(inventory.git_provenance.executable_digest) == 64
    assert not marker.exists()
    assert not fsmonitor_marker.exists()


def test_repository_validation_tools_share_trusted_git_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repository self-check helpers do not reintroduce ambient PATH lookup."""
    marker = tmp_path / "tool-shadow-invoked"
    shadow = tmp_path / "shadow-bin"
    _git_script(shadow / "git", "2.43.0", marker=marker)
    monkeypatch.setenv("PATH", str(shadow))

    result = run_repository_tool("git", "--version", cwd=tmp_path)

    assert result.returncode == 0
    assert result.stdout.startswith("git version ")
    assert not marker.exists()


@pytest.mark.parametrize("link_target", ("executable", "root"))
def test_runner_rejects_executable_and_trust_root_symlinks(
    tmp_path: Path,
    link_target: str,
) -> None:
    """Neither the selected executable nor its declared root may be a symlink."""
    real_root = tmp_path / "real-tools"
    _git_script(real_root / "git", "2.43.0")
    if link_target == "executable":
        trusted_root = tmp_path / "trusted-tools"
        trusted_root.mkdir()
        (trusted_root / "git").symlink_to(real_root / "git")
    else:
        trusted_root = tmp_path / "trusted-tools"
        trusted_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlink"):
        GitRunner(_policy(trusted_root))


def test_runner_detects_replacement_before_executing_new_bytes(tmp_path: Path) -> None:
    """A path replacement after provenance capture fails before attacker bytes run."""
    trusted_root = tmp_path / "trusted-tools"
    executable = _git_script(trusted_root / "git", "2.43.0", delegate=True)
    runner = GitRunner(_policy(trusted_root))
    marker = tmp_path / "replacement-invoked"
    replacement = _git_script(tmp_path / "replacement", "2.43.0", marker=marker)
    os.replace(replacement, executable)

    with pytest.raises(RuntimeError, match="replaced after provenance capture"):
        runner.run(tmp_path, "--version")
    assert not marker.exists()


def test_constructor_binds_validation_to_component_safe_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An intermediate-root swap after pathname validation never becomes baseline."""
    trusted_root = tmp_path / "trusted-tools"
    _git_script(trusted_root / "git", "2.43.0")
    outside = tmp_path / "outside-tools"
    marker = tmp_path / "outside-invoked"
    _git_script(outside / "git", "2.43.0", marker=marker)
    preserved = tmp_path / "preserved-tools"
    original_validate = GitRunner._validate_path

    def validate_then_swap(
        runner: GitRunner,
        candidate: Path,
        root: Path,
    ) -> tuple[Path, Path]:
        result = original_validate(runner, candidate, root)
        root.rename(preserved)
        root.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(GitRunner, "_validate_path", validate_then_swap)
    with pytest.raises(RuntimeError, match="cannot open trusted Git executable"):
        GitRunner(_policy(trusted_root))
    assert not marker.exists()


def test_runner_pins_descriptor_across_execution_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A swap after descriptor pinning executes original bytes, then fails evidence."""
    if not any(path.is_dir() for path in (Path("/proc/self/fd"), Path("/dev/fd"))):
        pytest.skip("platform has no descriptor execution path")
    tools = tmp_path / "tools"
    tools.mkdir()
    original_marker = tmp_path / "original-invoked"
    attacker_marker = tmp_path / "attacker-invoked"
    executable = tools / "git"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        "  printf '%s\\n' 'git version 2.43.0'\n"
        "  exit 0\n"
        "fi\n"
        f"printf original > '{original_marker}'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    runner = GitRunner(_policy(tools))
    replacement = _git_script(
        tmp_path / "replacement",
        "2.43.0",
        marker=attacker_marker,
    )
    original_run = provenance_module.subprocess.run

    def swap_then_run(*args: object, **kwargs: object) -> object:
        os.replace(replacement, executable)
        return original_run(*args, **kwargs)

    monkeypatch.setattr(provenance_module.subprocess, "run", swap_then_run)
    with pytest.raises(RuntimeError, match="replaced after provenance capture"):
        runner.run(tmp_path, "status")

    assert original_marker.read_text(encoding="utf-8") == "original"
    assert not attacker_marker.exists()


@pytest.mark.parametrize(
    ("version", "minimum", "maximum"),
    (
        ("2.35.1", "2.35.2", "3.0.0"),
        ("3.0.0", "2.35.2", "3.0.0"),
    ),
)
def test_runner_rejects_unsupported_git_versions(
    tmp_path: Path,
    version: str,
    minimum: str,
    maximum: str,
) -> None:
    """Both sides of the declared half-open compatibility interval are enforced."""
    trusted_root = tmp_path / version
    _git_script(trusted_root / "git", version)
    policy = GitTrustPolicy(
        trusted_roots=(str(trusted_root),),
        minimum_version=minimum,
        maximum_version_exclusive=maximum,
    )

    with pytest.raises(RuntimeError, match="outside supported interval"):
        GitRunner(policy)


def test_policy_and_provenance_round_trip_reject_identity_tampering(tmp_path: Path) -> None:
    """Trust and executable identities survive parsing and reject changed evidence."""
    trusted_root = tmp_path / "trusted-tools"
    _git_script(trusted_root / "git", "2.43.0.windows.1")
    policy = _policy(trusted_root)
    runner = GitRunner(policy)

    assert GitTrustPolicy.from_dict(policy.to_dict()) == policy
    assert GitExecutableProvenance.from_dict(runner.provenance.to_dict()) == runner.provenance
    changed = runner.provenance.to_dict()
    changed["version"] = "2.42.0"
    with pytest.raises(ValueError, match="identity digest"):
        GitExecutableProvenance.from_dict(changed)

    windows_policy = GitTrustPolicy(
        trusted_roots=("C:/Program Files/Git/cmd",),
    )
    assert GitTrustPolicy.from_dict(windows_policy.to_dict()) == windows_policy
    windows = GitExecutableProvenance.build(
        resolved_path="C:/Program Files/Git/cmd/git.exe",
        trusted_root="C:/Program Files/Git/cmd",
        version="2.43.0",
        executable_digest="1" * 64,
        trust_policy=windows_policy,
    )
    assert GitExecutableProvenance.from_dict(windows.to_dict()) == windows


def test_policy_rejects_ambiguous_roots_and_executable_escape(tmp_path: Path) -> None:
    """Relative roots, duplicate roots, and executable/root mismatch fail closed."""
    with pytest.raises(ValueError, match="normalised absolute"):
        GitTrustPolicy(trusted_roots=("relative-tools",))
    root = str(tmp_path / "trusted")
    with pytest.raises(ValueError, match="unique"):
        GitTrustPolicy(trusted_roots=(root, root))
    with pytest.raises(RuntimeError, match="outside trusted roots"):
        GitRunner(
            GitTrustPolicy(
                executable="/usr/bin/git",
                trusted_roots=(root,),
            )
        )


def test_runner_uses_ordered_roots_and_most_specific_absolute_root(tmp_path: Path) -> None:
    """Root ordering and containment are deterministic for relative and absolute inputs."""
    tools = tmp_path / "prefix" / "bin"
    executable = _git_script(tools / "git", "2.43.0")
    relative = GitRunner(GitTrustPolicy(trusted_roots=(str(tmp_path / "missing"), str(tools))))
    assert relative.provenance.trusted_root == str(tools)

    absolute = GitRunner(
        GitTrustPolicy(
            executable=str(executable),
            trusted_roots=(str(tmp_path), str(tools)),
        )
    )
    assert absolute.provenance.trusted_root == str(tools)

    if os.name != "nt":
        windows_root = "C:/Program Files/Git/cmd"
        with pytest.raises(RuntimeError, match="executable is not native"):
            GitRunner(
                GitTrustPolicy(
                    executable=f"{windows_root}/git.exe",
                    trusted_roots=(windows_root,),
                )
            )
        with pytest.raises(RuntimeError, match="trust root is not native"):
            GitRunner(GitTrustPolicy(trusted_roots=(windows_root,)))


def test_runner_rejects_unavailable_nonexecutable_and_failed_binaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery and version execution never coerce invalid executable surfaces."""
    with pytest.raises(RuntimeError, match="unavailable below"):
        GitRunner(_policy(tmp_path / "missing"))
    missing_root = tmp_path / "missing-absolute"
    with pytest.raises(RuntimeError, match="trusted root is unavailable"):
        GitRunner(
            GitTrustPolicy(
                executable=str(missing_root / "git"),
                trusted_roots=(str(missing_root),),
            )
        )

    nonexecutable_root = tmp_path / "nonexecutable"
    nonexecutable = _git_script(nonexecutable_root / "git", "2.43.0")
    nonexecutable.chmod(0o644)
    with pytest.raises(RuntimeError, match="single-link executable"):
        GitRunner(_policy(nonexecutable_root))

    unsafe_root = tmp_path / "unsafe-mode"
    unsafe = _git_script(unsafe_root / "git", "2.43.0")
    unsafe.chmod(0o775)
    with pytest.raises(RuntimeError, match="group/world write"):
        GitRunner(_policy(unsafe_root))
    reference_root = tmp_path / "reference"
    _git_script(reference_root / "git", "2.43.0")
    reference_runner = GitRunner(_policy(reference_root))
    with monkeypatch.context() as patch:
        patch.setattr(provenance_module.os, "name", "nt")
        assert reference_runner._validate_path(unsafe, unsafe_root) == (unsafe, unsafe_root)

    hardlink_root = tmp_path / "hardlink"
    hardlink_root.mkdir()
    outside = _git_script(tmp_path / "outside-git", "2.43.0")
    os.link(outside, hardlink_root / "git")
    with pytest.raises(RuntimeError, match="single-link executable"):
        GitRunner(_policy(hardlink_root))

    failed_root = tmp_path / "failed"
    failed = failed_root / "git"
    failed.parent.mkdir()
    failed.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    failed.chmod(0o755)
    with pytest.raises(RuntimeError, match="exit status 23"):
        GitRunner(_policy(failed_root))

    malformed_root = tmp_path / "malformed"
    _git_script(malformed_root / "git", "not-semantic")
    with pytest.raises(RuntimeError, match="unsupported version format"):
        GitRunner(_policy(malformed_root))

    non_utf8_root = tmp_path / "non-utf8"
    non_utf8 = non_utf8_root / "git"
    non_utf8.parent.mkdir()
    non_utf8.write_bytes(b"#!/bin/sh\nprintf '\\377\\n'\n")
    non_utf8.chmod(0o755)
    with pytest.raises(RuntimeError, match="non-UTF-8 version"):
        GitRunner(_policy(non_utf8_root))

    reserved_root = tmp_path / "reserved-hooks"
    _git_script(reserved_root / "git", "2.43.0")
    reserved_runner = GitRunner(_policy(reserved_root))
    (reserved_root / ".rigor-foundry-disabled-hooks").mkdir()
    with pytest.raises(RuntimeError, match="reserved disabled-hooks"):
        reserved_runner.run(tmp_path, "status", check=False)


@pytest.mark.parametrize(
    "arguments",
    (
        ("-c", "core.fsmonitor=/attacker/monitor", "status"),
        ("-ccore.hooksPath=/attacker/hooks", "status"),
        ("--config-env=CORE.FSMONITOR=ATTACKER_PATH", "status"),
    ),
)
def test_runner_rejects_protected_config_overrides(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    """Later argv cannot reactivate repository-local monitors or hooks."""
    tools = tmp_path / "protected-config"
    _git_script(tools / "git", "2.43.0")
    runner = GitRunner(_policy(tools))

    with pytest.raises(ValueError, match=r"Git config override .* is reserved"):
        runner.run(tmp_path, *arguments, check=False)


def test_runner_file_descriptor_and_timeout_guards_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real non-files and a simulated subprocess deadline exercise final guards."""
    with pytest.raises(RuntimeError, match="cannot open trusted"):
        GitRunner._snapshot_file(tmp_path / "missing")
    with pytest.raises(RuntimeError, match="not a regular file"):
        GitRunner._snapshot_file(tmp_path)
    with pytest.raises(RuntimeError, match="must be absolute"):
        GitRunner._open_no_follow(Path("relative/git"))
    with monkeypatch.context() as patch:
        patch.delattr(os, "O_NOFOLLOW")
        with pytest.raises(RuntimeError, match="lacks component-safe"):
            GitRunner._open_no_follow(Path("/usr/bin/git"))

    tools = tmp_path / "tools"
    _git_script(tools / "git", "2.43.0")
    runner = GitRunner(_policy(tools))

    def expire(*_args: object, **_kwargs: object) -> None:
        raise provenance_module.subprocess.TimeoutExpired("git", 30)

    monkeypatch.setattr(provenance_module.subprocess, "run", expire)
    with pytest.raises(RuntimeError, match="30-second limit"):
        runner.run(tmp_path, "status")


def test_runner_detects_validation_and_hash_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Instrumented race points reject escape, disappearance, and identity changes."""
    tools = tmp_path / "tools"
    executable = _git_script(tools / "git", "2.43.0")
    runner = GitRunner(_policy(tools))
    with pytest.raises(RuntimeError, match="outside trusted roots"):
        runner._validate_path(tmp_path / "outside" / "git", tools)
    with pytest.raises(RuntimeError, match="path is unavailable"):
        runner._validate_path(tools / "missing", tools)

    original_resolve = Path.resolve

    def unavailable_resolve(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> Path:
        if path == executable:
            raise OSError("injected resolution race")
        return original_resolve(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", unavailable_resolve)
        with pytest.raises(RuntimeError, match="cannot be resolved"):
            runner._validate_path(executable, tools)

    def changed_resolve(path: Path, *args: object, **kwargs: object) -> Path:
        if path == executable:
            return tmp_path / "different"
        return original_resolve(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", changed_resolve)
        with pytest.raises(RuntimeError, match="must not contain symlinks"):
            runner._validate_path(executable, tools)

    original_fstat = os.fstat
    calls = 0

    def changed_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = original_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size + 1,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns,
            )
        return metadata

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", changed_fstat)
        with pytest.raises(RuntimeError, match="changed while hashing"):
            GitRunner._snapshot_file(executable)

    original_stat = Path.stat

    def disappeared_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        if path == executable:
            raise OSError("injected disappearance")
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "stat", disappeared_stat)
        with pytest.raises(RuntimeError, match="disappeared while hashing"):
            GitRunner._snapshot_file(executable)

    def changed_path_stat(
        path: Path, *args: object, **kwargs: object
    ) -> os.stat_result | SimpleNamespace:
        metadata = original_stat(path, *args, **kwargs)
        if path == executable:
            return SimpleNamespace(
                st_dev=metadata.st_dev + 1,
                st_ino=metadata.st_ino,
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns,
            )
        return metadata

    with monkeypatch.context() as patch:
        patch.setattr(Path, "stat", changed_path_stat)
        with pytest.raises(RuntimeError, match="changed while hashing"):
            GitRunner._snapshot_file(executable)

    unsafe = _git_script(tmp_path / "unsafe-snapshot" / "git", "2.43.0")
    unsafe.chmod(0o775)
    with pytest.raises(RuntimeError, match="group/world write"):
        GitRunner._snapshot_file(unsafe)

    original_open_no_follow = GitRunner._open_no_follow
    open_calls = 0

    def disappear_before_pin(path: Path) -> int:
        nonlocal open_calls
        open_calls += 1
        if open_calls == 2:
            raise RuntimeError("injected pre-pin disappearance")
        return original_open_no_follow(path)

    with monkeypatch.context() as patch:
        patch.setattr(GitRunner, "_open_no_follow", staticmethod(disappear_before_pin))
        with pytest.raises(RuntimeError, match="disappeared before execution"):
            runner.run(tmp_path, "status", check=False)

    fstat_calls = 0

    def change_before_pin(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal fstat_calls
        fstat_calls += 1
        metadata = original_fstat(descriptor)
        if fstat_calls == 3:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino + 1,
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns,
            )
        return metadata

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", change_before_pin)
        with pytest.raises(RuntimeError, match="changed before descriptor pinning"):
            runner.run(tmp_path, "status", check=False)

    original_is_dir = Path.is_dir

    def hide_descriptor_roots(path: Path) -> bool:
        if path in {Path("/proc/self/fd"), Path("/dev/fd")}:
            return False
        return original_is_dir(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "is_dir", hide_descriptor_roots)
        with pytest.raises(RuntimeError, match="cannot execute a pinned Git descriptor"):
            runner.run(tmp_path, "status", check=False)


def test_portable_default_roots_are_platform_specific(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fixed default root table has explicit Windows, macOS, and POSIX branches."""
    runner = GitRunner()
    monkeypatch.setattr(provenance_module.os, "name", "nt")
    assert provenance_module._portable_roots()[0] == "C:/Program Files/Git/cmd"
    assert runner._environment()["SYSTEMROOT"]
    monkeypatch.setattr(provenance_module.os, "name", "posix")
    monkeypatch.setattr(provenance_module.sys, "platform", "darwin")
    assert provenance_module._portable_roots()[1] == "/opt/homebrew/bin"
    monkeypatch.setattr(provenance_module.sys, "platform", "linux")
    assert provenance_module._portable_roots()[0] == "/usr/bin"


def test_windows_basename_discovery_adds_executable_suffix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows basename discovery checks the fixed-root ``.exe`` form explicitly."""
    tools = tmp_path / "windows-tools"
    executable = _git_script(tools / "git.exe", "2.43.0")
    policy = GitTrustPolicy(trusted_roots=(str(tools),))
    monkeypatch.setattr(provenance_module.sys, "platform", "win32")
    runner = object.__new__(GitRunner)
    runner.policy = policy

    resolved, root = runner._locate()

    assert resolved == executable
    assert root == tools

    with pytest.raises(ValueError, match="differs from its trust policy"):
        GitExecutableProvenance.build(
            resolved_path="/usr/bin/git.exe",
            trusted_root="/usr/bin",
            version="2.43.0",
            executable_digest="1" * 64,
            trust_policy=GitTrustPolicy(trusted_roots=("/usr/bin",)),
        )
