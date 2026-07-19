# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native-adapter sandbox runtime tests
"""Exercise the extracted native-adapter runtime through real OS boundaries."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapter_runtime import (
    CHILD_ENVIRONMENT,
    OUTPUT_LIMIT,
    contained,
    file_digest,
    resolved_executable,
    sandbox_contract,
    stream_process,
    working_directory,
)


def test_child_environment_binds_the_python_prefix_library() -> None:
    """Console-script interpreters receive a deterministic trusted loader path."""
    assert CHILD_ENVIRONMENT["LD_LIBRARY_PATH"] == str(Path(sys.prefix) / "lib")


def test_runtime_resolves_only_contained_executables_and_directories(tmp_path: Path) -> None:
    """Executable and working-directory resolution stay inside fixed trust roots."""
    repository = GitRepository.create(tmp_path / "repository")
    executable = repository.write_text("tools/check", "#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    nested = repository.root / "nested"
    nested.mkdir()

    assert resolved_executable(repository.root, "tools/check") == executable
    assert (
        resolved_executable(repository.root, "{python}").resolve()
        == Path(sys.executable).resolve()
    )
    assert working_directory(repository.root, "nested") == nested
    assert contained(nested, (repository.root,))
    assert not contained(tmp_path, (repository.root,))
    with pytest.raises(ValueError, match="outside trusted"):
        resolved_executable(repository.root, "/tmp/untrusted")
    with pytest.raises(ValueError, match="escapes"):
        working_directory(repository.root, "../outside")


def test_runtime_hashes_and_streams_real_bounded_process_output(tmp_path: Path) -> None:
    """File and process evidence derives from real bytes under the aggregate cap."""
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"runtime-evidence")
    assert file_digest(payload) == hashlib.sha256(b"runtime-evidence").hexdigest()

    successful = stream_process(
        (sys.executable, "-c", "import sys;sys.stdout.write('out');sys.stderr.write('err')"),
        environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=2,
    )
    assert successful.returncode == 0
    assert successful.stdout == b"out"
    assert successful.stderr == b"err"
    assert successful.output_bytes == 6
    assert not successful.truncated
    assert not successful.timed_out

    truncated = stream_process(
        (sys.executable, "-c", f"print('x' * {OUTPUT_LIMIT + 1})"),
        environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=2,
    )
    assert truncated.returncode == 125
    assert truncated.output_bytes == OUTPUT_LIMIT
    assert truncated.truncated

    timed_out = stream_process(
        (sys.executable, "-c", "import time;time.sleep(5)"),
        environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=1,
    )
    assert timed_out.returncode == 124
    assert timed_out.timed_out

    closed_output_timeout = stream_process(
        (
            sys.executable,
            "-c",
            "import os,time;os.close(1);os.close(2);time.sleep(5)",
        ),
        environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=1,
    )
    assert closed_output_timeout.returncode == 124
    assert closed_output_timeout.timed_out

    with pytest.raises(ValueError, match="cannot hash"):
        file_digest(tmp_path / "missing")


def test_runtime_builds_a_real_descriptor_bound_sandbox_contract(tmp_path: Path) -> None:
    """The extracted owner produces an executable real Bubblewrap contract."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("control.py", "print('bounded')\n")
    repository.commit()
    command, environment, provenance, digest, launcher = sandbox_contract(
        repository.root,
        Path(sys.executable),
        repository.root,
    )
    try:
        assert command[0] == launcher.execution_path
        assert "--unshare-all" in command
        assert str(repository.root) in command
        assert environment == {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}
        assert provenance.executable_path == "/usr/bin/bwrap"
        assert len(digest) == 64
        assert os.fstat(launcher.descriptor).st_size > 0
    finally:
        launcher.close()


def test_runtime_binds_and_validates_profile_environment(tmp_path: Path) -> None:
    """Profile-only environment is content-bound and cannot override fixed values."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("control.py", "print('bounded')\n")
    repository.commit()
    command, _environment, _provenance, first_digest, launcher = sandbox_contract(
        repository.root,
        Path(sys.executable),
        repository.root,
        extra_environment={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/workspace/db"},
    )
    try:
        position = command.index("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
        assert command[position - 1] == "--setenv"
        assert command[position + 1] == "/workspace/db"
    finally:
        launcher.close()
    _command, _environment, _provenance, changed_digest, launcher = sandbox_contract(
        repository.root,
        Path(sys.executable),
        repository.root,
        extra_environment={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/workspace/changed"},
    )
    launcher.close()
    assert changed_digest != first_digest

    for additions in (
        {"PATH": "/untrusted"},
        {"LANG": "other"},
        {"": "value"},
        {"KEY": ""},
    ):
        with pytest.raises(ValueError, match="extra environment"):
            sandbox_contract(
                repository.root,
                Path(sys.executable),
                repository.root,
                extra_environment=additions,
            )


def test_runtime_builds_profile_mount_contract_and_closes_on_invalid_cwd(
    tmp_path: Path,
) -> None:
    """Profile destinations bind descriptors and construction errors release launchers."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("control.py", "print('bounded')\n")
    repository.commit()
    descriptor = os.open(sys.executable, os.O_RDONLY)
    try:
        command, _environment, _provenance, digest, launcher = sandbox_contract(
            repository.root,
            Path(sys.executable),
            repository.root,
            repository_destination=Path("/workspace"),
            repository_identity="f" * 64,
            executable_digest=file_digest(Path(sys.executable)),
            executable_descriptor=descriptor,
        )
        try:
            assert "--ro-bind-fd" in command
            assert "/workspace" in command
            assert len(digest) == 64
        finally:
            launcher.close()
        with pytest.raises(ValueError):
            sandbox_contract(
                repository.root,
                Path(sys.executable),
                tmp_path,
            )
    finally:
        os.close(descriptor)
