# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exclusive output writer tests
"""Prove explicit output creation never overwrites or follows adopter paths."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest
from cli_test_support import cli_repository
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from test_project_registry_syscall_scheduler import assert_reaped, worker_command

from rigor_foundry.safe_output import write_new_output


def test_write_new_output_creates_one_new_file_and_rejects_overwrite(tmp_path: Path) -> None:
    """The public writer creates once and preserves the first result."""
    output = tmp_path / "report.json"

    write_new_output(output, "first\n")
    with pytest.raises(ValueError, match="already exists"):
        write_new_output(output, "second\n")

    assert output.read_text(encoding="utf-8") == "first\n"


def test_write_new_output_rejects_late_symlink_without_touching_victim(tmp_path: Path) -> None:
    """A symlink introduced after any earlier validation cannot redirect the write."""
    parent = tmp_path / "reports"
    parent.mkdir()
    victim = tmp_path / "victim.json"
    victim.write_text("preserve\n", encoding="utf-8")
    output = parent / "report.json"
    output.symlink_to(victim)

    with pytest.raises(ValueError, match="already exists"):
        write_new_output(output, "replacement\n")

    assert output.is_symlink()
    assert victim.read_text(encoding="utf-8") == "preserve\n"


def test_write_new_output_rejects_symlinked_parent(tmp_path: Path) -> None:
    """Every parent component is bound without following directory links."""
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="no-follow directory"):
        write_new_output(linked_parent / "report.json", "unsafe\n")

    assert not (real_parent / "report.json").exists()


def test_empty_output_and_invalid_utf8_preserve_creation_boundaries(tmp_path: Path) -> None:
    """Create an empty output and refuse invalid UTF-8 before creating a file.

    Parameters
    ----------
    tmp_path : Path
        Owned output allocation with an unrelated retained sibling.
    """
    empty = tmp_path / "empty"
    retained = tmp_path / "retained"
    retained.write_bytes(b"unchanged")
    write_new_output(empty, "")
    assert empty.read_bytes() == b""
    assert stat.S_IMODE(empty.stat().st_mode) == 0o600
    invalid = tmp_path / "invalid"
    with pytest.raises(UnicodeEncodeError):
        write_new_output(invalid, "\ud800")
    assert not invalid.exists()
    assert retained.read_bytes() == b"unchanged"


def test_missing_parent_and_directory_output_are_refused_without_mutation(
    tmp_path: Path,
) -> None:
    """Refuse invalid public paths without creating their missing parent.

    Parameters
    ----------
    tmp_path : Path
        Owned missing-parent and root-directory input allocation.
    """
    missing = tmp_path / "missing"
    with pytest.raises(ValueError, match="parent does not exist"):
        write_new_output(missing / "output", "refused")
    with pytest.raises(ValueError, match="no filename"):
        write_new_output(Path("/"), "refused")
    assert not missing.exists()
    assert list(tmp_path.iterdir()) == []


def test_real_short_write_error_preserves_failed_output(tmp_path: Path) -> None:
    """Preserve actual partial bytes after EFBIG while closing the failed writer.

    Parameters
    ----------
    tmp_path : Path
        Owned output, retained sibling and actual native trace allocation.
    """
    output = tmp_path / "output"
    retained = tmp_path / "retained"
    retained.write_bytes(b"unchanged")
    body = """
import resource
from rigor_foundry.safe_output import write_new_output
limits = resource.getrlimit(resource.RLIMIT_FSIZE)
previous_signal = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (1, limits[1]))
arm_native_trace()
try:
    try:
        write_new_output(Path(sys.argv[1]), "payload")
    except ValueError as exc:
        assert isinstance(exc.__cause__, OSError)
        assert exc.__cause__.errno == errno.EFBIG
        print("real EFBIG refused")
    else:
        raise AssertionError("size-limited output unexpectedly succeeded")
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE, limits)
    signal.signal(signal.SIGXFSZ, previous_signal)
"""
    result = run_traced(worker_command(body, str(output)), lambda _stop: False)
    write_trace(tmp_path / "actual-short-write-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "real EFBIG refused"
    writes = [stop.result for stop in result.stops if stop.number == 1 and not stop.entering]
    assert writes[:2] == [1, -errno.EFBIG]
    assert output.read_bytes() == b"p"
    with pytest.raises(ValueError, match="already exists"):
        write_new_output(output, "retry must not replace partial bytes")
    assert output.read_bytes() == b"p"
    assert retained.read_bytes() == b"unchanged"
    assert_reaped(result.pid)


@pytest.mark.parametrize("phase", ["open", "fsync", "unlink"])
def test_actual_post_creation_swap_preserves_the_replacement(tmp_path: Path, phase: str) -> None:
    """Refuse an exchanged or removed output at its actual creation boundary.

    Parameters
    ----------
    tmp_path : Path
        Owned candidate and replacement with original native trace.
    phase : str
        Swap after open, swap before fsync, or remove before fsync.
    """
    output = tmp_path / "output"
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement remains")
    selected: list[SyscallStop] = []

    def replace_at_boundary(stop: SyscallStop) -> bool:
        """Change only the owned output at an observed open or fsync boundary."""
        after_open = stop.number == 257 and not stop.entering and stop.path == str(output)
        before_fsync = stop.number == 74 and stop.entering
        if not selected and (
            (phase == "open" and after_open) or (phase != "open" and before_fsync)
        ):
            selected.append(stop)
            if phase == "unlink":
                output.unlink()
            else:
                os.replace(replacement, output)
        return False

    body = """
from rigor_foundry.safe_output import write_new_output
arm_native_trace()
try:
    write_new_output(Path(sys.argv[1]), "new bytes")
except (RuntimeError, ValueError) as exc:
    if sys.argv[2] == "unlink":
        assert isinstance(exc, ValueError)
        assert isinstance(exc.__cause__, FileNotFoundError)
        assert str(exc) == f"output path or parent does not exist: {sys.argv[1]}"
        assert Path(sys.argv[1]).parent.is_dir()
    else:
        assert isinstance(exc, RuntimeError)
        expected = ("new output is not a single-link regular file" if sys.argv[2] == "open"
                    else "new output identity changed during creation")
        assert str(exc) == expected
    print("actual output replacement or removal refused")
else:
    raise AssertionError("changed output unexpectedly succeeded")
"""
    result = run_traced(worker_command(body, str(output), phase), replace_at_boundary)
    write_trace(tmp_path / "actual-created-inode-change-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert len(selected) == 1
    assert output.parent.is_dir()
    if phase == "unlink":
        assert not output.exists()
        assert replacement.read_bytes() == b"replacement remains"
    else:
        assert output.read_bytes() == b"replacement remains"
        assert not replacement.exists()
    assert_reaped(result.pid)


def test_actual_parent_replacement_preserves_the_new_parent_output(tmp_path: Path) -> None:
    """Detect a real parent exchange and preserve both directories' exact bytes.

    Parameters
    ----------
    tmp_path : Path
        Owned original and replacement parent allocations with native trace.
    """
    parent = tmp_path / "parent"
    parent.mkdir()
    retired = tmp_path / "retired"
    output = parent / "output"
    selected: list[SyscallStop] = []

    def replace_after_write(stop: SyscallStop) -> bool:
        """Exchange the actual output parent before its first fsync completes."""
        if stop.number == 74 and stop.entering and not selected:
            assert output.read_bytes() == b"new bytes"
            selected.append(stop)
            parent.rename(retired)
            parent.mkdir()
            output.write_bytes(b"replacement remains")
        return False

    body = """
from rigor_foundry.safe_output import write_new_output
arm_native_trace()
try:
    write_new_output(Path(sys.argv[1]), "new bytes")
except RuntimeError as exc:
    assert str(exc) == "output parent identity changed during creation"
    print("actual replaced parent refused")
else:
    raise AssertionError("replaced parent unexpectedly succeeded")
"""
    result = run_traced(worker_command(body, str(output)), replace_after_write)
    write_trace(tmp_path / "actual-parent-swap-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert len(selected) == 1
    assert output.read_bytes() == b"replacement remains"
    assert (retired / "output").read_bytes() == b"new bytes"
    assert_reaped(result.pid)


@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_failure_cleanup_preserves_replacement_after_final_ownership_sample(
    tmp_path: Path, entrypoint: str
) -> None:
    """Preserve a real replacement made after the last failed-write ownership sample.

    Parameters
    ----------
    tmp_path : Path
        Owned output, concurrent replacement and original syscall trace.
    entrypoint : str
        Public writer API or repository scan CLI with its actual error exit.
    """
    output = tmp_path / "output"
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement remains")
    repository = cli_repository(tmp_path / "repository").root if entrypoint == "cli" else tmp_path
    failures: list[SyscallStop] = []
    selected: list[SyscallStop] = []

    def replace_after_failure(stop: SyscallStop) -> bool:
        """Exchange only owned fixture paths at actual stat or final parent close."""
        if stop.number == 1 and not stop.entering and stop.result == -errno.EFBIG:
            failures.append(stop)
        sampled = stop.number == 262 and not stop.entering and stop.path == str(output)
        closing_parent = stop.number == 3 and stop.entering and stop.path == str(tmp_path)
        if failures and not selected and (sampled or closing_parent):
            assert output.read_bytes() == (b"p" if entrypoint == "api" else b"{")
            selected.append(stop)
            os.replace(replacement, output)
        return False

    body = """
import resource
from rigor_foundry.cli import main
from rigor_foundry.safe_output import write_new_output
limits = resource.getrlimit(resource.RLIMIT_FSIZE)
previous_signal = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (1, limits[1]))
arm_native_trace()
before = sorted(os.listdir('/proc/self/fd'))
try:
    if sys.argv[2] == "api":
        try:
            write_new_output(Path(sys.argv[1]), "payload")
        except ValueError as exc:
            assert isinstance(exc.__cause__, OSError)
            assert exc.__cause__.errno == errno.EFBIG
        else:
            raise AssertionError("size-limited output unexpectedly succeeded")
    else:
        assert main(["scan", "--root", sys.argv[3], "--json-out", sys.argv[1]]) == 2
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE, limits)
    signal.signal(signal.SIGXFSZ, previous_signal)
assert sorted(os.listdir('/proc/self/fd')) == before
print("real failed-write replacement preserved")
"""
    result = run_traced(
        worker_command(body, str(output), entrypoint, str(repository)), replace_after_failure
    )
    write_trace(tmp_path / "actual-post-sample-cleanup-replacement-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "real failed-write replacement preserved"
    if entrypoint == "cli":
        assert "repository audit error: cannot create output safely:" in result.stderr
    else:
        assert result.stderr == ""
    assert len(failures) == len(selected) == 1
    assert output.read_bytes() == b"replacement remains"
    assert not replacement.exists()
    assert_reaped(result.pid)
