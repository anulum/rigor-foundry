# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual repository file input tests
"""Exercise actual baseline blobs, no-follow worktree reads and complete Git paths."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import zlib
from pathlib import Path
from typing import cast

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_file_inputs import observe_repository_file_inputs


def _budget(
    *,
    source: int = 65536,
    total: int = 1048576,
    sources: int = 256,
    references: int = 256,
    depth: int = 16,
) -> PolicyReadBudget1:
    """Supply explicit original-format, file and transaction ceilings."""
    return PolicyReadBudget1.build(
        max_document_bytes=65536,
        max_source_bytes=source,
        max_total_source_bytes=total,
        max_sources=sources,
        max_rules=16,
        max_references=references,
        max_depth=depth,
    )


@pytest.mark.parametrize("object_format", ("sha1", "sha256"))
def test_file_inputs_keep_actual_baseline_staged_and_current_binary_bytes(
    tmp_path: Path, object_format: str
) -> None:
    """Earlier bytes survive renames/deletion while current hashes follow real bytes."""
    repository = GitRepository.create(tmp_path / "repository", object_format=object_format)
    repository.write_bytes("src/binary.bin", bytes(range(256)))
    executable = repository.write_text("src/run.sh", "#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    repository.write_bytes("empty", b"")
    repository.write_text("removed/nested.py", "OLD = 1\n")
    repository.write_text("before.py", "VALUE = 1\n")
    baseline = repository.commit()
    before_blob = repository.git_command("rev-parse", "HEAD:before.py").stdout.strip()
    repository.write_text("before.py", "VALUE = 2\n")
    head = repository.commit()
    repository.git_command("mv", "before.py", "after.py")
    repository.write_text("after.py", "VALUE = 3\n")
    repository.git_command("add", "after.py")
    staged_blob = repository.git_command("rev-parse", ":after.py").stdout.strip()
    repository.write_text("after.py", "VALUE = 4\n")
    (repository.root / "removed/nested.py").unlink()
    (repository.root / "removed").rmdir()
    new = repository.write_bytes("src/nový.bin", b"\xff\x00\x80\r\n")
    repository.write_text("docs/internal/secret.md", "ignored, independently owned\n")

    observed = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    old = {row.relative_path: row for row in observed.baseline_files}
    current = {row.relative_path: row for row in observed.current_files}
    assert observed.git.baseline_head == baseline
    assert observed.git.head == head != baseline
    assert old["before.py"].object_id == before_blob
    assert old["before.py"].byte_digest == hashlib.sha256(b"VALUE = 1\n").hexdigest()
    assert old["removed/nested.py"].byte_digest == hashlib.sha256(b"OLD = 1\n").hexdigest()
    assert current["before.py"].kind == current["removed/nested.py"].kind == "deleted"
    assert current["before.py"].byte_digest is None
    assert current["after.py"].byte_digest == hashlib.sha256(b"VALUE = 4\n").hexdigest()
    assert current["after.py"].object_id != staged_blob
    assert (
        next(
            entry.object_id
            for entry in observed.git.index.entries
            if entry.relative_path == "after.py"
        )
        == staged_blob
    )
    assert current["src/nový.bin"].byte_count == 5
    assert current["src/nový.bin"].byte_digest == hashlib.sha256(new.read_bytes()).hexdigest()
    assert current["src/binary.bin"].byte_digest == hashlib.sha256(bytes(range(256))).hexdigest()
    assert old["src/run.sh"].mode == current["src/run.sh"].mode == "100755"
    assert (
        old["empty"].byte_digest == current["empty"].byte_digest == hashlib.sha256(b"").hexdigest()
    )
    assert all(
        row.language is None and row.role is None for row in (*old.values(), *current.values())
    )
    assert "docs/internal/secret.md" not in current
    assert tuple(current) == tuple(sorted(current))


def test_file_inputs_hash_symlink_bytes_without_reading_the_target(tmp_path: Path) -> None:
    """Absolute and broken symlinks remain link contents, without following targets."""
    repository = GitRepository.create(tmp_path / "repository")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside bytes must not become source bytes")
    outside.chmod(0)
    repository.symlink("link", str(outside))
    baseline = repository.commit()
    (repository.root / "link").unlink()
    repository.symlink("link", "missing-target")
    observed = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    old = next(row for row in observed.baseline_files if row.relative_path == "link")
    current = next(row for row in observed.current_files if row.relative_path == "link")
    assert old.kind == current.kind == "symlink"
    assert old.mode == current.mode == "120000"
    assert old.byte_digest == hashlib.sha256(os.fsencode(outside)).hexdigest()
    assert current.byte_digest == hashlib.sha256(b"missing-target").hexdigest()
    assert old.object_id != current.object_id


def test_file_inputs_charge_actual_metadata_bytes_without_fixed_reservations(
    tmp_path: Path,
) -> None:
    """Valid file bytes can use more than half the unchanged transaction ceiling."""
    repository = GitRepository.create(tmp_path / "repository")
    payload = b"x" * 18000
    repository.write_bytes("source", payload)
    baseline = repository.commit()
    limits = _budget(source=20000, total=100000)
    observed = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=limits
    )
    assert 0 < observed.git.source_bytes_read < limits.max_total_source_bytes // 4
    before = next(row for row in observed.baseline_files if row.relative_path == "source")
    current = next(row for row in observed.current_files if row.relative_path == "source")
    assert before.byte_count == current.byte_count == len(payload)
    assert before.byte_digest == current.byte_digest == hashlib.sha256(payload).hexdigest()
    assert 4 * len(payload) > limits.max_total_source_bytes // 2


def test_file_inputs_retain_gitlinks_and_unsupported_worktree_types(tmp_path: Path) -> None:
    """Submodule directories and FIFOs remain unknown, without traversal or blocking."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("pipe", "baseline regular bytes\n")
    parent = repository.commit()
    repository.git_command("update-index", "--add", "--cacheinfo", f"160000,{parent},dependency")
    repository.git_command("commit", "-m", "test: retain dependency commit")
    baseline = repository.git_command("rev-parse", "HEAD").stdout.strip()
    (repository.root / "dependency").mkdir()
    (repository.root / "pipe").unlink()
    os.mkfifo(repository.root / "pipe", 0o600)
    observed = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    old = {row.relative_path: row for row in observed.baseline_files}
    current = {row.relative_path: row for row in observed.current_files}
    assert old["dependency"].kind == "gitlink"
    assert old["dependency"].object_id == parent
    assert old["dependency"].byte_digest is None
    assert current["dependency"].kind == current["pipe"].kind == "unsupported"
    assert current["dependency"].object_id is None
    assert current["pipe"].byte_digest is None


def test_file_inputs_preserve_unmerged_stages_alongside_actual_worktree_bytes(
    tmp_path: Path,
) -> None:
    """All three real index stages survive separately from the unresolved worktree."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("conflict", "baseline\n")
    baseline = repository.commit()
    blob = repository.git_command("rev-parse", "HEAD:conflict").stdout.strip()
    entries = f"0 {'0' * 40}\tconflict\n" + "".join(
        f"100644 {blob} {stage}\tconflict\n" for stage in (1, 2, 3)
    )
    subprocess.run(
        [repository.git, "update-index", "--index-info"],
        cwd=repository.root,
        input=entries.encode(),
        capture_output=True,
        check=True,
    )
    repository.write_text("conflict", "unresolved working bytes\n")
    observed = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    assert observed.git.index.unmerged_paths == ("conflict",)
    assert tuple(
        entry.stage for entry in observed.git.index.entries if entry.relative_path == "conflict"
    ) == (1, 2, 3)
    row = next(row for row in observed.current_files if row.relative_path == "conflict")
    assert row.byte_digest == hashlib.sha256(b"unresolved working bytes\n").hexdigest()
    assert row.object_id != blob


@pytest.mark.parametrize("kind", ("symlink", "file"))
def test_file_inputs_refuse_unsafe_actual_parent_components(tmp_path: Path, kind: str) -> None:
    """A tracked child cannot traverse a replaced parent to an outside directory."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("parent/source", "baseline\n")
    baseline = repository.commit()
    (repository.root / "parent/source").unlink()
    (repository.root / "parent").rmdir()
    if kind == "symlink":
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "source").write_text("outside bytes", encoding="utf-8")
        repository.symlink("parent", str(outside))
    else:
        repository.write_text("parent", "not a directory")
    descriptors = set(Path("/proc/self/fd").iterdir())
    with pytest.raises(RuntimeError, match="cannot inspect repository file path"):
        observe_repository_file_inputs(
            repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
        )
    assert set(Path("/proc/self/fd").iterdir()) == descriptors


@pytest.mark.parametrize(
    "kind",
    (
        "source-count",
        "reference-union",
        "depth",
        "transaction",
        "baseline-file",
        "current-file",
        "link-file",
        "link-total",
    ),
)
def test_file_inputs_enforce_actual_file_and_transaction_budgets(
    tmp_path: Path, kind: str
) -> None:
    """Real inputs refuse at the exhausted path, depth, file or transaction bound."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/source", "baseline\n")
    if kind == "baseline-file":
        repository.write_bytes("large", b"x" * 200)
    baseline = repository.commit()
    arguments: dict[str, int] = {}
    if kind == "source-count":
        arguments["sources"] = 1
    elif kind == "reference-union":
        repository.write_text("new-one", "new\n")
        repository.write_text("new-two", "new\n")
        arguments["references"] = 2
    elif kind == "depth":
        arguments["depth"] = 1
    elif kind == "transaction":
        arguments["total"] = 3
    elif kind in {"baseline-file", "current-file", "link-file"}:
        arguments["source"] = 100
        if kind == "current-file":
            repository.write_bytes("large", b"x" * 200)
        elif kind == "link-file":
            repository.symlink("new-link", "x" * 200)
    else:
        arguments.update(total=8000, source=4000)
        repository.symlink("new-link", "x" * 3500)
    with pytest.raises((ValueError, RuntimeError, StableReadError), match=r"budget|limit"):
        observe_repository_file_inputs(
            repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=_budget(**arguments),
        )


def test_file_inputs_refuse_corrupt_actual_git_blob_storage(tmp_path: Path) -> None:
    """Valid zlib bytes under an incorrect Git object name cannot attest baseline bytes."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("source", "original\n")
    baseline = repository.commit()
    blob = repository.git_command("rev-parse", "HEAD:source").stdout.strip()
    path = repository.root / ".git/objects" / blob[:2] / blob[2:]
    path.chmod(0o600)
    path.write_bytes(zlib.compress(b"blob 8\0changed\n"))
    with pytest.raises(ValueError, match="baseline blob bytes differ"):
        observe_repository_file_inputs(
            repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
        )


def test_file_inputs_refuse_changed_git_state_during_actual_blob_capture(tmp_path: Path) -> None:
    """A fixture-selected delegate mutates the real index, invalidating closing Git state."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("source", "baseline\n")
    baseline = repository.commit()
    tools = tmp_path / "tools"
    tools.mkdir()
    executable = tools / "git"
    marker = tmp_path / "changed"
    executable.write_text(
        "#!/bin/sh\ncase \" $* \" in\n*' cat-file blob '*)\n"
        '/usr/bin/git "$@"\nresult=$?\n'
        f"if [ ! -e {shlex.quote(str(marker))} ]; then\n"
        f"  printf changed > {shlex.quote(str(marker))}\n"
        f"  printf 'changed\\n' > {shlex.quote(str(repository.root / 'source'))}\n"
        f"  /usr/bin/git -C {shlex.quote(str(repository.root))} add source\n"
        'fi\nexit $result;;\n*) exec /usr/bin/git "$@";;\nesac\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    runner = GitRunner(GitTrustPolicy(trusted_roots=(str(tools),)))
    with pytest.raises(ValueError, match="observations changed"):
        observe_repository_file_inputs(
            repository.root, baseline_head=baseline, runner=runner, budget=_budget()
        )
    assert marker.read_text(encoding="utf-8") == "changed"
    assert repository.git_command("status", "--porcelain").stdout.startswith("M ")


def test_file_inputs_refuse_unvalidated_runner_and_budget_before_root_access(
    tmp_path: Path,
) -> None:
    """Malformed explicit inputs do not create a path or select an alternate root."""
    absent = tmp_path / "absent"
    with pytest.raises(ValueError, match="actual Git runner"):
        observe_repository_file_inputs(
            absent,
            baseline_head="1" * 40,
            runner=cast(GitRunner, object()),
            budget=_budget(),
        )
    with pytest.raises(ValueError, match="policy read budget"):
        observe_repository_file_inputs(
            absent,
            baseline_head="1" * 40,
            runner=GitRunner(),
            budget=cast(PolicyReadBudget1, object()),
        )
    assert not absent.exists()


@pytest.mark.parametrize(
    ("phase", "message"),
    (
        ("metadata", "file metadata changed"),
        ("disappearance", "file disappeared"),
        ("byte-disagreement", "observations changed"),
        ("root-object", "directory object changed"),
    ),
)
def test_file_inputs_refuse_real_changes_at_native_read_boundaries(
    tmp_path: Path, phase: str, message: str
) -> None:
    """Real owned-file mutations invalidate the public API without replacing helpers."""
    repository = GitRepository.create(tmp_path / "repository")
    source = repository.write_text("source", "baseline\n")
    baseline = repository.commit()
    repository.write_text("source", "working bytes\n")
    alternate = tmp_path / "alternate"
    if phase == "root-object":
        shutil.copytree(repository.root, alternate, symlinks=True)
    worker = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[4])
from project_registry_syscall_scheduler import arm_native_trace
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_file_inputs import observe_repository_file_inputs
runner=GitRunner()
budget=PolicyReadBudget1.from_dict(json.loads(sys.argv[3]))
arm_native_trace()
try:
    result=observe_repository_file_inputs(Path(sys.argv[1]),baseline_head=sys.argv[2],runner=runner,budget=budget)
except (ValueError,RuntimeError,OSError) as exc:
    print(json.dumps({'accepted':False,'error':str(exc)}))
else:
    print(json.dumps({'accepted':True,'paths':[row.relative_path for row in result.current_files]}))
"""
    root_opens = 0
    finished_read = False
    post_read_samples = 0
    changed = False
    before = source.stat()

    def mutate(stop: SyscallStop) -> bool:
        """Pause at actual owned-child syscalls and mutate only the selected fixture."""
        nonlocal root_opens, finished_read, post_read_samples, changed
        if stop.entering and stop.number == 257 and stop.path == str(repository.root):
            root_opens += 1
            if phase == "root-object" and root_opens == 2:
                repository.root.rename(tmp_path / "retained")
                alternate.rename(repository.root)
                changed = True
        if stop.number == 0 and not stop.entering and stop.path == str(source):
            finished_read |= stop.result == 0
        if stop.entering and stop.number == 262 and stop.path == str(source) and finished_read:
            post_read_samples += 1
            selected = 3 if phase == "byte-disagreement" else 2
            if not changed and phase != "root-object" and post_read_samples == selected:
                if phase == "metadata":
                    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
                elif phase == "disappearance":
                    source.unlink()
                else:
                    source.write_text("different working bytes\n", encoding="utf-8")
                changed = True
        return False

    result = run_traced(
        [
            sys.executable,
            "-B",
            "-c",
            worker,
            str(repository.root),
            baseline,
            json.dumps(_budget().to_dict()),
            str(Path(__file__).parent),
        ],
        mutate,
        timeout=75,
    )
    write_trace(tmp_path / "file-inputs-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert changed, "the actual selected native boundary was not observed"
    outcome = json.loads(result.stdout)
    assert outcome["accepted"] is False
    assert message in outcome["error"]


def test_complete_capture_reports_exact_transaction_cost_for_real_enclosing_composition(
    tmp_path: Path,
) -> None:
    """The reported counter includes both Git snapshots and complete file passes."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_bytes("data", b"actual baseline bytes")
    baseline = repository.commit()
    repository.write_bytes("data", b"actual current bytes")
    observed = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    file_bytes = sum(
        row.byte_count or 0 for row in observed.baseline_files + observed.current_files
    )
    assert observed.source_bytes_read == 2 * observed.git.source_bytes_read + 2 * file_bytes
    assert (
        observe_repository_file_inputs(
            repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=_budget(total=observed.source_bytes_read),
        )
        == observed
    )
    with pytest.raises((ValueError, RuntimeError)):
        observe_repository_file_inputs(
            repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=_budget(total=observed.source_bytes_read - 1),
        )
    for maximum in (-1, True, 257):
        with pytest.raises(ValueError):
            observe_repository_file_inputs(
                repository.root,
                baseline_head=baseline,
                runner=GitRunner(),
                budget=_budget(),
                maximum_paths=maximum,
            )
    with pytest.raises(ValueError, match="path budget"):
        observe_repository_file_inputs(
            repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=_budget(),
            maximum_paths=0,
        )


def test_zero_remaining_path_allowance_accepts_only_an_actual_empty_git_tree(
    tmp_path: Path,
) -> None:
    """A real empty commit and index are retained rather than fabricated by filtering."""
    repository = GitRepository.create(tmp_path / "repository")
    (repository.root / ".gitignore").unlink()
    repository.git_command("commit", "--allow-empty", "-m", "test: actual empty tree")
    baseline = repository.git_command("rev-parse", "HEAD").stdout.strip()
    observed = observe_repository_file_inputs(
        repository.root,
        baseline_head=baseline,
        runner=GitRunner(),
        budget=_budget(),
        maximum_paths=0,
    )
    assert observed.baseline_files == observed.current_files == ()
    assert observed.git.baseline_entries.entries == observed.git.index.entries == ()
    assert observed.source_bytes_read > 0
