# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual Git repository input tests
"""Exercise baseline, staged, unmerged and nonignored inputs from real Git roots."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_git_inputs import (
    observe_repository_git_inputs,
    parse_git_baseline_entries,
    parse_git_untracked_paths,
)


def _budget(
    *, document: int = 65536, total: int = 1048576, references: int = 256
) -> PolicyReadBudget1:
    """Supply explicit bounds for the actual repository plumbing transaction."""
    return PolicyReadBudget1.build(
        max_document_bytes=document,
        max_source_bytes=65536,
        max_total_source_bytes=total,
        max_sources=16,
        max_rules=16,
        max_references=references,
        max_depth=8,
    )


@pytest.mark.parametrize("object_format", ("sha1", "sha256"))
def test_repository_inputs_keep_baseline_staged_unstaged_and_untracked_paths(
    tmp_path: Path, object_format: str
) -> None:
    """Deleted and renamed baseline entries remain alongside current and untracked paths."""
    repository = GitRepository.create(tmp_path / "repository", object_format=object_format)
    repository.write_text("src/before.py", "VALUE = 1\n")
    repository.write_text("src/modified.py", "VALUE = 2\n")
    baseline = repository.commit()
    repository.git_command("mv", "src/before.py", "src/after.py")
    repository.write_text("src/modified.py", "VALUE = 3\n")
    repository.write_text("src/new.py", "VALUE = 4\n")
    repository.write_text("docs/internal/retained.md", "private ignored material\n")
    runner = GitRunner()
    observed = observe_repository_git_inputs(
        repository.root, baseline_head=baseline, runner=runner, budget=_budget()
    )
    assert observed.baseline_head == observed.head == baseline
    assert observed.head_tree == observed.baseline_tree
    assert observed.object_format == object_format
    assert {entry.relative_path for entry in observed.baseline_entries.entries} == {
        ".gitignore",
        "src/before.py",
        "src/modified.py",
    }
    assert {entry.relative_path for entry in observed.index.entries} == {
        ".gitignore",
        "src/after.py",
        "src/modified.py",
    }
    assert observed.untracked_paths == ("src/new.py",)
    assert b"src/before.py\0" in observed.status_bytes
    assert b"src/after.py\0" in observed.status_bytes
    assert b"src/modified.py\0" in observed.status_bytes
    assert observed.index.unmerged_paths == ()
    assert observed.git_provenance == runner.provenance
    assert repository.git_command("rev-parse", "HEAD").stdout.strip() == baseline


@pytest.mark.parametrize("object_format", ("sha1", "sha256"))
def test_repository_inputs_distinguish_earlier_baseline_head_index_and_worktree(
    tmp_path: Path, object_format: str
) -> None:
    """A later commit and two uncommitted versions retain their distinct identities."""
    repository = GitRepository.create(tmp_path / "repository", object_format=object_format)
    repository.write_text("source.py", "VALUE = 1\n")
    baseline = repository.commit()
    baseline_blob = repository.git_command("rev-parse", "HEAD:source.py").stdout.strip()
    repository.write_text("source.py", "VALUE = 2\n")
    head = repository.commit()
    head_blob = repository.git_command("rev-parse", "HEAD:source.py").stdout.strip()
    repository.write_text("source.py", "VALUE = 3\n")
    repository.git_command("add", "source.py")
    staged_blob = repository.git_command("rev-parse", ":source.py").stdout.strip()
    repository.write_text("source.py", "VALUE = 4\n")
    repository.write_text("src/nový.py", "VALUE = 5\n")

    observed = observe_repository_git_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )

    assert observed.baseline_head == baseline
    assert observed.head == head != baseline
    assert (
        observed.baseline_tree
        == repository.git_command("rev-parse", baseline + "^{tree}").stdout.strip()
    )
    assert observed.head_tree == repository.git_command("rev-parse", "HEAD^{tree}").stdout.strip()
    assert observed.baseline_tree != observed.head_tree
    before = next(
        entry for entry in observed.baseline_entries.entries if entry.relative_path == "source.py"
    )
    staged = next(entry for entry in observed.index.entries if entry.relative_path == "source.py")
    assert before.object_id == baseline_blob
    assert staged.object_id == staged_blob
    assert len({baseline_blob, head_blob, staged_blob}) == 3
    assert observed.untracked_paths == ("src/nový.py",)
    assert b"MM source.py\0" in observed.status_bytes
    assert "?? src/nový.py\0".encode() in observed.status_bytes
    assert (repository.root / "source.py").read_text(encoding="utf-8") == "VALUE = 4\n"
    assert repository.git_command("rev-parse", "HEAD").stdout.strip() == head
    assert repository.git_command("rev-parse", ":source.py").stdout.strip() == staged_blob


def test_repository_inputs_retain_all_real_unmerged_index_stages(tmp_path: Path) -> None:
    """Actual stages one, two and three survive observation instead of being discarded."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("conflict.txt", "baseline\n")
    baseline = repository.commit()
    blob = repository.git_command("rev-parse", "HEAD:conflict.txt").stdout.strip()
    rows = f"0 {'0' * 40}\tconflict.txt\n" + "".join(
        f"100644 {blob} {stage}\tconflict.txt\n" for stage in (1, 2, 3)
    )
    subprocess.run(
        [repository.git, "update-index", "--index-info"],
        cwd=repository.root,
        input=rows.encode(),
        check=True,
        capture_output=True,
    )
    observed = observe_repository_git_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    entries = tuple(
        entry for entry in observed.index.entries if entry.relative_path == "conflict.txt"
    )
    assert tuple(entry.stage for entry in entries) == (1, 2, 3)
    assert observed.index.unmerged_paths == ("conflict.txt",)


def test_repository_inputs_keep_actual_symlink_and_gitlink_modes(tmp_path: Path) -> None:
    """Baseline and index modes retain links without traversing their targets."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("target.txt", "source\n")
    repository.symlink("source-link", "target.txt")
    parent = repository.commit()
    repository.git_command("update-index", "--add", "--cacheinfo", f"160000,{parent},dependency")
    repository.git_command("commit", "-m", "test: retain Git dependency entry")
    baseline = repository.git_command("rev-parse", "HEAD").stdout.strip()
    observed = observe_repository_git_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
    )
    modes = {entry.relative_path: entry.mode for entry in observed.baseline_entries.entries}
    assert modes["source-link"] == "120000"
    assert modes["dependency"] == "160000"


def test_repository_inputs_refuse_subdirectory_and_symlink_roots(tmp_path: Path) -> None:
    """A containing repository or alias cannot silently replace the selected exact root."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/source.py", "VALUE = 1\n")
    baseline = repository.commit()
    with pytest.raises(ValueError, match="actual Git worktree root"):
        observe_repository_git_inputs(
            repository.root / "src", baseline_head=baseline, runner=GitRunner(), budget=_budget()
        )
    alias = tmp_path / "alias"
    alias.symlink_to(repository.root, target_is_directory=True)
    with pytest.raises(OSError):
        observe_repository_git_inputs(
            alias, baseline_head=baseline, runner=GitRunner(), budget=_budget()
        )


def test_repository_inputs_refuse_missing_baseline_and_unborn_head(tmp_path: Path) -> None:
    """A missing commit never becomes an empty baseline or an invented HEAD."""
    repository = GitRepository.create(tmp_path / "repository")
    with pytest.raises(RuntimeError, match="exit status"):
        observe_repository_git_inputs(
            repository.root, baseline_head="1" * 40, runner=GitRunner(), budget=_budget()
        )


def test_repository_inputs_enforce_actual_output_and_total_budgets(tmp_path: Path) -> None:
    """Actual plumbing output is refused under insufficient document or transaction bounds."""
    repository = GitRepository.create(tmp_path / "repository")
    baseline = repository.commit()
    runner = GitRunner()
    with pytest.raises(RuntimeError, match="exceeded output limit"):
        observe_repository_git_inputs(
            repository.root, baseline_head=baseline, runner=runner, budget=_budget(document=1)
        )
    with pytest.raises(ValueError, match="total byte budget"):
        observe_repository_git_inputs(
            repository.root, baseline_head=baseline, runner=runner, budget=_budget(total=1)
        )


def test_repository_inputs_refuse_reference_exhaustion_without_dropping_paths(
    tmp_path: Path,
) -> None:
    """A complete baseline exceeding its row allowance is refused instead of filtered."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/source.py", "VALUE = 1\n")
    baseline = repository.commit()
    with pytest.raises(ValueError, match="reference budget"):
        observe_repository_git_inputs(
            repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=_budget(references=1),
        )


def test_repository_inputs_refuse_non_utf8_untracked_paths(tmp_path: Path) -> None:
    """Actual nonportable path bytes cannot silently disappear from the observed scope."""
    repository = GitRepository.create(tmp_path / "repository")
    baseline = repository.commit()
    name = os.fsencode(repository.root) + b"/untracked-\xff"
    descriptor = os.open(name, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    os.close(descriptor)
    with pytest.raises(UnicodeDecodeError):
        observe_repository_git_inputs(
            repository.root, baseline_head=baseline, runner=GitRunner(), budget=_budget()
        )


def test_repository_inputs_close_root_descriptor_after_failed_observations(tmp_path: Path) -> None:
    """Repeated real missing-baseline failures release each retained directory handle."""
    repository = GitRepository.create(tmp_path / "repository")
    runner = GitRunner()
    before = {item.name for item in Path("/proc/self/fd").iterdir()}
    for _ in range(3):
        with pytest.raises(RuntimeError, match="exit status"):
            observe_repository_git_inputs(
                repository.root, baseline_head="1" * 40, runner=runner, budget=_budget()
            )
    after = {item.name for item in Path("/proc/self/fd").iterdir()}
    assert after == before


def test_baseline_format_parser_consumes_actual_git_output_and_refuses_corruption(
    tmp_path: Path,
) -> None:
    """Retained baseline-format bytes are checked independently of process invocation."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("source.py", "VALUE = 1\n")
    baseline = repository.commit()
    payload = repository.git_command(
        "ls-tree", "-r", "-z", "--full-tree", baseline
    ).stdout.encode()
    result = parse_git_baseline_entries(payload, budget=_budget())
    assert tuple(entry.relative_path for entry in result.entries) == (".gitignore", "source.py")
    assert parse_git_baseline_entries(b"", budget=_budget()).entries == ()
    for malformed in (
        payload[:-1],
        payload.replace(b"\t", b" "),
        payload.replace(b" blob ", b" tree "),
        payload + payload,
    ):
        with pytest.raises(ValueError):
            parse_git_baseline_entries(malformed, budget=_budget())
    with pytest.raises(ValueError, match="document budget"):
        parse_git_baseline_entries(payload, budget=_budget(document=1))
    with pytest.raises(ValueError, match="reference budget"):
        parse_git_baseline_entries(payload, budget=_budget(references=1))
    with pytest.raises(ValueError, match="policy read budget"):
        parse_git_baseline_entries(payload, budget=cast(PolicyReadBudget1, None))


def test_untracked_format_parser_consumes_actual_git_output_and_refuses_corruption(
    tmp_path: Path,
) -> None:
    """No retained untracked-format row is truncated, deduplicated or omitted silently."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    repository.write_text("new.py", "VALUE = 1\n")
    repository.write_text("second.py", "VALUE = 2\n")
    payload = repository.git_command(
        "ls-files", "--others", "--exclude-standard", "-z"
    ).stdout.encode()
    assert parse_git_untracked_paths(payload, budget=_budget()) == ("new.py", "second.py")
    assert parse_git_untracked_paths(b"", budget=_budget()) == ()
    for malformed in (payload[:-1], payload + payload):
        with pytest.raises(ValueError):
            parse_git_untracked_paths(malformed, budget=_budget())
    with pytest.raises(ValueError, match="document budget"):
        parse_git_untracked_paths(payload, budget=_budget(document=1))
    with pytest.raises(ValueError, match="reference budget"):
        parse_git_untracked_paths(payload, budget=_budget(references=1))
    with pytest.raises(ValueError, match="policy read budget"):
        parse_git_untracked_paths(payload, budget=cast(PolicyReadBudget1, None))


def test_repository_inputs_refuse_relative_roots_and_noncommit_baselines(tmp_path: Path) -> None:
    """A relative root and a tag object's identity cannot substitute for exact inputs."""
    repository = GitRepository.create(tmp_path / "repository")
    baseline = repository.commit()
    runner = GitRunner()
    with pytest.raises(ValueError, match="absolute path"):
        observe_repository_git_inputs(
            Path("."), baseline_head=baseline, runner=runner, budget=_budget()
        )
    repository.git_command("tag", "-a", "fixture-baseline", "-m", "fixture baseline")
    tag = repository.git_command("rev-parse", "refs/tags/fixture-baseline").stdout.strip()
    with pytest.raises(ValueError, match="exact commit object"):
        observe_repository_git_inputs(
            repository.root, baseline_head=tag, runner=runner, budget=_budget()
        )
    with pytest.raises(ValueError, match="actual Git runner"):
        observe_repository_git_inputs(
            repository.root, baseline_head=baseline, runner=cast(GitRunner, None), budget=_budget()
        )


@pytest.mark.parametrize("change", ("untracked", "root-object", "object-format"))
def test_repository_inputs_refuse_actual_changes_at_git_process_boundaries(
    tmp_path: Path, change: str
) -> None:
    """A fixture executable delegates real Git and changes owned state at read boundaries.

    This controls actual source observations and directory objects, rather than
    replacing Python helpers. The fixture executable is not host admission proof.
    """
    repository = GitRepository.create(tmp_path / "repository")
    baseline = repository.commit()
    tools = tmp_path / "tools"
    tools.mkdir()
    executable = tools / "git"
    marker = tmp_path / "first-status"
    retained = tmp_path / "retained-repository"
    if change == "untracked":
        mutation = "printf changed > " + shlex.quote(str(repository.root / "new.py")) + "\n"
    else:
        mutation = (
            "if [ -e " + shlex.quote(str(marker)) + " ]; then\n"
            "  /usr/bin/mv "
            + shlex.quote(str(repository.root))
            + " "
            + shlex.quote(str(retained))
            + "\n"
            "  /usr/bin/mkdir " + shlex.quote(str(repository.root)) + "\n"
            "else\n  printf seen > " + shlex.quote(str(marker)) + "\nfi\n"
        )
    preamble = (
        'case " $* " in *" --show-object-format "*) printf "sha512\\n"; exit 0;; esac\n'
        if change == "object-format"
        else ""
    )
    executable.write_text(
        "#!/bin/sh\n"
        + preamble
        + '/usr/bin/git "$@"\nresult=$?\n'
        + 'case " $* " in *" status "*)\n'
        + mutation
        + ';; esac\nexit "$result"\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    runner = GitRunner(GitTrustPolicy(trusted_roots=(str(tools),)))
    expected = {
        "untracked": "observations changed",
        "root-object": "directory object changed",
        "object-format": "inconsistent formats",
    }
    with pytest.raises(ValueError, match=expected[change]):
        observe_repository_git_inputs(
            repository.root, baseline_head=baseline, runner=runner, budget=_budget()
        )
    if change == "root-object":
        assert (retained / ".git/HEAD").is_file()
