# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — group workspace allocation
"""Exercise workspace allocation against real registry generations and directories."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from rigor_foundry.group_workspace import allocate_group_workspace
from rigor_foundry.project_registry_cutover import (
    ProjectRegistryCutoverInvalid,
)
from rigor_foundry.project_registry_models import (
    ProjectRegistration,
    ProjectRegistry,
    ProjectRegistryAuthority,
    ProjectRegistryConsumer,
    ProjectRegistryGroup,
)
from rigor_foundry.project_registry_views import build_registry_consumer_outputs

REGISTRY_PATH = "agentic-shared/memory/projects/registry/project_registry.json"


def registry(*, lifecycle: str = "active", retired_group: bool = False) -> ProjectRegistry:
    """Build a closed registry for the workspace's concrete allocation domain."""
    group_root = "03_CODE/GROUP-A"
    project_root = f"{group_root}/repositories/PROJECT-A"
    group = ProjectRegistryGroup(
        "GROUP-A",
        group_root,
        f"{group_root}/repositories",
        f"{group_root}/agentic_group_memory/memory_index.md",
        "retired" if retired_group else "active",
    )
    project = ProjectRegistration(
        "PROJECT-A",
        project_root,
        "GROUP-A",
        (),
        "git-repository",
        lifecycle,
        "private",
        "scaffold-only",
        (),
    )
    consumers = [
        ProjectRegistryConsumer(
            "project-index-PROJECT-A",
            "project-index",
            f"{project_root}/agentic_project_memory/registry_binding.json",
            None,
            "PROJECT-A",
        ),
    ]
    if not retired_group:
        consumers.append(
            ProjectRegistryConsumer(
                "group-view-GROUP-A",
                "group-view",
                f"{group_root}/agentic_group_memory/registry_view.json",
                "GROUP-A",
                None,
            )
        )
    return ProjectRegistry.build(
        generated_at="2026-09-04T12:00:00.000000Z",
        previous_registry_sha256=None,
        authority=ProjectRegistryAuthority(
            "Owner",
            "2026-09-04T11:30:00.000000Z",
            "coordination/owner.md",
            "a" * 64,
            "RIGOR-FOUNDRY/validator-1",
            "registry-contract",
        ),
        groups=(group,),
        projects=(project,),
        consumers=tuple(sorted(consumers, key=lambda item: item.consumer_id)),
    )


def workspace_tree(tmp_path: Path, candidate: ProjectRegistry | None = None) -> tuple[Path, str]:
    """Commit real registry consumers and enroll the private group container."""
    candidate = candidate or registry()
    root = tmp_path / "monorepo"
    root.mkdir()
    outputs = {REGISTRY_PATH: candidate.to_bytes()}
    outputs.update(
        {
            item.target_path: item.to_bytes()
            for item in build_registry_consumer_outputs(candidate, {})
        }
    )
    for relative, payload in outputs.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        target.chmod(0o600)
    for item in candidate.groups:
        (root / item.root_path / "agentic_group_workspace").mkdir(mode=0o700)
    return root, candidate.registry_sha256


def allocate(root: Path, digest: str, session: str = "session-1") -> Path:
    """Invoke the public allocator with the fixture's exact registry identity."""
    return allocate_group_workspace(
        root,
        REGISTRY_PATH,
        project_id="PROJECT-A",
        session_id=session,
        expected_registry_sha256=digest,
    )


def test_allocation_preserves_other_sessions_and_refuses_reuse(tmp_path: Path) -> None:
    """New private allocations never overwrite retained sibling content."""
    root, digest = workspace_tree(tmp_path)
    first = allocate(root, digest)
    evidence = first / "scratch/unique.txt"
    evidence.write_text("unique work", encoding="utf-8")
    second = allocate(root, digest, "session-2")
    for directory in (first, second, second / "scratch", second / "tmp"):
        assert directory.is_dir() and not directory.is_symlink()
        assert directory.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        allocate(root, digest)
    assert evidence.read_text() == "unique work"
    assert {p.name for p in second.iterdir()} == {"scratch", "tmp"}


@pytest.mark.parametrize(
    "session",
    ["", ".", "..", "../escape", "/absolute", "a/b", "a\\b", "x" * 129, "with space", "é"],
)
def test_invalid_session_never_creates_project_directory(tmp_path: Path, session: str) -> None:
    """Reject traversal and ambiguous component spelling before any allocation."""
    root, digest = workspace_tree(tmp_path)
    with pytest.raises(ValueError, match="session identifier"):
        allocate(root, digest, session)
    assert not list((root / "03_CODE/GROUP-A/agentic_group_workspace").iterdir())


@pytest.mark.parametrize("digest", ["bad", "0" * 64])
def test_registry_pin_is_mandatory(tmp_path: Path, digest: str) -> None:
    """Malformed and stale registry pins fail before filesystem mutation."""
    root, _ = workspace_tree(tmp_path)
    with pytest.raises(ValueError, match=r"digest|stale"):
        allocate(root, digest)
    assert not list((root / "03_CODE/GROUP-A/agentic_group_workspace").iterdir())


@pytest.mark.parametrize("kind", ["unknown", "paused", "retired-group"])
def test_ineligible_project_or_group_is_refused(tmp_path: Path, kind: str) -> None:
    """Lifecycle and owning group, not directory proximity, determine eligibility."""
    candidate = registry(
        lifecycle="paused" if kind == "paused" else "active",
        retired_group=kind == "retired-group",
    )
    root, digest = workspace_tree(tmp_path, candidate)
    with pytest.raises(ValueError, match=r"eligible|active"):
        allocate_group_workspace(
            root,
            REGISTRY_PATH,
            project_id="UNKNOWN" if kind == "unknown" else "PROJECT-A",
            session_id="session-1",
            expected_registry_sha256=digest,
        )


@pytest.mark.parametrize("level", ["container", "project", "session"])
def test_symlink_redirect_is_never_followed(tmp_path: Path, level: str) -> None:
    """A redirect at any workspace component cannot create content outside scope."""
    root, digest = workspace_tree(tmp_path)
    container = root / "03_CODE/GROUP-A/agentic_group_workspace"
    external = tmp_path / "outside"
    external.mkdir(mode=0o700)
    if level == "container":
        container.rmdir()
        target = container
    elif level == "project":
        target = container / "PROJECT-A"
    else:
        (container / "PROJECT-A").mkdir(mode=0o700)
        target = container / "PROJECT-A/session-1"
    target.symlink_to(external, target_is_directory=True)
    with pytest.raises(OSError):
        allocate(root, digest)
    assert not list(external.iterdir())
    assert target.is_symlink()


@pytest.mark.parametrize("level", ["container", "project"])
def test_permissive_parent_is_not_accepted(tmp_path: Path, level: str) -> None:
    """Preexisting parent permissions are never silently repaired or accepted."""
    root, digest = workspace_tree(tmp_path)
    target = root / "03_CODE/GROUP-A/agentic_group_workspace"
    if level == "project":
        target /= "PROJECT-A"
        target.mkdir(mode=0o700)
    target.chmod(0o755)
    with pytest.raises(ValueError, match="not private"):
        allocate(root, digest)
    assert target.stat().st_mode & 0o777 == 0o755
    assert not list(target.iterdir())


def test_corrupt_consumer_blocks_allocation(tmp_path: Path) -> None:
    """A valid registry JSON alone does not certify its current consumer state."""
    root, digest = workspace_tree(tmp_path)
    consumer = root / registry().consumers[0].path
    consumer.write_bytes(b"{}")
    with pytest.raises(ProjectRegistryCutoverInvalid):
        allocate(root, digest)
    assert not list((root / "03_CODE/GROUP-A/agentic_group_workspace").iterdir())


def test_concurrent_same_session_has_one_winner(tmp_path: Path) -> None:
    """Exclusive session mkdir arbitrates real simultaneous callers without reuse."""
    root, digest = workspace_tree(tmp_path)
    barrier = Barrier(2)

    def attempt() -> bool:
        barrier.wait(timeout=5)
        try:
            allocate(root, digest)
        except FileExistsError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        assert sorted(future.result(timeout=10) for future in futures) == [False, True]
    destination = root / "03_CODE/GROUP-A/agentic_group_workspace/PROJECT-A/session-1"
    assert {path.name for path in destination.iterdir()} == {"scratch", "tmp"}


@pytest.mark.parametrize("change", ["path", "permissions", "child-permissions", "registry"])
def test_filesystem_interleaving_preserves_partial_allocation(tmp_path: Path, change: str) -> None:
    """Real audit-event interleaving changes state before the final mkdir.

    The hook runs only in the child and changes real files, not allocator
    helpers or syscall return values. This is a deterministic interleaving
    regression, not proof of exclusion against arbitrary concurrent writers.
    """
    import subprocess
    import sys

    root, digest = workspace_tree(tmp_path)
    script = """
import sys
from pathlib import Path
from rigor_foundry.group_workspace import allocate_group_workspace
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.project_registry_views import build_registry_consumer_outputs
root, digest, change, registry_path = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
destination = root / "03_CODE/GROUP-A/agentic_group_workspace/PROJECT-A/session-1"
old = ProjectRegistry.from_bytes((root / registry_path).read_bytes())
new = ProjectRegistry.build(
    generated_at="2026-09-04T12:01:00.000000Z",
    previous_registry_sha256=old.registry_sha256, authority=old.authority,
    groups=old.groups, projects=old.projects, consumers=old.consumers,
)
def interfere(event, arguments):
    if event != "os.mkdir" or arguments[0] != "tmp":
        return
    if change == "path":
        destination.rename(destination.with_name("retained"))
        destination.mkdir(mode=0o700)
    elif change == "permissions":
        destination.chmod(0o755)
    elif change == "child-permissions":
        (destination / "scratch").chmod(0o755)
    else:
        for output in build_registry_consumer_outputs(new, {}):
            (root / output.target_path).write_bytes(output.to_bytes())
        (root / registry_path).write_bytes(new.to_bytes())
sys.addaudithook(interfere)
try:
    allocate_group_workspace(root, registry_path, project_id="PROJECT-A",
        session_id="session-1", expected_registry_sha256=digest)
except (ValueError, RuntimeError) as error:
    print(str(error))
    raise SystemExit(1)
raise SystemExit("unexpected acceptance")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(root), digest, change, REGISTRY_PATH],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert {
        "path": "workspace path changed during allocation",
        "permissions": "workspace allocation is not private",
        "child-permissions": "workspace allocation is not private",
        "registry": "workspace registry changed during allocation",
    }[change] in result.stdout
    destination = root / "03_CODE/GROUP-A/agentic_group_workspace/PROJECT-A/session-1"
    retained = destination.with_name("retained") if change == "path" else destination
    assert (retained / "scratch").is_dir()
    assert (retained / "tmp").is_dir()
