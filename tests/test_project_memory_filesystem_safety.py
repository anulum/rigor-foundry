# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory store tests
"""Exercise real filesystem interference and interrupted memory-store operations."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from project_memory_store_support import manifest, record, repository

from rigor_foundry.project_memory_store import (
    ProjectMemoryStoreInvalid,
    commit_project_memory_generation,
    load_project_memory_generation,
    verify_project_memory_history,
    write_project_memory_record,
)


@pytest.mark.parametrize("surface", ["manifest", "index", "content", "history"])
@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_fifo_replacement_refuses_without_waiting_for_a_writer(
    tmp_path: Path, surface: str, entrypoint: str
) -> None:
    """A substituted FIFO must not stall the public reader or integrity command."""
    root = repository(tmp_path)
    payload = b"# Project identity\n"
    item = record("identity-fifo-check", payload)
    content = write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history = commit_project_memory_generation(root, candidate)
    memory = root / "agentic_project_memory"
    target = {
        "manifest": memory / "memory_manifest.json",
        "index": memory / "memory_index.md",
        "content": content,
        "history": history,
    }[surface]
    preserved = {
        path: path.read_bytes() for path in memory.rglob("*") if path.is_file() and path != target
    }
    target.unlink()
    os.mkfifo(target, mode=0o600)
    before = target.lstat()
    if entrypoint == "api":
        arguments = [
            "-c",
            "from pathlib import Path; import sys\n"
            "from rigor_foundry.project_memory_store import "
            "ProjectMemoryStoreInvalid, load_project_memory_generation\n"
            "try:\n"
            "    load_project_memory_generation(Path(sys.argv[1]))\n"
            "except ProjectMemoryStoreInvalid:\n"
            "    print('refused'); sys.exit(1)\n"
            "raise SystemExit('unexpected acceptance')\n",
            str(root),
        ]
        expected = b"refused\n"
    else:
        arguments = ["-m", "tools.check_project_memory_integrity", str(root), "--history"]
        expected = b"project-memory-integrity: FAIL\n"
    result = subprocess.run(
        [sys.executable, *arguments],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == expected
    assert result.stderr == b""
    after = target.lstat()
    assert stat.S_ISFIFO(after.st_mode)
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_mtime_ns,
    )
    assert {path: path.read_bytes() for path in preserved} == preserved


@pytest.mark.parametrize(
    "change", ["growth", "unlink", "replace", "permissions", "hardlink", "late-permissions"]
)
def test_current_read_rejects_file_change_after_descriptor_snapshot(
    tmp_path: Path, change: str
) -> None:
    """Change a real manifest after fstat returns, without faking syscall results.

    A child-local profiling hook schedules a deterministic filesystem mutation
    at the public OS boundary. The full public loader still runs normally.
    This proves the observed interleaving, not exclusion of arbitrary writers.
    """
    root = repository(tmp_path)
    payload = b"# Project identity\n"
    item = record("identity-stable-read", payload)
    write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    commit_project_memory_generation(root, candidate)
    script = """
import os
import sys
from pathlib import Path
from rigor_foundry.project_memory_store import (
    ProjectMemoryStoreInvalid, load_project_memory_generation,
)
root, change = Path(sys.argv[1]), sys.argv[2]
target = root / "agentic_project_memory/memory_manifest.json"
original = target.read_bytes()
changed = False
snapshots = 0
def interfere(frame, event, function):
    global changed, snapshots
    if changed or event != "c_return" or function is not os.fstat:
        return
    for name in os.listdir("/proc/self/fd"):
        try:
            linked = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        if linked == str(target):
            break
    else:
        return
    snapshots += 1
    if change == "late-permissions" and snapshots < 2:
        return
    changed = True
    if change == "growth":
        with target.open("ab") as output:
            output.write(b" " * 65537)
    elif change == "unlink":
        target.unlink()
    elif change == "replace":
        replacement = target.with_name("replacement.json")
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        replacement.replace(target)
    elif change in ("permissions", "late-permissions"):
        target.chmod(0o644)
    else:
        os.link(target, target.with_name("retained-link.json"))
sys.setprofile(interfere)
try:
    load_project_memory_generation(root)
except ProjectMemoryStoreInvalid as error:
    sys.setprofile(None)
    assert changed
    print(str(error))
    raise SystemExit(1)
sys.setprofile(None)
raise SystemExit("unexpected acceptance")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(root), change],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert {
        "growth": "exceeds its byte bound",
        "unlink": "changed while being read",
        "replace": "changed while being read",
        "permissions": "changed while being read",
        "hardlink": "changed while being read",
        "late-permissions": "changed while being read",
    }[change] in result.stdout
    assert (root / "agentic_project_memory" / item.content_path).read_bytes() == payload


@pytest.mark.parametrize("blocked_view", ["memory_index.md", "memory_manifest.json"])
def test_interrupted_generation_retains_history_and_retries_exactly(
    tmp_path: Path, blocked_view: str
) -> None:
    """An obstructed replacement preserves evidence and permits exact retry."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-retry", payload)
    write_project_memory_record(root, item, payload)
    first = manifest("2026-09-04T12:01:00.000000Z", (item,))
    first_history = commit_project_memory_generation(root, first)
    candidate = manifest("2026-09-04T12:02:00.000000Z", (item,), first.manifest_sha256)
    private = root / "agentic_project_memory"
    candidate_file = tmp_path / "candidate.json"
    candidate_file.write_bytes(candidate.to_bytes())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from pathlib import Path
from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_store import (
    ProjectMemoryStoreInvalid, commit_project_memory_generation,
)
root, candidate_file, view = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
candidate = ProjectMemoryManifest.from_bytes(candidate_file.read_bytes())
target = root / 'agentic_project_memory' / view
changed = False
def obstruct(event, arguments):
    global changed
    if event == 'os.rename' and str(arguments[1]) == str(target) and not changed:
        changed = True
        target.rename(target.with_name(view + '.retained'))
        target.mkdir(mode=0o700)
sys.addaudithook(obstruct)
try:
    commit_project_memory_generation(root, candidate)
except ProjectMemoryStoreInvalid as error:
    assert changed
    print(error)
    raise SystemExit(1)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(candidate_file),
            blocked_view,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert "cannot replace the derived current generation" in result.stdout
    history = (
        private
        / "history/manifests"
        / (f"{candidate.generation_id}_{candidate.manifest_sha256}.json")
    )
    assert history.read_bytes() == candidate.to_bytes()
    assert first_history.read_bytes() == first.to_bytes()
    with pytest.raises(ProjectMemoryStoreInvalid):
        load_project_memory_generation(root)
    target = private / blocked_view
    target.rmdir()
    target.with_name(blocked_view + ".retained").rename(target)
    assert commit_project_memory_generation(root, candidate) == history
    assert load_project_memory_generation(root) == candidate
    assert verify_project_memory_history(root) == (
        candidate.manifest_sha256,
        first.manifest_sha256,
    )
    assert not list(private.glob(".*.tmp"))


@pytest.mark.parametrize("change", ["enumeration", "missing-current", "duplicate-digest"])
def test_history_directory_changes_are_refused(tmp_path: Path, change: str) -> None:
    """Real directory changes after current-view validation cannot certify history."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-enumeration", payload)
    write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history_file = commit_project_memory_generation(root, candidate)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from pathlib import Path
from rigor_foundry.project_memory_store import ProjectMemoryStoreInvalid, verify_project_memory_history
root, history_file, change = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
directory = history_file.parent
changed = False
def interfere(event, arguments):
    global changed
    if event != 'os.scandir' or str(arguments[0]) != str(directory) or changed:
        return
    changed = True
    if change == 'enumeration':
        directory.rename(directory.with_name('retained-manifests'))
    elif change == 'missing-current':
        history_file.rename(directory.parent / 'retained-current.json')
    else:
        duplicate = directory / ('20260904T120200000000Z_' + history_file.name.split('_', 1)[1])
        duplicate.write_bytes(history_file.read_bytes())
        duplicate.chmod(0o600)
sys.addaudithook(interfere)
try:
    verify_project_memory_history(root)
except ProjectMemoryStoreInvalid as error:
    assert changed
    print(error)
    raise SystemExit(1)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(history_file),
            change,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    expected = {
        "enumeration": "history cannot be enumerated",
        "missing-current": "predecessor is missing from history",
        "duplicate-digest": "history digest is ambiguous",
    }
    if change == "duplicate-digest":
        # Filesystem enumeration order determines which equivalent refusal comes first.
        assert any(
            message in result.stdout
            for message in (
                "history digest is ambiguous",
                "history filename does not match its manifest",
            )
        )
    else:
        assert expected[change] in result.stdout
    assert (root / "agentic_project_memory" / item.content_path).read_bytes() == payload


def test_repository_alias_change_cannot_redirect_record_write(tmp_path: Path) -> None:
    """Changing a caller's repository alias cannot move an admitted record write."""
    root = repository(tmp_path)
    other = repository(tmp_path / "other")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    payload = b"# Identity\n"
    item = record("identity-alias", payload)
    metadata = tmp_path / "record.json"
    metadata.write_text(json.dumps(item.to_dict()), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json, sys
from pathlib import Path
from rigor_foundry.project_memory_models import ProjectMemoryRecord
from rigor_foundry.project_memory_store import ProjectMemoryStoreInvalid, write_project_memory_record
root, other, alias, metadata = map(Path, sys.argv[1:])
item = ProjectMemoryRecord.from_dict(json.loads(metadata.read_text()), 'record')
target = root / 'agentic_project_memory/records/identity'
changed = False
def interfere(event, arguments):
    global changed
    if event == 'os.mkdir' and str(arguments[0]) == str(target) and not changed:
        changed = True
        alias.unlink()
        alias.symlink_to(other, target_is_directory=True)
sys.addaudithook(interfere)
try:
    write_project_memory_record(alias, item, b'# Identity\\n')
except ProjectMemoryStoreInvalid as error:
    assert changed
    print(error)
    raise SystemExit(1)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(other),
            str(alias),
            str(metadata),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert "content path changed during resolution" in result.stdout
    assert not (root / "agentic_project_memory" / item.content_path).exists()
    assert not (other / "agentic_project_memory" / item.content_path).exists()


@pytest.mark.parametrize("change", ["history-create", "round-trip"])
def test_commit_detects_concurrent_history_or_current_writer(tmp_path: Path, change: str) -> None:
    """An out-of-protocol writer cannot silently replace the committed result."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-concurrent", payload)
    write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    other = manifest("2026-09-04T12:02:00.000000Z", (item,), candidate.manifest_sha256)
    candidate_file, other_file = tmp_path / "candidate.json", tmp_path / "other.json"
    candidate_file.write_bytes(candidate.to_bytes())
    other_file.write_bytes(other.to_bytes())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from pathlib import Path
from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_store import ProjectMemoryStoreInvalid, commit_project_memory_generation
root, candidate_file, other_file = map(Path, sys.argv[1:4])
change = sys.argv[4]
candidate = ProjectMemoryManifest.from_bytes(candidate_file.read_bytes())
other = ProjectMemoryManifest.from_bytes(other_file.read_bytes())
private = root / 'agentic_project_memory'
history = private / 'history/manifests'
target = history / (candidate.generation_id + '_' + candidate.manifest_sha256 + '.json')
changed = False
replacements = 0
def interfere(event, arguments):
    global changed
    if change != 'history-create' or changed or event != 'open':
        return
    if str(arguments[0]) == str(target) and arguments[2] & os.O_EXCL:
        changed = True
        target.write_bytes(candidate.to_bytes())
        target.chmod(0o600)
def after_replace(frame, event, function):
    global replacements, changed
    if change != 'round-trip' or changed or event != 'c_return' or function is not os.replace:
        return
    replacements += 1
    if replacements != 2:
        return
    changed = True
    other_history = history / (other.generation_id + '_' + other.manifest_sha256 + '.json')
    other_history.write_bytes(other.to_bytes())
    other_history.chmod(0o600)
    (private / 'memory_manifest.json').write_bytes(other.to_bytes())
    (private / 'memory_index.md').write_text(other.index_text())
sys.addaudithook(interfere)
sys.setprofile(after_replace)
try:
    commit_project_memory_generation(root, candidate)
except ProjectMemoryStoreInvalid as error:
    sys.setprofile(None)
    assert changed
    print(error)
    raise SystemExit(1)
sys.setprofile(None)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(candidate_file),
            str(other_file),
            change,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert {
        "history-create": "cannot retain immutable history manifest",
        "round-trip": "committed generation did not round-trip exactly",
    }[change] in result.stdout
    if change == "history-create":
        retained = commit_project_memory_generation(root, candidate)
        assert retained.read_bytes() == candidate.to_bytes()
    else:
        assert load_project_memory_generation(root) == other
        assert verify_project_memory_history(root) == (
            other.manifest_sha256,
            candidate.manifest_sha256,
        )
