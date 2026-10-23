# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete directory observation tests
"""Exercise actual directory bytes, finite traversal and native pathname races."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from test_inventory_domain import domain_budget

from rigor_foundry.directory_file_inputs import observe_directory_file_inputs
from rigor_foundry.policy_read_budget import PolicyReadBudget1


def test_actual_directory_retains_every_leaf_empty_directory_and_link_bytes(
    tmp_path: Path,
) -> None:
    """Real binary, executable, Unicode, hardlink, FIFO and symlink entries survive."""
    root = tmp_path / "directory"
    (root / "nested/empty").mkdir(parents=True)
    (root / "nested/data.bin").write_bytes(b"\x00\xff\x80")
    source = root / "program.py"
    source.write_bytes(b"VALUE = 1\n")
    source.chmod(0o755)
    os.link(source, root / "hardlink")
    (root / "unicode-\u03bb").write_bytes(b"")
    outside = tmp_path / "outside"
    outside.write_bytes(b"must not be read through the link")
    (root / "opaque").symlink_to(outside)
    (root / "directory-link").symlink_to(root / "nested", target_is_directory=True)
    os.mkfifo(root / "fifo")
    observed = observe_directory_file_inputs(root, budget=domain_budget())
    rows = {row.relative_path: row for row in observed.files}
    assert set(rows) == {
        "nested/data.bin",
        "program.py",
        "hardlink",
        "unicode-\u03bb",
        "opaque",
        "directory-link",
        "fifo",
    }
    assert observed.directories == ("nested", "nested/empty")
    assert observed.root == root
    assert (observed.root_device, observed.root_inode) == (root.stat().st_dev, root.stat().st_ino)
    assert rows["nested/data.bin"].byte_digest == hashlib.sha256(b"\x00\xff\x80").hexdigest()
    assert rows["program.py"].mode == "100755"
    assert rows["hardlink"].byte_digest == rows["program.py"].byte_digest
    assert rows["unicode-\u03bb"].byte_count == 0
    assert rows["fifo"].kind == "unsupported"
    for name in ("opaque", "directory-link"):
        payload = os.fsencode(os.readlink(root / name))
        assert rows[name].kind == "symlink"
        assert rows[name].byte_digest == hashlib.sha256(payload).hexdigest()
        assert rows[name].byte_count == len(payload)
    assert all(row.object_id is row.language is row.role is None for row in observed.files)
    assert tuple(rows) == tuple(sorted(rows))


def test_actual_empty_root_is_distinct_from_missing_or_unsafe_root(tmp_path: Path) -> None:
    """Only an existing opened empty directory produces an empty observation."""
    root = tmp_path / "empty"
    root.mkdir()
    result = observe_directory_file_inputs(root, budget=domain_budget())
    assert result.files == () and result.directories == () and result.source_bytes_read == 0
    (tmp_path / "link").symlink_to(root, target_is_directory=True)
    for path in (tmp_path / "missing", tmp_path / "link", tmp_path / "link/child"):
        with pytest.raises(OSError):
            observe_directory_file_inputs(path, budget=domain_budget())
    for path in (Path("relative"), root / ".." / "empty"):
        with pytest.raises(ValueError):
            observe_directory_file_inputs(path, budget=domain_budget())
    with pytest.raises(ValueError, match="policy read budget"):
        observe_directory_file_inputs(root, budget=cast(PolicyReadBudget1, {}))


def test_actual_source_transaction_charges_both_passes_and_all_name_enumerations(
    tmp_path: Path,
) -> None:
    """Exact inclusive total includes file/link payloads and four copies of each name."""
    root = tmp_path / "directory"
    (root / "nested").mkdir(parents=True)
    (root / "nested/data").write_bytes(b"abc")
    (root / "link").symlink_to("nested/data")
    limits = domain_budget()
    result = observe_directory_file_inputs(root, budget=limits)
    names = sum(len(name.encode()) for name in ("nested", "data", "link"))
    expected = 4 * names + 2 * (3 + len(b"nested/data"))
    assert result.source_bytes_read == expected
    assert (
        observe_directory_file_inputs(root, budget=domain_budget(max_total_source_bytes=expected))
        == result
    )
    with pytest.raises((ValueError, RuntimeError), match=r"byte budget|limit-exceeded"):
        observe_directory_file_inputs(
            root, budget=domain_budget(max_total_source_bytes=expected - 1)
        )


@pytest.mark.parametrize(
    ("limits", "message"),
    (
        ({"max_sources": 1}, "entry budget"),
        ({"max_references": 1}, "entry budget"),
        ({"max_depth": 1}, "path depth budget"),
        ({"max_document_bytes": 1}, "document byte budget"),
        ({"max_source_bytes": 1}, "exceeds the read limit"),
        ({"max_total_source_bytes": 1}, "total byte budget"),
    ),
)
def test_actual_traversal_refuses_each_original_ceiling(
    tmp_path: Path, limits: dict[str, int], message: str
) -> None:
    """Real nested bytes cannot be omitted or truncated to meet an input ceiling."""
    root = tmp_path / "directory"
    (root / "nested").mkdir(parents=True)
    (root / "nested/data").write_bytes(b"actual bytes")
    with pytest.raises((ValueError, RuntimeError), match=message):
        observe_directory_file_inputs(root, budget=domain_budget(**limits))


def test_link_source_ceiling_does_not_read_its_target(tmp_path: Path) -> None:
    """Long link bytes refuse even when their target is missing."""
    root = tmp_path / "directory"
    root.mkdir()
    (root / "link").symlink_to("unavailable-target")
    with pytest.raises(ValueError, match="link bytes exceed"):
        observe_directory_file_inputs(root, budget=domain_budget(max_source_bytes=1))


@pytest.mark.parametrize("name", (b".git", b"invalid-\xff"))
def test_unrepresentable_or_git_administration_entry_refuses_without_omission(
    tmp_path: Path, name: bytes
) -> None:
    """Actual unsupported names cannot disappear from a successful complete result."""
    root = tmp_path / "directory"
    root.mkdir()
    descriptor = os.open(os.fsencode(root) + b"/" + name, os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(descriptor)
    with pytest.raises(ValueError, match=r"Git metadata|not UTF-8"):
        observe_directory_file_inputs(root, budget=domain_budget())


@pytest.mark.parametrize(
    ("phase", "message"),
    (
        ("child-before", "child object changed before"),
        ("entry-after", "entry changed during"),
        ("names-after", "listing or object changed"),
        ("metadata-after", "listing or object changed"),
        ("root-path", "root object changed"),
        ("between-passes", "observations changed during"),
    ),
)
def test_actual_native_directory_mutations_refuse_at_their_owning_boundaries(
    tmp_path: Path, phase: str, message: str
) -> None:
    """Owned-child syscall stops mutate real paths without replacing production reads."""
    root = tmp_path / "directory"
    (root / "child").mkdir(parents=True)
    source = root / "data"
    source.write_bytes(b"before")
    alternate = tmp_path / "alternate"
    shutil.copytree(root, alternate)
    changed = False
    root_opens = 0
    source_stats = 0
    directory_reads = 0

    def mutate(stop: SyscallStop) -> bool:
        """Change one fixture only at the selected actual kernel boundary."""
        nonlocal changed, root_opens, source_stats, directory_reads
        if stop.entering and stop.number == 257 and stop.path == str(root):
            root_opens += 1
        if stop.entering and stop.number == 262 and stop.path == str(source):
            source_stats += 1
        if stop.entering and stop.number == 217 and stop.path == str(root):
            directory_reads += 1
        selected = (
            (
                phase == "child-before"
                and stop.entering
                and stop.number == 257
                and stop.path == str(root / "child")
            )
            or (
                phase == "entry-after"
                and stop.entering
                and stop.number == 262
                and stop.path == str(source)
                and source_stats == 4
            )
            or (
                phase in {"names-after", "metadata-after"}
                and stop.entering
                and stop.number == 217
                and stop.path == str(root)
                and directory_reads == 3
            )
            or (
                phase == "root-path"
                and stop.entering
                and stop.number == 257
                and stop.path == str(root)
                and root_opens == 2
            )
            or (
                phase == "between-passes"
                and not stop.entering
                and stop.number == 217
                and stop.path == str(root)
                and directory_reads == 4
            )
        )
        if not changed and selected:
            if phase == "child-before":
                (root / "child").rename(tmp_path / "retained-child")
                (root / "child").mkdir()
            elif phase == "entry-after":
                source.chmod(0o700)
            elif phase == "names-after":
                source.rename(root / "different-name")
            elif phase == "metadata-after":
                root.chmod(0o700)
            elif phase == "root-path":
                root.rename(tmp_path / "retained-root")
                alternate.rename(root)
            else:
                source.write_bytes(b"after!")
            changed = True
        return False

    worker = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
from project_registry_syscall_scheduler import arm_native_trace
from rigor_foundry.directory_file_inputs import observe_directory_file_inputs
from rigor_foundry.policy_read_budget import PolicyReadBudget1
arm_native_trace()
try:
    observe_directory_file_inputs(Path(sys.argv[1]),budget=PolicyReadBudget1.from_dict(json.loads(sys.argv[2])))
except (ValueError,RuntimeError,OSError) as exc:
    outcome={'accepted':False,'error':str(exc)}
else:
    outcome={'accepted':True}
print(json.dumps(outcome))
"""
    result = run_traced(
        [
            sys.executable,
            "-B",
            "-c",
            worker,
            str(root),
            json.dumps(domain_budget().to_dict()),
            str(Path(__file__).parent),
        ],
        mutate,
        timeout=25,
    )
    write_trace(tmp_path / "directory-input-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert changed, "selected real native boundary was not observed"
    outcome = json.loads(result.stdout)
    assert outcome["accepted"] is False
    assert message in outcome["error"]


def test_enclosing_allowances_only_tighten_original_limits_and_preserve_real_empty_roots(
    tmp_path: Path,
) -> None:
    """A zero remaining allowance permits only an actual zero-cost empty capture."""
    root = tmp_path / "directory"
    root.mkdir()
    limits = domain_budget()
    result = observe_directory_file_inputs(
        root, budget=limits, maximum_total_bytes=0, maximum_entries=0
    )
    assert result.files == () and result.directories == () and result.source_bytes_read == 0
    for value in (-1, True, limits.max_total_source_bytes + 1):
        with pytest.raises(ValueError):
            observe_directory_file_inputs(root, budget=limits, maximum_total_bytes=value)
    for value in (-1, True, min(limits.max_sources, limits.max_references) + 1):
        with pytest.raises(ValueError):
            observe_directory_file_inputs(root, budget=limits, maximum_entries=value)
    (root / "actual").write_bytes(b"content")
    with pytest.raises(ValueError, match="entry budget"):
        observe_directory_file_inputs(root, budget=limits, maximum_entries=0)
    with pytest.raises(ValueError, match="total byte budget"):
        observe_directory_file_inputs(root, budget=limits, maximum_total_bytes=0)
