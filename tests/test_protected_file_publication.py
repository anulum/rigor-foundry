# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact publication planning tests
"""Exercise public operation expansion, complete content and refusal paths."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import cast

import pytest
from test_project_memory_activation_plan import proposal

from rigor_foundry.project_memory_activation_content import (
    prepare_project_memory_activation_content,
)
from rigor_foundry.protected_file_publication import (
    PreparedProtectedFilePublication,
    ProtectedDirectoryCreation,
    ProtectedFileLock,
    ProtectedFilePublication,
    prepare_protected_file_publication,
    prepare_protected_snapshot_publication,
)


def snapshot_plan(
    targets: tuple[ProtectedFilePublication, ...],
    snapshots: dict[tuple[str, str], ProtectedFilePublication],
    *,
    operations: int = 100,
    content_bytes: int = 4096,
    directories: tuple[ProtectedDirectoryCreation, ...] = (),
    locks: tuple[ProtectedFileLock, ...] = (),
) -> PreparedProtectedFilePublication:
    """Call the preserving public boundary with explicit test-only limits."""
    return prepare_protected_snapshot_publication(
        targets,
        snapshots=snapshots,
        claim_task_id="test-task",
        content_domain="raw-file-bytes",
        max_operations=operations,
        max_content_bytes=content_bytes,
        directories=directories,
        locks=locks,
    )


def lock(previous: bytes | None = b"lock identity\n") -> ProtectedFileLock:
    """Declare one test-only exact lock; no live authority is enrolled."""
    return ProtectedFileLock("root", "memory/.generation.lock", "root", "memory", "0700", previous)


@pytest.mark.parametrize("previous", [b"existing\n", b"", None])
def test_lock_creation_binding_and_reverse_release(previous: bytes | None) -> None:
    """Compile absent/existing lock setup and reverse release without implicit lock rewrites."""
    first = lock(previous)
    second = replace(lock(b"second"), relative_path="memory/.second.lock")
    result = snapshot_plan((file(),), {}, locks=(first, second))
    body = json.loads(result.operation_fields)
    operations = body["auxiliary_operations"]
    setup = ["create", "fsync", "fsync"] if previous is None else []
    assert [operation["opcode"] for operation in operations] == [
        *setup,
        "lock",
        "lock",
        "create",
        "fsync",
        "fsync",
        "unlock",
        "unlock",
    ]
    assert [o["paths"][0]["relative_path"] for o in operations if o["opcode"] == "lock"] == [
        first.relative_path,
        second.relative_path,
    ]
    assert [o["paths"][0]["relative_path"] for o in operations if o["opcode"] == "unlock"] == [
        second.relative_path,
        first.relative_path,
    ]
    acquired = next(o for o in operations if o["opcode"] == "lock")
    assert acquired["paths"][0]["before"] == acquired["paths"][0]["after"]
    assert acquired["paths"][0]["before"]["sha256"] == hashlib.sha256(previous or b"").hexdigest()
    ids = [o["operation_id"] for o in body["operations"] + operations]
    assert len(ids) == len(set(ids))
    assert len(body["operations"]) == (2 if previous is None else 1)
    assert not any(o["opcode"] in ("write", "unlink", "rename") for o in operations)
    if previous is None:
        assert dict(result.contents)[hashlib.sha256(b"").hexdigest()] == b""
        assert operations[0]["operation_id"].startswith("lock-setup-")


def test_all_locks_are_held_before_any_original_snapshot_is_created() -> None:
    """Order acquisition before all preservation creates and release after durability steps."""
    original = file(b"original")
    result = snapshot_plan(
        (original,), {("root", "memory/index"): snapshot(b"original")}, locks=(lock(),)
    )
    operations = json.loads(result.operation_fields)["auxiliary_operations"]
    assert operations[0]["opcode"] == "lock"
    assert operations[1]["opcode"] == "create"
    assert operations[1]["paths"][0]["root_id"] == "transaction"
    assert operations[-1]["opcode"] == "unlock"
    assert operations[-2]["opcode"] == "fsync"


def test_new_lock_can_use_an_explicitly_new_directory_but_existing_lock_cannot() -> None:
    """Permit absent lock creation under planned parents but reject existing-child contradictions."""
    declared = replace(
        lock(None), relative_path="memory/new/.lock", parent_relative_path="memory/new"
    )
    result = snapshot_plan((file(),), {}, directories=(directory(),), locks=(declared,))
    operations = json.loads(result.operation_fields)["auxiliary_operations"]
    assert [o["opcode"] for o in operations[:6]] == [
        "mkdir",
        "fsync",
        "create",
        "fsync",
        "fsync",
        "lock",
    ]
    with pytest.raises(ValueError, match="precondition contradicts"):
        snapshot_plan(
            (file(),), {}, directories=(directory(),), locks=(replace(declared, previous=b"old"),)
        )


@pytest.mark.parametrize("declarations", [[], [lock()], (object(),)])
def test_lock_declarations_are_immutable_and_exact(declarations: object) -> None:
    """Reject mutable sequences and foreign objects at the lock declaration boundary."""
    with pytest.raises(ValueError, match="immutable exact tuple"):
        snapshot_plan((file(),), {}, locks=cast(tuple[ProtectedFileLock, ...], declarations))


def test_lock_count_and_effects_use_actual_shared_budgets() -> None:
    """Charge lock setup, acquisition, release and retained content to shared budgets."""
    with pytest.raises(ValueError, match="lock count"):
        snapshot_plan((file(),), {}, operations=4, locks=(lock(), lock(), lock()))
    assert snapshot_plan((file(),), {}, operations=6, locks=(lock(b""),))
    with pytest.raises(ValueError, match="lock effects"):
        snapshot_plan((file(),), {}, operations=5, locks=(lock(b""),))
    assert snapshot_plan((file(),), {}, operations=10, locks=(lock(None),))
    with pytest.raises(ValueError, match="lock effects"):
        snapshot_plan((file(),), {}, operations=9, locks=(lock(None),))
    total = len(file().candidate) + len(lock().previous or b"")
    assert snapshot_plan((file(),), {}, content_bytes=total, locks=(lock(),))
    with pytest.raises(ValueError, match="expanded"):
        snapshot_plan((file(),), {}, content_bytes=total - 1, locks=(lock(),))


@pytest.mark.parametrize("path", ["memory/index", "memory"])
def test_lock_cannot_alias_business_file_or_parent(path: str) -> None:
    """Reject lock destinations that collide with business files or declared parent directories."""
    declaration = replace(lock(), relative_path=path)
    if path == "memory":
        declaration = replace(
            declaration, parent_root_id="external", parent_relative_path="container"
        )
    with pytest.raises(ValueError, match=r"collision|aliases"):
        snapshot_plan((file(),), {}, locks=(declaration,))


def test_lock_cannot_alias_snapshot_or_replacement_temporary() -> None:
    """Reject acquisition paths overlapping snapshots, replacement temporaries or other locks."""
    original = file(b"old")
    copies = {("root", "memory/index"): snapshot(b"old")}
    for declaration in (
        replace(lock(), relative_path="memory/.exact.tmp"),
        ProtectedFileLock("transaction", "prior/original", "transaction", "prior", "0700", b"old"),
    ):
        with pytest.raises(ValueError, match="collision"):
            snapshot_plan((original,), copies, locks=(declaration,))
    with pytest.raises(ValueError, match="collision"):
        snapshot_plan((file(),), {}, locks=(lock(), lock()))


def test_mutable_existing_lock_content_is_refused() -> None:
    """Reject mutable prior lock bytes before operation expansion."""
    with pytest.raises(ValueError, match="immutable file bytes"):
        snapshot_plan((file(),), {}, locks=(lock(cast(bytes, bytearray(b"old"))),))


def directory() -> ProtectedDirectoryCreation:
    """Declare one exact new parent, not a recursive filesystem operation."""
    return ProtectedDirectoryCreation("root", "memory/new", "root", "memory", "0700")


def new_child() -> ProtectedFilePublication:
    """Declare a new file under the explicitly created directory."""
    return replace(file(), relative_path="memory/new/index", parent_relative_path="memory/new")


def test_new_directory_has_explicit_creation_and_parent_durability_before_files() -> None:
    """Require explicit mkdir and parent fsync before child publication within the exact budget."""
    result = snapshot_plan((new_child(),), {}, directories=(directory(),), operations=6)
    body = json.loads(result.operation_fields)
    operations = body["auxiliary_operations"]
    assert [operation["opcode"] for operation in operations] == [
        "mkdir",
        "fsync",
        "create",
        "fsync",
        "fsync",
    ]
    assert operations[0]["paths"] == [
        {
            "root_id": "root",
            "relative_path": "memory/new",
            "before": {"kind": "absent"},
            "after": {"kind": "directory", "mode": "0700"},
        }
    ]
    assert operations[1]["paths"][0]["relative_path"] == "memory"
    assert operations[-1]["paths"][0]["relative_path"] == "memory/new"
    assert len({o["operation_id"] for o in body["operations"] + operations}) == 6
    with pytest.raises(ValueError, match="directory effects"):
        snapshot_plan((new_child(),), {}, directories=(directory(),), operations=5)


def test_nested_directory_order_is_explicit_and_no_recursive_mkdir_is_inferred() -> None:
    """Respect parent-before-child creation order without synthesizing recursive mkdir."""
    nested = ProtectedDirectoryCreation("root", "memory/new/nested", "root", "memory/new", "0700")
    child = replace(
        new_child(),
        relative_path="memory/new/nested/index",
        parent_relative_path="memory/new/nested",
    )
    result = snapshot_plan((child,), {}, directories=(directory(), nested))
    operations = json.loads(result.operation_fields)["auxiliary_operations"]
    assert [o["paths"][0]["relative_path"] for o in operations[:4]] == [
        "memory/new",
        "memory",
        "memory/new/nested",
        "memory/new",
    ]
    with pytest.raises(ValueError, match="precede children"):
        snapshot_plan((child,), {}, directories=(nested, directory()))
    with pytest.raises(ValueError, match="precede children"):
        snapshot_plan((child,), {}, directories=(directory(), replace(nested, parent_mode="0755")))


def test_directory_at_enrolled_root_level_has_explicit_cross_root_parent() -> None:
    """Preserve separately named cross-root parent durability for root-level directories."""
    declaration = ProtectedDirectoryCreation("root", "new", "enrolled-parent", "container", "0755")
    child = replace(new_child(), relative_path="new/index", parent_relative_path="new")
    result = snapshot_plan((child,), {}, directories=(declaration,))
    assert (
        json.loads(result.operation_fields)["auxiliary_operations"][1]["paths"][0]["root_id"]
        == "enrolled-parent"
    )


@pytest.mark.parametrize("declarations", [[], [directory()], (object(),)])
def test_directory_input_is_immutable_and_exact(declarations: object) -> None:
    """Reject mutable or incorrectly typed directory declaration collections."""
    with pytest.raises(ValueError, match="immutable exact tuple"):
        snapshot_plan(
            (new_child(),),
            {},
            directories=cast(tuple[ProtectedDirectoryCreation, ...], declarations),
        )


def test_directory_duplicates_and_unrelated_creations_are_refused() -> None:
    """Reject duplicate mkdir targets and directories unrelated to any planned effect."""
    with pytest.raises(ValueError, match="duplicate directory"):
        snapshot_plan((new_child(),), {}, directories=(directory(), directory()))
    with pytest.raises(ValueError, match="unrelated"):
        snapshot_plan((file(),), {}, directories=(directory(),))


def test_directory_cannot_occupy_a_file_destination() -> None:
    """Refuse a directory creation whose path is also a declared file destination."""
    occupied = replace(file(), relative_path="memory/new")
    with pytest.raises(ValueError, match="aliases"):
        snapshot_plan((occupied, new_child()), {}, directories=(directory(),))


def test_directory_parent_must_be_immediate_and_have_one_mode() -> None:
    """Reject non-immediate directory parents and inconsistent mode declarations."""
    with pytest.raises(ValueError, match="not immediate"):
        snapshot_plan(
            (new_child(),),
            {},
            directories=(replace(directory(), parent_relative_path="elsewhere"),),
        )
    with pytest.raises(ValueError, match="parent modes contradict"):
        snapshot_plan(
            (file(), new_child()), {}, directories=(replace(directory(), parent_mode="0755"),)
        )


def test_existing_file_cannot_claim_a_new_parent() -> None:
    """Reject existing child preconditions or unsafe modes beneath an absent parent."""
    child = replace(new_child(), previous=b"old", temporary_path="memory/new/.exact.tmp")
    with pytest.raises(ValueError, match="precondition contradicts"):
        snapshot_plan(
            (child,),
            {(child.root_id, child.relative_path): snapshot(b"old")},
            directories=(directory(),),
        )
    with pytest.raises(ValueError, match="precondition contradicts"):
        snapshot_plan((replace(new_child(), parent_mode="0755"),), {}, directories=(directory(),))


def test_directory_fields_are_checked_before_use_as_mapping_keys() -> None:
    """Validate root identifier types before using directory declarations as hash keys."""
    with pytest.raises(ValueError, match="identifier"):
        snapshot_plan(
            (new_child(),), {}, directories=(replace(directory(), root_id=cast(str, [])),)
        )


def snapshot(content: bytes, path: str = "prior/original") -> ProtectedFilePublication:
    """Declare a private original-byte snapshot, without creating a directory."""
    return ProtectedFilePublication(
        "transaction", path, "transaction", "prior", "0700", None, content
    )


def test_all_exact_snapshots_precede_every_business_write() -> None:
    """Snapshot every exact predecessor before business writes regardless of mapping order."""
    first = file(b"bootstrap bytes\n")
    last = replace(
        file(b""), relative_path="memory/registry", temporary_path="memory/.registry.tmp"
    )
    created = replace(file(), relative_path="memory/record")
    copies = {
        (last.root_id, last.relative_path): snapshot(b"", "prior/registry"),
        (first.root_id, first.relative_path): snapshot(b"bootstrap bytes\n"),
    }
    result = snapshot_plan((first, created, last), copies)
    body = json.loads(result.operation_fields)
    assert [entry["relative_path"] for entry in body["operations"]] == [
        "prior/original",
        "prior/registry",
        "memory/index",
        "memory/record",
        "memory/registry",
    ]
    operations = body["auxiliary_operations"]
    assert [operation["opcode"] for operation in operations[:6]] == [
        "create",
        "fsync",
        "fsync",
        "create",
        "fsync",
        "fsync",
    ]
    assert (
        operations[0]["content_reference"]["sha256"]
        == hashlib.sha256(b"bootstrap bytes\n").hexdigest()
    )
    assert operations[3]["content_reference"]["sha256"] == hashlib.sha256(b"").hexdigest()
    assert all(operation["paths"][0]["root_id"] == "transaction" for operation in operations[:6])
    assert operations[6]["paths"][0]["root_id"] == "root"
    assert operations[-2]["paths"][1]["relative_path"] == last.relative_path
    copies.clear()
    assert (
        result.operation_fields == json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    )


def test_create_only_preservation_has_no_spurious_snapshot() -> None:
    """Do not invent preservation snapshots for exclusive-create-only publications."""
    assert snapshot_plan((file(),), {}) == prepare(file())


@pytest.mark.parametrize(
    "copies",
    [
        {},
        {("root", "foreign"): snapshot(b"old")},
        {
            ("root", "memory/index"): snapshot(b"old"),
            ("root", "extra"): snapshot(b"old", "prior/extra"),
        },
    ],
)
def test_missing_extra_or_wrong_snapshot_target_is_refused(
    copies: dict[tuple[str, str], ProtectedFilePublication],
) -> None:
    """Require precisely the replacement target set in preservation mappings."""
    with pytest.raises(ValueError, match="snapshot"):
        snapshot_plan((file(b"old"),), copies)


@pytest.mark.parametrize(
    "copy",
    [
        snapshot(b"wrong"),
        replace(snapshot(b"old"), previous=b"existing"),
        replace(snapshot(b"old"), temporary_path="prior/.temp"),
        replace(snapshot(b"old"), candidate=cast(bytes, bytearray(b"old"))),
        cast(ProtectedFilePublication, object()),
    ],
)
def test_snapshot_is_exclusive_exact_and_immutable(copy: ProtectedFilePublication) -> None:
    """Require immutable exact original bytes at exclusive-create snapshot destinations."""
    with pytest.raises(ValueError, match="exclusively create exact"):
        snapshot_plan((file(b"old"),), {("root", "memory/index"): copy})


def test_snapshot_cannot_alias_original_or_another_temporary() -> None:
    """Reject preservation paths colliding with original targets or replacement temporaries."""
    for path in ("memory/index", "memory/.exact.tmp"):
        with pytest.raises(ValueError, match="collision"):
            snapshot_plan(
                (file(b"old"),),
                {("root", "memory/index"): replace(file(), relative_path=path, candidate=b"old")},
            )


def test_snapshot_costs_are_included_in_combined_budgets() -> None:
    """Include preserved predecessor copies in combined operation and byte budgets."""
    target = file(b"old")
    copies = {("root", "memory/index"): snapshot(b"old")}
    total = len(target.candidate) + 2 * len(b"old")
    assert snapshot_plan((target,), copies, operations=9, content_bytes=total)
    with pytest.raises(ValueError, match="expanded"):
        snapshot_plan((target,), copies, operations=8, content_bytes=total)
    with pytest.raises(ValueError, match="expanded"):
        snapshot_plan((target,), copies, operations=9, content_bytes=total - 1)


def test_validated_activation_content_preserves_bootstrap_consumers_and_registry() -> None:
    """Compose validated activation content with raw bootstrap and registry preservation."""
    p = proposal()
    content = prepare_project_memory_activation_content(
        p.previous.to_bytes(),
        {o.consumer_id: o.to_bytes() for o in p.prior_outputs},
        p.cutover,
        p.memory,
        bootstrap_manifest=p.bootstrap,
        bootstrap_index=p.index,
        record_contents={p.memory.records[0].content_path: b"# Project identity\n"},
        max_content_bytes=1024 * 1024,
    )
    consumer_paths = {
        consumer.consumer_id: consumer.path for consumer in p.cutover.candidate.consumers
    }
    targets = []
    copies = {}
    for index, item in enumerate(content.objects):
        if item.role == "registry":
            path = "ecosystem/registry.json"
        elif item.role == "consumer":
            path = "ecosystem/" + consumer_paths[item.identity]
        else:
            path = "memory/" + item.identity
        target = ProtectedFilePublication(
            "enrolled",
            path,
            "enrolled",
            path.rpartition("/")[0],
            "0700",
            item.previous,
            item.candidate,
            path + ".exact.tmp" if item.previous is not None else None,
        )
        targets.append(target)
        if item.previous is not None:
            copies[(target.root_id, target.relative_path)] = snapshot(
                item.previous, f"prior/{index:04d}.raw"
            )
    result = snapshot_plan(tuple(targets), copies, operations=200, content_bytes=1024 * 1024)
    body = json.loads(result.operation_fields)
    primaries = body["operations"]
    assert len(primaries) == len(content.objects) + len(copies)
    assert all(item["root_id"] == "transaction" for item in primaries[: len(copies)])
    assert primaries[-1]["relative_path"] == "ecosystem/registry.json"
    raw_contents = dict(result.contents)
    for original in (
        p.bootstrap,
        p.index,
        p.previous.to_bytes(),
        *(o.to_bytes() for o in p.prior_outputs),
    ):
        assert raw_contents[hashlib.sha256(original).hexdigest()] == original
    snapshot_steps = body["auxiliary_operations"][: len(copies) * 3]
    assert [step["opcode"] for step in snapshot_steps] == ["create", "fsync", "fsync"] * len(
        copies
    )
    assert all(step["paths"][0]["root_id"] == "transaction" for step in snapshot_steps)
    assert body["auxiliary_operations"][len(copies) * 3]["paths"][0]["root_id"] == "enrolled"


def file(previous: bytes | None = None) -> ProtectedFilePublication:
    """Return an exact private file and a separately named parent."""
    return ProtectedFilePublication(
        "root",
        "memory/index",
        "root",
        "memory",
        "0700",
        previous,
        b"candidate\n",
        "memory/.exact.tmp" if previous is not None else None,
    )


def prepare(
    *files: ProtectedFilePublication, operations: int = 100, content_bytes: int = 4096
) -> PreparedProtectedFilePublication:
    """Compile with explicit test budgets, not production enrollment."""
    return prepare_protected_file_publication(
        tuple(files),
        claim_task_id="test-task",
        content_domain="raw-file-bytes",
        max_operations=operations,
        max_content_bytes=content_bytes,
    )


@pytest.mark.parametrize("previous", [None, b"old\n", b""])
def test_exact_complete_success_chain(previous: bytes | None) -> None:
    """Compile exact create/replace transitions and durability order, including empty files."""
    target = file(previous)
    result = prepare(target)
    body = json.loads(result.operation_fields)
    (primary,) = body["operations"]
    ops = body["auxiliary_operations"]
    assert primary["action"] == ("create" if previous is None else "replace")
    assert primary["relative_path"] == target.relative_path
    assert [o["opcode"] for o in ops] == (
        ["create", "fsync", "fsync"]
        if previous is None
        else ["create", "fsync", "rename", "fsync"]
    )
    assert ops[0]["paths"][0]["relative_path"] == (target.temporary_path or target.relative_path)
    assert ops[0]["paths"][0]["before"] == {"kind": "absent"}
    assert ops[-1]["paths"][0] == {
        "root_id": "root",
        "relative_path": "memory",
        "before": {"kind": "directory", "mode": "0700"},
        "after": {"kind": "directory", "mode": "0700"},
    }
    digest = hashlib.sha256(target.candidate).hexdigest()
    assert result.contents == ((digest, target.candidate),)
    assert ops[0]["content_reference"] == {
        "domain": "raw-file-bytes",
        "handle": digest,
        "sha256": digest,
        "size_bytes": len(target.candidate),
    }
    if previous is not None:
        rename = ops[2]["paths"]
        assert rename[0]["after"] == {"kind": "absent"}
        assert rename[1]["before"]["sha256"] == hashlib.sha256(previous).hexdigest()
        assert rename[1]["after"] == rename[0]["before"] == ops[1]["paths"][0]["after"]
    assert (
        prepare(
            target,
            operations=len(ops) + 1,
            content_bytes=len(target.candidate) + len(previous or b""),
        )
        == result
    )


def test_order_and_deduplication() -> None:
    """Preserve target order while deduplicating equal payloads and keeping operation IDs unique."""
    second = replace(
        file(b"registry"),
        relative_path="registry/current",
        parent_relative_path="registry",
        temporary_path="registry/.exact.tmp",
    )
    result = prepare(file(), second)
    body = json.loads(result.operation_fields)
    assert [o["relative_path"] for o in body["operations"]] == ["memory/index", "registry/current"]
    assert len(result.contents) == 1
    ids = [o["operation_id"] for o in body["operations"] + body["auxiliary_operations"]]
    assert len(ids) == len(set(ids))


def test_cross_root_parent_and_zero_bytes() -> None:
    """Represent empty file contents and separately enrolled parent roots explicitly."""
    target = replace(
        file(), relative_path="index", parent_root_id="parent", parent_mode="0755", candidate=b""
    )
    result = prepare(target)
    assert (
        json.loads(result.operation_fields)["auxiliary_operations"][-1]["paths"][0]["root_id"]
        == "parent"
    )
    assert result.contents == ((hashlib.sha256(b"").hexdigest(), b""),)


@pytest.mark.parametrize("budget", [False, 0, -1, 1.5, 2**53])
@pytest.mark.parametrize("side", ["operations", "bytes"])
def test_budget_types(budget: object, side: str) -> None:
    """Reject invalid operation and byte capacities before compilation."""
    with pytest.raises(ValueError, match="positive exact"):
        prepare(
            file(),
            operations=cast(int, budget) if side == "operations" else 100,
            content_bytes=cast(int, budget) if side == "bytes" else 4096,
        )


def test_empty_and_underbudget_refusal() -> None:
    """Reject empty plans and budgets smaller than their complete expanded representation."""
    with pytest.raises(ValueError, match="file count"):
        prepare()
    with pytest.raises(ValueError, match="file count"):
        prepare(file(), operations=3)
    with pytest.raises(ValueError, match="expanded"):
        prepare(file(b"old"), operations=4)
    with pytest.raises(ValueError, match="expanded"):
        prepare(file(), content_bytes=1)


@pytest.mark.parametrize("declarations", [[], [file()], (object(),)])
def test_input_declarations_cannot_change_between_validation_and_expansion(
    declarations: object,
) -> None:
    """Reject mutable or foreign file declarations before deriving the operation sequence."""
    with pytest.raises(ValueError, match="immutable tuple"):
        prepare_protected_file_publication(
            cast(tuple[ProtectedFilePublication, ...], declarations),
            claim_task_id="test-task",
            content_domain="raw-file-bytes",
            max_operations=100,
            max_content_bytes=4096,
        )


def test_invalid_unicode_path_is_refused_before_serialization() -> None:
    """Reject surrogate code points before attempting canonical JSON encoding."""
    with pytest.raises(ValueError, match="exact and relative"):
        prepare(replace(file(), relative_path="memory/\ud800"))


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute",
        "../escape",
        "a//b",
        "a/./b",
        "a\\b",
        "a*",
        "a?",
        "a[0]",
        "a\x00",
        "a\x7f",
        "a" * 4097,
    ],
)
def test_ambiguous_paths_refused(path: str) -> None:
    """Reject absolute, traversal, glob, control-character and oversized path spellings."""
    with pytest.raises(ValueError, match="exact and relative"):
        prepare(replace(file(), relative_path=path))


@pytest.mark.parametrize("identity", ["", "*", "a" * 257])
def test_invalid_root_identifiers(identity: str) -> None:
    """Reject malformed root identities rather than serializing ambiguous references."""
    with pytest.raises(ValueError, match="identifier"):
        prepare(replace(file(), root_id=identity))


@pytest.mark.parametrize("mode", ["0777", "0770", "0702", "0600", "700", "bad"])
def test_unsafe_parent_modes(mode: str) -> None:
    """Reject malformed parent modes, missing owner access and shared write permission."""
    with pytest.raises(ValueError, match="parent requires"):
        prepare(replace(file(), parent_mode=mode))


def test_contradictory_parent_modes() -> None:
    """Refuse inconsistent observations for the same immediate parent."""
    with pytest.raises(ValueError, match="contradictory"):
        prepare(file(), replace(file(), relative_path="memory/second", parent_mode="0755"))


def test_non_immediate_parent() -> None:
    """Reject a claimed textual parent that is not the file's immediate ancestor."""
    with pytest.raises(ValueError, match="immediate"):
        prepare(replace(file(), parent_relative_path="other"))


@pytest.mark.parametrize("prior", [False, True])
def test_mutable_bytes(prior: bool) -> None:
    """Reject mutable prior or candidate buffers at the publication boundary."""
    mutable = cast(bytes, bytearray(b"foreign"))
    target = (
        replace(file(b"old"), previous=mutable) if prior else replace(file(), candidate=mutable)
    )
    with pytest.raises(ValueError, match="immutable"):
        prepare(target)


def test_creation_cannot_smuggle_temporary() -> None:
    """Prevent exclusive-create declarations from adding unused temporary destinations."""
    with pytest.raises(ValueError, match="exclusive creation"):
        prepare(replace(file(), temporary_path="memory/.stray"))


@pytest.mark.parametrize("temporary", [None, "other/temp", "memory/index"])
def test_replacement_requires_distinct_same_directory_temporary(temporary: str | None) -> None:
    """Require replacement temporaries to be distinct and in the destination directory."""
    with pytest.raises(ValueError):
        prepare(replace(file(b"old"), temporary_path=temporary))


def test_all_destination_collisions() -> None:
    """Reject repeated targets and cross-file temporary collisions."""
    with pytest.raises(ValueError, match="collision"):
        prepare(file(), file())
    with pytest.raises(ValueError, match="collision"):
        prepare(file(b"old"), replace(file(), relative_path="memory/.exact.tmp"))


def test_file_cannot_alias_parent() -> None:
    """Reject file destinations that are also needed as directory parents."""
    with pytest.raises(ValueError, match="aliases"):
        prepare(
            file(),
            replace(
                file(),
                relative_path="memory",
                parent_root_id="parent",
                parent_relative_path="container",
            ),
        )
