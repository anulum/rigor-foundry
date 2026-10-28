# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete retained baseline record tests
"""Exercise baseline source serialization, topology, exact identities and budgets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from test_inventory_domain import domain, domain_budget
from test_project_registry_models import registry

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.inventory_baseline import InventoryBaseline1, InventoryBaselineRoot
from rigor_foundry.inventory_domain import InventoryDomainRoot
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_inventory_rows import RepositoryFileRow
from rigor_foundry.typed_object_reference import TypedObjectRef1


class BaselineArguments(TypedDict):
    """Exact typed public builder inputs before a deliberately invalid mutation."""

    baseline_id: str
    project_id: str
    domain_reference: TypedObjectRef1
    registry_reference: TypedObjectRef1
    roots: tuple[InventoryBaselineRoot, ...]


def baseline() -> InventoryBaseline1:
    """Build a complete protocol example; runtime tests capture real Git commits."""
    declared, registered = domain(), registry()
    payload = b"VALUE = 1\n"
    blob = hashlib.sha1(b"blob 10\0" + payload, usedforsecurity=False).hexdigest()
    rows = (
        RepositoryFileRow(
            "src/module.py",
            "regular",
            "100644",
            blob,
            hashlib.sha256(payload).hexdigest(),
            len(payload),
            "python",
            "source",
        ),
    )
    private = replace(rows[0], relative_path="scripts/tool.py", object_id=None, role="tool")
    return InventoryBaseline1.build(
        baseline_id="before-change",
        project_id="PROJECT-A",
        domain_reference=TypedObjectRef1.from_dict(declared.reference()),
        registry_reference=TypedObjectRef1.build(
            kind="project-registry",
            format_version="gotm-project-registry.v1",
            object_id=registered.generation_id,
            object_digest=registered.registry_sha256,
        ),
        roots=(
            InventoryBaselineRoot(declared.roots[0], "1" * 40, rows, ()),
            InventoryBaselineRoot(declared.roots[1], None, (private,), ("empty", "scripts")),
        ),
        budget=domain_budget(),
    )


def rehashed(data: dict[str, object]) -> dict[str, object]:
    """Change data without confusing valid hashing with baseline semantics."""
    body = dict(data)
    body.pop("baseline_digest")
    return {**body, "baseline_digest": canonical_digest(body)}


def test_complete_baseline_survives_actual_retained_source_round_trip(tmp_path: Path) -> None:
    """The fixed owning parser preserves every original row and empty directory."""
    before = baseline()
    payload = json.dumps(before.to_dict()).encode()
    path = tmp_path / "baseline.json"
    path.write_bytes(payload)
    reference = TypedObjectRef1.from_dict(before.reference())
    with RetainedContextSource(
        path,
        reference=reference,
        raw_digest=hashlib.sha256(payload).hexdigest(),
        budget=domain_budget(),
    ) as retained:
        assert retained.read() == before
        assert retained.reference == reference
    assert before.roots[0].files[0].object_id is not None
    assert before.roots[1].directories == ("empty", "scripts")
    assert before.roots[1].files[0].object_id is None
    body = before.to_dict()
    assert body.pop("baseline_digest") == canonical_digest(body)
    assert not {"installed", "complete", "authority", "generator_proof"}.intersection(body)


@pytest.mark.parametrize("kind", ("ignored", "generated"))
def test_directory_baseline_retains_unknown_and_unsupported_preimages(kind: str) -> None:
    """Neither unknown labels nor unsupported leaves acquire invented Git identities."""
    root = InventoryDomainRoot("data", "projects/application/data", kind)
    unsupported = RepositoryFileRow("channel", "unsupported", None, None, None, None, None, None)
    row = replace(baseline().roots[1].files[0], language=None, role=None)
    value = InventoryBaselineRoot(root, None, (unsupported, row), ("scripts",))
    assert InventoryBaselineRoot.from_dict(value.to_dict(), budget=domain_budget()) == value
    assert value.files[0].kind == "unsupported"
    assert value.files[1].language is None and value.files[1].role is None


@pytest.mark.parametrize(
    "fault",
    (
        "root-type",
        "files-type",
        "directories-type",
        "row-type",
        "hard-rows",
        "file-order",
        "directory-order",
        "same-file-directory",
        "file-parent",
        "directory-parent",
        "git-directories",
        "git-missing-object",
        "git-deleted",
        "git-format",
        "directory-head",
        "directory-git-object",
        "directory-gitlink",
        "unsupported-mode",
        "unsupported-bytes",
    ),
)
def test_root_direct_construction_refuses_contradictory_before_images(fault: str) -> None:
    """Public construction rejects topology loss and fabricated history relations."""
    git, private = baseline().roots
    changes: dict[str, object] = {}
    value = private
    if fault == "root-type":
        changes["root"] = {}
    elif fault == "files-type":
        changes["files"] = []
    elif fault == "directories-type":
        changes["directories"] = []
    elif fault == "row-type":
        changes["files"] = ({},)
    elif fault == "hard-rows":
        changes["files"] = (private.files[0],) * 65537
    elif fault == "file-order":
        changes["files"] = (private.files[0], private.files[0])
    elif fault == "directory-order":
        changes["directories"] = ("scripts", "empty")
    elif fault == "same-file-directory":
        changes["directories"] = ("scripts", "scripts/tool.py")
    elif fault == "file-parent":
        changes["files"] = (
            replace(private.files[0], relative_path="scripts"),
            private.files[0],
        )
    elif fault == "directory-parent":
        changes["directories"] = ("scripts/missing",)
    elif fault == "git-directories":
        value, changes = git, {"directories": ("src",)}
    elif fault == "git-missing-object":
        value, changes = git, {"files": (replace(git.files[0], object_id=None),)}
    elif fault == "git-deleted":
        value, changes = (
            git,
            {"files": (RepositoryFileRow("gone", "deleted", None, None, None, None, None, None),)},
        )
    elif fault == "git-format":
        value, changes = git, {"files": (replace(git.files[0], object_id="1" * 64),)}
    elif fault == "directory-head":
        changes["git_head"] = "1" * 40
    elif fault == "directory-git-object":
        changes["files"] = (replace(private.files[0], object_id="1" * 40),)
    elif fault == "directory-gitlink":
        changes["files"] = (
            RepositoryFileRow("child", "gitlink", "160000", "1" * 40, None, None, None, None),
        )
    elif fault == "unsupported-mode":
        changes["files"] = (
            RepositoryFileRow("channel", "unsupported", "100644", None, None, None, None, None),
        )
    else:
        changes["files"] = (
            RepositoryFileRow("channel", "unsupported", None, None, "1" * 64, 0, None, None),
        )
    with pytest.raises(ValueError):
        InventoryBaselineRoot(
            cast(InventoryDomainRoot, changes.get("root", value.root)),
            cast(str | None, changes.get("git_head", value.git_head)),
            cast(tuple[RepositoryFileRow, ...], changes.get("files", value.files)),
            cast(tuple[str, ...], changes.get("directories", value.directories)),
        )


def test_root_parser_enforces_closed_fields_and_explicit_budgets() -> None:
    """Array types and reference ceilings are checked before retaining preimages."""
    value = baseline().roots[1].to_dict()
    for invalid in (
        {**value, "extra": True},
        {**value, "files": {}},
        {**value, "directories": None},
    ):
        with pytest.raises(ValueError):
            InventoryBaselineRoot.from_dict(invalid, budget=domain_budget())
    with pytest.raises(ValueError, match="reference budget"):
        InventoryBaselineRoot.from_dict(value, budget=domain_budget(max_references=1))
    with pytest.raises(ValueError, match="budget is required"):
        InventoryBaselineRoot.from_dict(value, budget=cast(PolicyReadBudget1, {}))
    empty = replace(baseline().roots[1], files=(), directories=())
    assert InventoryBaselineRoot.from_dict(empty.to_dict(), budget=domain_budget()) == empty


def test_topology_uses_path_components_and_retains_a_deep_git_path() -> None:
    """Punctuation cannot hide a file parent; long names do not require ancestor expansion."""
    git = baseline().roots[0]
    original = git.files[0]
    with pytest.raises(ValueError, match="topology conflicts"):
        replace(
            git,
            files=tuple(
                replace(original, relative_path=path) for path in ("a", "a.z", "a/child.py")
            ),
        )
    path = "/".join((*("d" for _ in range(512)), "source.py"))
    deep = replace(git, files=(replace(original, relative_path=path),))
    parsed = InventoryBaselineRoot.from_dict(deep.to_dict(), budget=domain_budget())
    assert parsed.files[0].relative_path == path
    assert parsed.files[0].byte_digest == original.byte_digest


@pytest.mark.parametrize(
    "fault",
    (
        "extra",
        "version",
        "kind",
        "digest",
        "empty",
        "root-type",
        "duplicate",
        "path",
        "domain-kind",
        "registry-kind",
        "project",
    ),
)
def test_complete_baseline_refuses_rehashed_semantic_or_header_changes(fault: str) -> None:
    """A recalculated hash cannot bless unsupported headers or ambiguous roots."""
    data = baseline().to_dict()
    roots = cast(list[dict[str, object]], data["roots"])
    if fault == "extra":
        data["complete"] = True
    elif fault == "version":
        data["schema_version"] = "2.0"
    elif fault == "kind":
        data["object_kind"] = "other"
    elif fault == "digest":
        data["baseline_digest"] = "0" * 64
    elif fault == "empty":
        data["roots"] = []
    elif fault == "root-type":
        data["roots"] = {}
    elif fault == "duplicate":
        data["roots"] = [roots[0], roots[0]]
    elif fault == "path":
        descriptor = cast(dict[str, object], roots[1]["root"])
        roots[1]["root"] = {**descriptor, "canonical_path": domain().roots[0].canonical_path}
    elif fault == "domain-kind":
        data["domain_reference"] = data["registry_reference"]
    elif fault == "registry-kind":
        data["registry_reference"] = data["domain_reference"]
    else:
        data["project_id"] = "bad identity"
    with pytest.raises(ValueError):
        InventoryBaseline1.from_dict(
            data if fault == "digest" else rehashed(data), budget=domain_budget()
        )


def test_baseline_build_parse_and_direct_instance_resource_boundaries() -> None:
    """Direct and decoded entrypoints enforce aggregate bounds without truncation."""
    value = baseline()
    args: BaselineArguments = {
        "baseline_id": value.baseline_id,
        "project_id": value.project_id,
        "domain_reference": value.domain_reference,
        "registry_reference": value.registry_reference,
        "roots": value.roots,
    }
    for limits in (domain_budget(max_sources=1), domain_budget(max_references=3)):
        with pytest.raises(ValueError):
            InventoryBaseline1.build(**args, budget=limits)
        with pytest.raises(ValueError):
            InventoryBaseline1.from_dict(value.to_dict(), budget=limits)
    for field in ("files", "directories"):
        data = value.to_dict()
        cast(list[dict[str, object]], data["roots"])[0][field] = None
        with pytest.raises(ValueError, match="must be arrays"):
            InventoryBaseline1.from_dict(rehashed(data), budget=domain_budget())
    invalid_roots: tuple[object, ...] = ([], (), (None,), (value.roots[0],) * 4097)
    for invalid in invalid_roots:
        with pytest.raises(ValueError):
            replace(value, roots=cast(tuple[InventoryBaselineRoot, ...], invalid))
    large = replace(value.roots[1], files=(), directories=tuple(f"d{n:05d}" for n in range(65535)))
    with pytest.raises(ValueError, match="bounded complete"):
        replace(value, roots=(value.roots[0], large))
    for field in ("domain_reference", "registry_reference"):
        invalid_args = cast(BaselineArguments, {**args, field: {}})
        with pytest.raises(ValueError):
            InventoryBaseline1.build(**invalid_args, budget=domain_budget())
    with pytest.raises(ValueError):
        replace(value, domain_reference=cast(TypedObjectRef1, {}))
    with pytest.raises(ValueError):
        replace(value, registry_reference=cast(TypedObjectRef1, {}))
    invalid_args = {**args, "roots": cast(tuple[InventoryBaselineRoot, ...], [])}
    with pytest.raises(ValueError, match="source/reference"):
        InventoryBaseline1.build(**invalid_args, budget=domain_budget())
    with pytest.raises(ValueError, match="budget is required"):
        InventoryBaseline1.build(**args, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="budget is required"):
        InventoryBaseline1.from_dict(value.to_dict(), budget=cast(PolicyReadBudget1, {}))
    changed = replace(value.roots[1], directories=("scripts",))
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, roots=(value.roots[0], changed))
