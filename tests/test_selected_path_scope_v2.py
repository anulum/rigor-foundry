# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected path scope tests
"""Exercise exact registry-derived path roots and generation refusals."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_deployment_profile import encode_profile
from test_project_registry_models import profiled_registry, project, resign
from test_project_registry_models import registry as sample_registry

from rigor_foundry.models import canonical_digest
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.tier0_builtin.path_admission_v2 import canonicalize_atomic_path_v2
from rigor_foundry.tier0_builtin.selected_path_scope_v2 import derive_selected_path_scope_v2


def test_selected_scope_uses_only_verified_registry_paths(tmp_path: Path) -> None:
    """A real target is admitted under the single selected registry root."""
    selected = sample_registry()
    project = tmp_path / "03_CODE/GROUP-A/repositories/PROJECT-A"
    project.mkdir(parents=True)
    scope = derive_selected_path_scope_v2(
        registry_bytes=selected.to_bytes(),
        monorepo_root=str(tmp_path),
        selected_project_id="PROJECT-A",
        registry_generation_id=selected.generation_id,
        registry_sha256=selected.registry_sha256,
    )
    assert scope.selected_root.path == str(project)
    assert scope.registry_generation_id == selected.generation_id
    assert scope.registry_sha256 == selected.registry_sha256
    assert scope.path_scope_digest == canonical_digest(
        {
            "schema": "rigor.selected-path-scope.v2",
            "registry_generation_id": selected.generation_id,
            "registry_sha256": selected.registry_sha256,
            "monorepo_root": str(tmp_path),
            "selected_project_id": "PROJECT-A",
            "selected_root": str(project),
            "projects": [{"project_id": "PROJECT-A", "group_id": "GROUP-A", "path": str(project)}],
            "groups": [{"group_id": "GROUP-A", "path": str(tmp_path / "03_CODE/GROUP-A")}],
        }
    )
    target = project / "report.txt"
    assert canonicalize_atomic_path_v2(str(target), scope) == {
        "form": "path",
        "value": str(target),
    }
    project.rename(project.with_name("moved"))
    with pytest.raises((PermissionError, OSError)):
        canonicalize_atomic_path_v2(str(target), scope)
    project.mkdir()
    assert canonicalize_atomic_path_v2(str(target), scope)["value"] == str(target)


def test_profiled_scope_uses_explicit_alternate_roots_with_real_admission(tmp_path: Path) -> None:
    """A valid alternate registry layout supplies roots without fixed v1 substitution."""
    wire = json.dumps(profiled_registry().to_dict())
    wire = wire.replace("03_CODE/GROUP-A", "portfolio/team")
    wire = wire.replace("/repositories", "/members").replace("/agentic_group_memory", "/memory")
    data = json.loads(wire)
    data["deployment_profile"] = json.loads(encode_profile(data["deployment_profile"]))
    selected = ProjectRegistry.from_dict(resign(data))
    root = tmp_path / "portfolio/team/members/PROJECT-A"
    root.mkdir(parents=True)
    scope = derive_selected_path_scope_v2(
        registry_bytes=selected.to_bytes(),
        monorepo_root=str(tmp_path),
        selected_project_id="PROJECT-A",
        registry_generation_id=selected.generation_id,
        registry_sha256=selected.registry_sha256,
    )
    assert scope.selected_root.path == str(root)
    assert tuple(item.path for item in scope.registered_groups) == (
        str(tmp_path / "portfolio/team"),
    )
    assert canonicalize_atomic_path_v2(str(root / "new.txt"), scope) == {
        "form": "path",
        "value": str(root / "new.txt"),
    }
    assert not (tmp_path / "03_CODE").exists()


def test_inactive_roots_remain_registered_but_cannot_be_selected(tmp_path: Path) -> None:
    """Retired registrations stay in root checks without activating their project."""
    inactive = replace(project("PROJECT-B", memory_state="absent"), lifecycle_state="retired")
    selected = sample_registry(projects=(project(), inactive))
    scope = derive_selected_path_scope_v2(
        registry_bytes=selected.to_bytes(),
        monorepo_root=str(tmp_path),
        selected_project_id="PROJECT-A",
        registry_generation_id=selected.generation_id,
        registry_sha256=selected.registry_sha256,
    )
    assert {item.path for item in scope.registered_projects} == {
        str(tmp_path / item.canonical_path) for item in selected.projects
    }
    assert not list(tmp_path.iterdir())
    with pytest.raises(PermissionError, match="absent or inactive"):
        derive_selected_path_scope_v2(
            registry_bytes=selected.to_bytes(),
            monorepo_root=str(tmp_path),
            selected_project_id="PROJECT-B",
            registry_generation_id=selected.generation_id,
            registry_sha256=selected.registry_sha256,
        )


@pytest.mark.parametrize(
    "fault",
    (
        "missing-body",
        "registry-hash",
        "generation",
        "project",
        "empty-project",
        "relative-root",
        "slash-root",
        "double-slash-root",
        "noncanonical-root",
    ),
)
def test_selected_scope_refuses_missing_or_different_custody(tmp_path: Path, fault: str) -> None:
    """A caller root or changed registry generation cannot form this scope."""
    selected = sample_registry()
    values: dict[str, object] = {
        "registry_bytes": selected.to_bytes(),
        "monorepo_root": str(tmp_path),
        "selected_project_id": "PROJECT-A",
        "registry_generation_id": selected.generation_id,
        "registry_sha256": selected.registry_sha256,
    }
    if fault == "missing-body":
        values["registry_bytes"] = None
    elif fault == "registry-hash":
        values["registry_sha256"] = "0" * 64
    elif fault == "generation":
        values["registry_generation_id"] = "different"
    elif fault == "project":
        values["selected_project_id"] = "other"
    elif fault == "empty-project":
        values["selected_project_id"] = ""
    elif fault == "relative-root":
        values["monorepo_root"] = "relative"
    elif fault == "double-slash-root":
        values["monorepo_root"] = "//srv/mono"
    elif fault == "noncanonical-root":
        values["monorepo_root"] = f"{tmp_path}/../other"
    else:
        values["monorepo_root"] = "/"
    with pytest.raises((PermissionError, ValueError)):
        derive_selected_path_scope_v2(
            registry_bytes=cast(bytes, values["registry_bytes"]),
            monorepo_root=cast(str, values["monorepo_root"]),
            selected_project_id=cast(str, values["selected_project_id"]),
            registry_generation_id=cast(str, values["registry_generation_id"]),
            registry_sha256=cast(str, values["registry_sha256"]),
        )
