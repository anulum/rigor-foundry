# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — pinned clause scope expansion tests
"""Exercise registry template paths without granting an action."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from test_project_registry_models import group, profiled_registry, project
from test_project_registry_models import registry as project_registry

from rigor_foundry.clause_scope_registry_expansion_v2 import expand_clause_scope_v2
from rigor_foundry.project_registry_models import ProjectRegistry

_SCHEMA = "rigor.clause-scope-selector.v2"


def _registry() -> ProjectRegistry:
    """Include two own projects and one foreign registered group."""
    return project_registry(
        groups=(group("GROUP-A"), group("GROUP-B")),
        projects=(project("PROJECT-A", "GROUP-A"), project("PROJECT-B", "GROUP-A")),
    )


@pytest.mark.parametrize("selector", ["group-memory:GROUP-A", "project-coordination:PROJECT-A"])
def test_interim_resolver_refuses_profiled_layout_instead_of_guessing(
    tmp_path: Path, selector: str
) -> None:
    """A valid profiled registry needs a resolver for its explicit layout contract."""
    selected = profiled_registry(_registry())
    assert ProjectRegistry.from_bytes(selected.to_bytes()) == selected
    assert selected.profile is not None
    with pytest.raises(PermissionError, match="requires an unprofiled registry"):
        _expand(tmp_path, selector, registry=selected)


def _expand(
    root: Path,
    selector: str,
    *,
    subject: str = "admit",
    effect_class: str = "local-file-write",
    registry: ProjectRegistry | None = None,
    project_id: str = "PROJECT-A",
    expected_registry_sha256: str | None = None,
    resolver_version: str = "registry-v1-interim",
    monorepo_root: Path | None = None,
) -> tuple[str, ...]:
    """Resolve one selector with the current protected generation pins."""
    selected = _registry() if registry is None else registry
    return expand_clause_scope_v2(
        scope={"schema": _SCHEMA, "targets": [selector], "exclusions": []},
        subject=subject,
        effect_class=effect_class,
        project_id=project_id,
        registry=selected,
        expected_registry_sha256=(
            selected.registry_sha256
            if expected_registry_sha256 is None
            else expected_registry_sha256
        ),
        monorepo_root=root if monorepo_root is None else monorepo_root,
        resolver_version=resolver_version,
    ).targets


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("project-root:PROJECT-A", ("03_CODE/GROUP-A/repositories/PROJECT-A",)),
        (
            "project-coordination:PROJECT-A",
            (".coordination/handovers/PROJECT-A", ".coordination/sessions/PROJECT-A"),
        ),
        (
            "group-workspace:GROUP-A/PROJECT-A",
            ("03_CODE/GROUP-A/agentic_group_workspace/PROJECT-A",),
        ),
        (
            "group-projects:GROUP-A",
            (
                "03_CODE/GROUP-A/repositories/PROJECT-A",
                "03_CODE/GROUP-A/repositories/PROJECT-B",
            ),
        ),
        (
            "group-project-records:GROUP-A",
            (
                ".coordination/handovers/PROJECT-A",
                ".coordination/handovers/PROJECT-B",
                ".coordination/sessions/PROJECT-A",
                ".coordination/sessions/PROJECT-B",
            ),
        ),
        ("group-workspace:GROUP-A", ("03_CODE/GROUP-A/agentic_group_workspace",)),
        ("group-memory:GROUP-A", ("03_CODE/GROUP-A/agentic_group_memory",)),
        (
            "group-exchange-state:GROUP-A",
            (
                "03_CODE/GROUP-A/agentic_group_exchange/archive",
                "03_CODE/GROUP-A/agentic_group_exchange/quarantine",
                "03_CODE/GROUP-A/agentic_group_exchange/triage",
            ),
        ),
        ("group-exchange-inbox:GROUP-B", ("03_CODE/GROUP-B/agentic_group_exchange/inbox",)),
        ("monorepo-read-root", ("",)),
    ],
)
def test_all_registry_forms_expand_from_current_generation(
    tmp_path: Path, selector: str, expected: tuple[str, ...]
) -> None:
    """Every registered template resolves to the exact pinned path set."""
    effect_class = (
        "read"
        if selector == "monorepo-read-root"
        else (
            "exchange-record-create"
            if selector.startswith("group-exchange-inbox:")
            else "local-file-write"
        )
    )
    assert _expand(tmp_path, selector, effect_class=effect_class) == tuple(
        f"path:{tmp_path / path}" for path in expected
    )


def test_literal_forms_and_exclusions_remain_exact(tmp_path: Path) -> None:
    """A literal is not rewritten using filesystem or registry aliases."""
    selected = _registry()
    scope = {
        "schema": _SCHEMA,
        "targets": ["path:/tmp/rigor", "remote:https://example.test/resource"],
        "exclusions": ["path-glob:/tmp/rigor/*"],
    }
    result = expand_clause_scope_v2(
        scope=scope,
        subject="admit",
        effect_class="local-file-write",
        project_id="PROJECT-A",
        registry=selected,
        expected_registry_sha256=selected.registry_sha256,
        monorepo_root=tmp_path,
        resolver_version="registry-v1-interim",
    )
    assert result.targets == ("path:/tmp/rigor", "remote:https://example.test/resource")
    assert result.exclusions == ("path-glob:/tmp/rigor/*",)
    assert result.registry_generation_id == selected.generation_id
    assert result.registry_sha256 == selected.registry_sha256


@pytest.mark.parametrize(
    ("target", "exclusion", "removed"),
    [
        ("path:/srv/data/file", "path:/srv/data", True),
        ("repo:/srv/data", "path:/srv/data", True),
        ("path:/srv/data-other", "repo:/srv/data", False),
        ("remote:https://example.test/a", "remote:https://example.test/a", True),
        ("remote:https://example.test/a", "remote:https://example.test/b", False),
        ("endpoint:service:item", "endpoint:service:item", True),
        ("host:node-a", "host:node-a", True),
        ("host:node-a", "endpoint:service:item", False),
        ("any-repository", "repo:/srv/data", False),
    ],
)
def test_veto_exclusion_cannot_silence_a_complete_target(
    tmp_path: Path, target: str, exclusion: str, removed: bool
) -> None:
    """Full containment refuses; siblings and differently formed targets survive."""
    selected = _registry()
    scope = {"schema": _SCHEMA, "targets": [target], "exclusions": [exclusion]}
    if removed:
        with pytest.raises(PermissionError, match="target element expands to empty"):
            expand_clause_scope_v2(
                scope=scope,
                subject="veto",
                effect_class="local-file-write",
                project_id="PROJECT-A",
                registry=selected,
                expected_registry_sha256=selected.registry_sha256,
                monorepo_root=tmp_path,
                resolver_version="registry-v1-interim",
            )
    else:
        result = expand_clause_scope_v2(
            scope=scope,
            subject="veto",
            effect_class="local-file-write",
            project_id="PROJECT-A",
            registry=selected,
            expected_registry_sha256=selected.registry_sha256,
            monorepo_root=tmp_path,
            resolver_version="registry-v1-interim",
        )
        assert result.targets == (target,)
        assert result.exclusions == (exclusion,)


@pytest.mark.parametrize(
    ("selector", "subject", "effect_class"),
    [
        ("project-root:PROJECT-B", "admit", "local-file-write"),
        ("group-projects:GROUP-B", "admit", "local-file-write"),
        ("group-exchange-inbox:GROUP-A", "admit", "exchange-record-create"),
        ("group-exchange-inbox:GROUP-B", "rate", "exchange-record-create"),
        ("any-remote", "admit", "local-file-write"),
    ],
)
def test_foreign_or_forbidden_selector_refuses(
    tmp_path: Path, selector: str, subject: str, effect_class: str
) -> None:
    """A template cannot widen to another project or group."""
    with pytest.raises((PermissionError, ValueError)):
        _expand(tmp_path, selector, subject=subject, effect_class=effect_class)


def test_wrong_generation_resolver_or_root_refuses(tmp_path: Path) -> None:
    """Selection pins and no-follow root precede any template expansion."""
    selected = _registry()
    for changes in (
        {"expected_registry_sha256": "0" * 64},
        {"resolver_version": "pcs-k2-v1"},
        {"monorepo_root": Path("relative/root")},
    ):
        with pytest.raises(PermissionError):
            _expand(tmp_path, "project-root:PROJECT-A", registry=selected, **changes)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises((OSError, ValueError)):
        _expand(alias, "project-root:PROJECT-A", registry=selected)


def test_forged_in_memory_registry_refuses(tmp_path: Path) -> None:
    """A forged generation object cannot bypass canonical round-trip checks."""
    selected = _registry()
    forged = replace(selected, registry_sha256="0" * 64)
    with pytest.raises((PermissionError, ValueError)):
        _expand(tmp_path, "project-root:PROJECT-A", registry=forged)


def test_inactive_project_or_owning_group_refuses(tmp_path: Path) -> None:
    """A current generation alone does not activate retired identities."""
    with pytest.raises(PermissionError, match="project is not active"):
        _expand(tmp_path, "project-root:PROJECT-A", project_id="MISSING")
    base = _registry()
    retired_group = replace(group("GROUP-A"), lifecycle_state="retired")
    selected = ProjectRegistry.build(
        generated_at=base.generated_at,
        previous_registry_sha256=base.previous_registry_sha256,
        authority=base.authority,
        groups=(retired_group, group("GROUP-B")),
        projects=(project("PROJECT-A", "GROUP-A"),),
        consumers=tuple(
            item
            for item in base.consumers
            if item.group_id != "GROUP-A" and item.project_id != "PROJECT-B"
        ),
    )
    with pytest.raises(PermissionError, match="owning group is not active"):
        _expand(tmp_path, "project-root:PROJECT-A", registry=selected)
