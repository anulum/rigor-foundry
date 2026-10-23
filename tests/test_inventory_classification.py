# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — configured input classification tests
"""Classify real Git-domain input rows without losing bytes, deleted paths or unknowns."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository
from test_inventory_domain import domain, domain_budget

from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.inventory_classification import classify_repository_file_inputs
from rigor_foundry.inventory_domain import InventoryDomain1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_file_inputs import (
    RepositoryFileInputs,
    observe_repository_file_inputs,
)
from rigor_foundry.repository_git_inputs import RepositoryGitInputs
from rigor_foundry.repository_inventory_rows import RepositoryFileRow


def test_classification_uses_exact_longest_suffix_and_component_prefix_rules(
    tmp_path: Path,
) -> None:
    """Actual bytes survive deterministic rule precedence and explicit unmatched fields."""
    repository = GitRepository.create(tmp_path / "repository")
    values = {
        "src/module.PY": "VALUE = 1\n",
        "src/generated.py": '{"generated":true}\n',
        "tests/test_module.py": "assert 1 == 1\n",
        "tests/fixtures/example.py": "VALUE = 2\n",
        "tests/special.py": "print('example')\n",
        "testsuite/source.py": "VALUE = 3\n",
        "src/types.d.ts": "export declare const VALUE: number;\n",
        "src/wrapper.ts": "export const VALUE: number = 1;\n",
        "src/deleted.py": "VALUE = 4\n",
        "unmatched": "unknown bytes\n",
    }
    for name, text in values.items():
        repository.write_text(name, text)
    baseline = repository.commit()
    (repository.root / "src/deleted.py").unlink()
    raw = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=domain_budget()
    )
    result = classify_repository_file_inputs(
        raw, root_id="core", domain=domain(), budget=domain_budget()
    )
    rows = {row.relative_path: row for row in result.current_files}
    assert rows["src/module.PY"].language == "python"
    assert rows["src/generated.py"].language == "json"
    assert rows["src/types.d.ts"].language == "typescript-declaration"
    assert rows["src/wrapper.ts"].language == "typescript"
    assert rows["tests/test_module.py"].role == "test"
    assert rows["tests/fixtures/example.py"].role == "fixture"
    assert rows["tests/special.py"].role == "example"
    assert rows["testsuite/source.py"].language == "python"
    assert rows["testsuite/source.py"].role is None
    assert rows["unmatched"].language is rows["unmatched"].role is None
    assert rows[".gitignore"].language == "text" and rows[".gitignore"].role == "configuration"
    assert rows["src/deleted.py"].kind == "deleted"
    assert rows["src/deleted.py"].language == "python"
    assert rows["src/deleted.py"].byte_digest is None
    assert result.git == raw.git
    for before, after in zip(
        raw.baseline_files + raw.current_files,
        result.baseline_files + result.current_files,
        strict=True,
    ):
        assert replace(after, language=None, role=None) == before
    assert len(rows) == len(values) + 1


def test_classification_keeps_gitlinks_unsupported_types_and_empty_rules_unknown(
    tmp_path: Path,
) -> None:
    """A path label cannot replace a gitlink's independent root or a directory's byte owner."""
    repository = GitRepository.create(tmp_path / "repository")
    parent = repository.commit()
    repository.git_command(
        "update-index", "--add", "--cacheinfo", f"160000,{parent},dependency.py"
    )
    repository.git_command("commit", "-m", "test: retain dependency root")
    baseline = repository.git_command("rev-parse", "HEAD").stdout.strip()
    (repository.root / "dependency.py").mkdir()
    raw = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=domain_budget()
    )
    result = classify_repository_file_inputs(
        raw, root_id="core", domain=domain(), budget=domain_budget()
    )
    before = next(row for row in result.baseline_files if row.relative_path == "dependency.py")
    after = next(row for row in result.current_files if row.relative_path == "dependency.py")
    assert before.kind == "gitlink" and after.kind == "unsupported"
    assert before.language is before.role is after.language is after.role is None
    empty = InventoryDomain1.build(
        domain_id="unclassified",
        project_id="PROJECT-A",
        roots=domain().roots,
        rules=(),
        budget=domain_budget(),
    )
    unknown = classify_repository_file_inputs(
        raw, root_id="core", domain=empty, budget=domain_budget()
    )
    assert unknown == raw


def test_classification_refuses_invalid_sources_roots_and_row_budgets(tmp_path: Path) -> None:
    """Caller metadata cannot bypass the complete configured or row preimage parsers."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/source.py", "VALUE = 1\n")
    baseline = repository.commit()
    raw = observe_repository_file_inputs(
        repository.root, baseline_head=baseline, runner=GitRunner(), budget=domain_budget()
    )
    for selected in ("absent", "bad identity"):
        with pytest.raises(ValueError):
            classify_repository_file_inputs(
                raw, root_id=selected, domain=domain(), budget=domain_budget()
            )
    with pytest.raises(ValueError, match="actual inventory domain"):
        classify_repository_file_inputs(
            raw, root_id="core", domain=cast(InventoryDomain1, {}), budget=domain_budget()
        )
    with pytest.raises(ValueError, match="policy read budget"):
        classify_repository_file_inputs(
            raw, root_id="core", domain=domain(), budget=cast(PolicyReadBudget1, {})
        )
    for value in (cast(RepositoryFileInputs, {}), replace(raw, git=cast(RepositoryGitInputs, {}))):
        with pytest.raises(ValueError, match="actual repository file"):
            classify_repository_file_inputs(
                value, root_id="core", domain=domain(), budget=domain_budget()
            )
    with pytest.raises(ValueError):
        classify_repository_file_inputs(
            replace(raw, baseline_files=cast(tuple[RepositoryFileRow, ...], [])),
            root_id="core",
            domain=domain(),
            budget=domain_budget(),
        )
    one = InventoryDomain1.build(
        domain_id="one",
        project_id="PROJECT-A",
        roots=domain().roots[:1],
        rules=(),
        budget=domain_budget(),
    )
    with pytest.raises(ValueError, match="source count budget"):
        classify_repository_file_inputs(
            raw, root_id="core", domain=one, budget=domain_budget(max_sources=1)
        )


def test_common_classifier_consumes_actual_directory_rows_without_fake_git_state(
    tmp_path: Path,
) -> None:
    """The same selectors preserve real directory identities and explicit unknown rows."""
    from rigor_foundry.directory_file_inputs import observe_directory_file_inputs
    from rigor_foundry.inventory_classification import classify_inventory_file_rows

    root = tmp_path / "directory"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts/tool.py").write_bytes(b"VALUE = 1\n")
    (root / "unknown").write_bytes(b"unclassified")
    observed = observe_directory_file_inputs(root, budget=domain_budget())
    rows = classify_inventory_file_rows(
        observed.files, root_id="private", domain=domain(), budget=domain_budget()
    )
    selected = {row.relative_path: row for row in rows}
    assert selected["scripts/tool.py"].language == "python"
    assert selected["scripts/tool.py"].role == "tool"
    assert selected["unknown"].language is selected["unknown"].role is None
    assert tuple(replace(row, language=None, role=None) for row in rows) == observed.files
    assert all(row.object_id is None for row in rows)
