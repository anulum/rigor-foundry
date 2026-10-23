# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained inventory source observation tests
"""Exercise actual retained domain/registry/code selections and real Git-root bytes."""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from repository_audit_git_repository import GitRepository
from test_context_owner_implementation import implementation_budget
from test_inventory_domain import domain
from test_project_registry_models import registry

import rigor_foundry.inventory_source_observations as source_module
from rigor_foundry.context_owner_implementation import (
    OwnerImplementationSnapshot,
    observe_owner_implementation,
)
from rigor_foundry.context_producer_contract import (
    ContextProducerContract1,
    ContextRootBinding,
    SourceFormat,
)
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.inventory_domain import InventoryDomain1
from rigor_foundry.inventory_source_observations import observe_classified_git_root
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.typed_object_reference import TypedObjectRef1


class ObservationArguments(TypedDict):
    """Complete typed inputs for one actual configured Git-root observation."""

    root_id: str
    baseline_head: str
    monorepo_root: Path
    domain_source: RetainedContextSource
    registry_source: RetainedContextSource
    contract_source: RetainedContextSource
    implementation: OwnerImplementationSnapshot
    runner: GitRunner
    budget: PolicyReadBudget1


@dataclass(frozen=True)
class SelectedInventory:
    """Actual task-owned fixture files and held source leases."""

    arguments: ObservationArguments
    paths: tuple[Path, ...]
    references: tuple[TypedObjectRef1, ...]
    repository: GitRepository


@contextmanager
def selection(
    root: Path, *, fault: str = "", declared_domain: InventoryDomain1 | None = None
) -> Iterator[SelectedInventory]:
    """Create real repository/registry/domain/contract inputs before retaining sources."""
    root.mkdir()
    host, control = root / "host", root / "control"
    control.mkdir()
    repository = GitRepository.create(host / "03_CODE/GROUP-A/repositories/PROJECT-A")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.write_text("unclassified", "not automatically enrolled\n")
    baseline = repository.commit()
    limits = implementation_budget()
    code = observe_owner_implementation(Path(source_module.__file__).parent, budget=limits)
    declared = domain() if declared_domain is None else declared_domain
    if fault in {"missing-project", "outside-project", "generated-root"}:
        roots = declared.roots
        if fault == "outside-project":
            roots = (replace(roots[0], canonical_path="unrelated/repository"), roots[1])
        elif fault == "generated-root":
            roots = (replace(roots[0], source_kind="generated"), roots[1])
        declared = InventoryDomain1.build(
            domain_id=declared.domain_id,
            project_id="ABSENT" if fault == "missing-project" else declared.project_id,
            roots=roots,
            rules=declared.rules,
            budget=limits,
        )
    registered = registry()
    bindings = tuple(
        ContextRootBinding(
            item.root_id,
            declared.project_id,
            "GROUP-B" if fault == "binding-group" else "GROUP-A",
            item.canonical_path + "/wrong" if fault == "binding-path" else item.canonical_path,
            "0" * 64 if fault == "binding-scope" else declared.domain_digest,
        )
        for item in declared.roots
    )
    if fault == "binding-set":
        bindings = bindings[:1]
    if fault == "binding-extra":
        bindings = tuple(
            sorted(
                (
                    *bindings,
                    ContextRootBinding(
                        "extra",
                        "PROJECT-A",
                        "GROUP-A",
                        "03_CODE/GROUP-A/repositories/PROJECT-A/extra",
                        declared.domain_digest,
                    ),
                ),
                key=lambda item: item.root_id,
            )
        )
    formats: tuple[SourceFormat, ...] = (
        ("inventory-domain", "1.0"),
        (
            "project-registry",
            "project-registry.v2" if fault == "registry-format" else "gotm-project-registry.v1",
        ),
        ("repository-state", "1.0"),
    )
    if fault == "missing-domain-format":
        formats = formats[1:]
    contract = ContextProducerContract1.build(
        contract_id="inventory-contract",
        owner_id="inventory-owner",
        owner_class="registry" if fault == "contract-role" else "inventory",
        implementation_id="builtin.project-registry.v1"
        if fault == "contract-role"
        else "builtin.maintained-inventory.v1",
        implementation_digest="0" * 64 if fault == "contract-code" else code.implementation_digest,
        source_formats=(("project-registry", "gotm-project-registry.v1"),)
        if fault == "contract-role"
        else formats,
        subject_kinds=("registry-generation",)
        if fault == "contract-role"
        else ("baseline-inventory", "repository-state"),
        fact_references=(),
        root_bindings=bindings,
        budget=limits,
    )
    references = (
        TypedObjectRef1.from_dict(declared.reference()),
        TypedObjectRef1.build(
            kind="project-registry",
            format_version="gotm-project-registry.v1",
            object_id=registered.generation_id,
            object_digest=registered.registry_sha256,
        ),
        TypedObjectRef1.from_dict(contract.reference()),
    )
    payloads = (
        json.dumps(declared.to_dict()).encode(),
        registered.to_bytes(),
        json.dumps(contract.to_dict()).encode(),
    )
    paths = tuple(control / f"source-{index}.json" for index in range(3))
    for path, payload in zip(paths, payloads, strict=True):
        path.write_bytes(payload)
    with ExitStack() as stack:
        sources = tuple(
            stack.enter_context(
                RetainedContextSource(
                    path,
                    reference=ref,
                    raw_digest=hashlib.sha256(payload).hexdigest(),
                    budget=limits,
                )
            )
            for path, ref, payload in zip(paths, references, payloads, strict=True)
        )
        arguments: ObservationArguments = {
            "root_id": "core",
            "baseline_head": baseline,
            "monorepo_root": Path("relative") if fault == "host-path" else host,
            "domain_source": sources[1] if fault == "source-kind" else sources[0],
            "registry_source": sources[1],
            "contract_source": sources[2],
            "implementation": replace(code, implementation_digest="0" * 64)
            if fault == "code-selection"
            else code,
            "runner": GitRunner(),
            "budget": limits,
        }
        yield SelectedInventory(arguments, paths, references, repository)


def test_actual_retained_domain_selects_classified_bytes_without_whole_inventory_claim(
    tmp_path: Path,
) -> None:
    """Actual source closure retains every declared root while observing one actual Git root."""
    with selection(tmp_path / "selection") as chosen:
        result = observe_classified_git_root(**chosen.arguments)
        rows = {row.relative_path: row for row in result.files.current_files}
        assert rows["src/module.py"].language == "python"
        assert rows["src/module.py"].role == "source"
        assert rows["unclassified"].language is rows["unclassified"].role is None
        assert result.domain_reference == chosen.references[0]
        assert result.registry_reference == chosen.references[1]
        assert result.contract_reference == chosen.references[2]
        assert result.files.git.baseline_head == chosen.arguments["baseline_head"]
        assert result.files.git.root == chosen.repository.root
        assert len(result.source_snapshot_digest) == 64
        assert len(domain().roots) == 2


@pytest.mark.parametrize(
    "fault",
    (
        "missing-project",
        "outside-project",
        "generated-root",
        "binding-group",
        "binding-path",
        "binding-scope",
        "binding-set",
        "binding-extra",
        "missing-domain-format",
        "registry-format",
        "contract-role",
        "contract-code",
        "host-path",
        "source-kind",
        "code-selection",
    ),
)
def test_actual_selected_source_or_registry_mismatch_refuses(tmp_path: Path, fault: str) -> None:
    """A changed complete configuration, group, format or implementation cannot fall back."""
    with selection(tmp_path / "selection", fault=fault) as chosen, pytest.raises(ValueError):
        observe_classified_git_root(**chosen.arguments)


def test_root_identity_and_actual_input_types_cannot_choose_an_alternate_source(
    tmp_path: Path,
) -> None:
    """Malformed host inputs refuse; a directory declaration is not coerced into Git."""
    with selection(tmp_path / "selection") as chosen:
        for identity in ("absent", "private", "bad identity"):
            arguments = chosen.arguments.copy()
            arguments["root_id"] = identity
            with pytest.raises(ValueError):
                observe_classified_git_root(**arguments)
        arguments = chosen.arguments.copy()
        arguments["budget"] = cast(PolicyReadBudget1, {})
        with pytest.raises(ValueError, match="policy read budget"):
            observe_classified_git_root(**arguments)
        arguments = chosen.arguments.copy()
        arguments["runner"] = cast(GitRunner, {})
        with pytest.raises(ValueError, match="actual Git runner"):
            observe_classified_git_root(**arguments)
        arguments = chosen.arguments.copy()
        arguments["domain_source"] = cast(RetainedContextSource, {})
        with pytest.raises(ValueError, match="actual retained"):
            observe_classified_git_root(**arguments)
        arguments = chosen.arguments.copy()
        arguments["implementation"] = cast(OwnerImplementationSnapshot, {})
        with pytest.raises(ValueError, match="complete inventory implementation"):
            observe_classified_git_root(**arguments)


@pytest.mark.parametrize(
    ("phase", "message"),
    (
        ("domain-bytes", "identity changed"),
        ("implementation", "implementation changed during"),
        ("host-root", "host monorepo directory object changed"),
    ),
    ids=("domain-bytes", "implementation", "host-root"),
)
def test_actual_source_code_and_host_changes_refuse_at_native_boundaries(
    tmp_path: Path, phase: str, message: str
) -> None:
    """Owned-child syscall stops mutate real complete sources, code copies or root objects."""
    with selection(tmp_path / "selection") as chosen:
        code_parent = tmp_path / "code"
        copied = code_parent / "rigor_foundry"
        canonical = Path(source_module.__file__).parent
        shutil.copytree(canonical, copied, symlinks=True)
        for original in canonical.rglob("*.py"):
            assert (copied / original.relative_to(canonical)).read_bytes() == original.read_bytes()
        host = chosen.arguments["monorepo_root"]
        alternate = tmp_path / "alternate"
        if phase == "host-root":
            shutil.copytree(host, alternate, symlinks=True)
        worker = """
import hashlib,json,sys
from contextlib import ExitStack
from pathlib import Path
sys.path.insert(0,sys.argv[1]);sys.path.insert(1,sys.argv[2])
from project_registry_syscall_scheduler import arm_native_trace
from rigor_foundry.context_owner_implementation import observe_owner_implementation
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.inventory_source_observations import observe_classified_git_root
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.typed_object_reference import TypedObjectRef1
config=json.loads(sys.argv[3]);budget=PolicyReadBudget1.from_dict(config['budget'])
code=observe_owner_implementation(Path(sys.argv[1])/'rigor_foundry',budget=budget)
stack=ExitStack()
sources=[stack.enter_context(RetainedContextSource(Path(path),reference=TypedObjectRef1.from_dict(ref),raw_digest=hashlib.sha256(Path(path).read_bytes()).hexdigest(),budget=budget)) for path,ref in zip(config['paths'],config['references'],strict=True)]
runner=GitRunner();arm_native_trace()
try:
    observe_classified_git_root(root_id='core',baseline_head=config['baseline'],monorepo_root=Path(config['host']),domain_source=sources[0],registry_source=sources[1],contract_source=sources[2],implementation=code,runner=runner,budget=budget)
except (ValueError,RuntimeError,OSError) as exc:
    outcome={'accepted':False,'error':str(exc)}
else:
    outcome={'accepted':True}
try:stack.close()
except (ValueError,RuntimeError,OSError) as exc:outcome['closing_error']=str(exc)
print(json.dumps(outcome))
"""
        changed = False
        observed_file_read = False
        source = chosen.repository.root / "src/module.py"

        def mutate(stop: SyscallStop) -> bool:
            """Alter only the selected real fixture object at its actual native boundary."""
            nonlocal changed, observed_file_read
            if (
                not stop.entering
                and stop.number == 0
                and stop.path == str(source)
                and stop.result == 0
            ):
                observed_file_read = True
            if (
                not changed
                and phase == "host-root"
                and observed_file_read
                and stop.entering
                and stop.number == 257
                and stop.path == str(copied)
            ):
                host.rename(tmp_path / "retained-host")
                alternate.rename(host)
                changed = True
            if (
                not changed
                and phase != "host-root"
                and not stop.entering
                and stop.number == 0
                and stop.path == str(source)
                and stop.result == 0
            ):
                if phase == "domain-bytes":
                    chosen.paths[0].write_bytes(chosen.paths[0].read_bytes() + b"\n")
                else:
                    with (copied / "__init__.py").open("a") as handle:
                        handle.write("\n# owned fixture source changed\n")
                changed = True
            return False

        config = {
            "budget": chosen.arguments["budget"].to_dict(),
            "paths": [str(path) for path in chosen.paths],
            "references": [ref.to_dict() for ref in chosen.references],
            "baseline": chosen.arguments["baseline_head"],
            "host": str(host),
        }
        try:
            result = run_traced(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    worker,
                    str(code_parent),
                    str(Path(__file__).parent),
                    json.dumps(config),
                ],
                mutate,
                timeout=100,
            )
            write_trace(tmp_path / "inventory-source-trace.json", result)
            assert result.returncode == 0, result.stderr
            assert changed, "selected actual native boundary was not observed"
            outcome = json.loads(result.stdout)
            assert outcome["accepted"] is False
            assert message in outcome["error"]
            for original in canonical.rglob("*.py"):
                counterpart = copied / original.relative_to(canonical)
                if original.name == "__init__.py" and original.parent == canonical:
                    assert ast.dump(
                        ast.parse(counterpart.read_text(encoding="utf-8"))
                    ) == ast.dump(ast.parse(original.read_text(encoding="utf-8")))
                else:
                    assert counterpart.read_bytes() == original.read_bytes()
        finally:
            # The outer fixture owns the original source lease and must observe this refusal too.
            if phase == "domain-bytes" and changed:
                with pytest.raises(ValueError, match="identity changed"):
                    chosen.arguments["domain_source"].close()
