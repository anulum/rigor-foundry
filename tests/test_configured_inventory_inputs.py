# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual configured root collection tests
"""Collect complete real Git/directory domains under original retained sources."""

from __future__ import annotations

import ast
import json
import shlex
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from repository_audit_git_repository import GitRepository
from test_context_owner_implementation import implementation_budget
from test_inventory_domain import domain
from test_inventory_source_observations import SelectedInventory, selection

from rigor_foundry.configured_inventory_inputs import (
    InventoryGitBaseline,
    observe_configured_inventory_inputs,
)
from rigor_foundry.context_owner_implementation import OwnerImplementationSnapshot
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.directory_file_inputs import DirectoryFileInputs
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy
from rigor_foundry.inventory_domain import InventoryDomain1, InventoryDomainRoot
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_file_inputs import (
    RepositoryFileInputs,
    observe_repository_file_inputs,
)


class CollectionArguments(TypedDict):
    """Exact actual selected public inputs, without untyped keyword laundering."""

    baselines: tuple[InventoryGitBaseline, ...]
    monorepo_root: Path
    domain_source: RetainedContextSource
    registry_source: RetainedContextSource
    contract_source: RetainedContextSource
    implementation: OwnerImplementationSnapshot
    runner: GitRunner
    budget: PolicyReadBudget1


def arguments(chosen: SelectedInventory) -> CollectionArguments:
    """Use the real retained sources and explicit independent Git baseline."""
    args = chosen.arguments
    return {
        "baselines": (InventoryGitBaseline("core", args["baseline_head"]),),
        "monorepo_root": args["monorepo_root"],
        "domain_source": args["domain_source"],
        "registry_source": args["registry_source"],
        "contract_source": args["contract_source"],
        "implementation": args["implementation"],
        "runner": args["runner"],
        "budget": args["budget"],
    }


def declared(*, kind: str = "ignored") -> InventoryDomain1:
    """Retain the complete real declaration while changing one explicit capture kind."""
    original = domain()
    return InventoryDomain1.build(
        domain_id=original.domain_id,
        project_id=original.project_id,
        roots=(original.roots[0], replace(original.roots[1], source_kind=kind)),
        rules=original.rules,
        budget=implementation_budget(),
    )


def private_tree(chosen: SelectedInventory, *, ignored: bool = True) -> Path:
    """Create actual maintained directory bytes and optionally a real Git ignore rule."""
    repository = chosen.repository
    if ignored:
        ignore = repository.root / ".gitignore"
        ignore.write_text(ignore.read_text() + "\ntools/.internal/\n")
    result = repository.write_text("tools/.internal/scripts/tool.py", "VALUE = 2\n")
    (result.parent / "empty").mkdir()
    return result


def test_complete_actual_domain_captures_git_and_ignored_directory_without_fake_history(
    tmp_path: Path,
) -> None:
    """Every declared root, file, empty directory and original Git stage survives."""
    with selection(tmp_path / "selection") as chosen:
        private_tree(chosen)
        result = observe_configured_inventory_inputs(**arguments(chosen))
        assert tuple(root.root.root_id for root in result.roots) == ("core", "private")
        core, private = result.roots
        assert isinstance(core.inputs, RepositoryFileInputs)
        assert isinstance(private.inputs, DirectoryFileInputs)
        assert len(core.inputs.baseline_files) == 3
        assert not any(
            row.relative_path.startswith("tools/.internal/") for row in core.inputs.current_files
        )
        assert private.inputs.directories == ("scripts", "scripts/empty")
        assert private.inputs.files[0].language == "python"
        assert private.inputs.files[0].role == "tool"
        assert private.inputs.files[0].object_id is None
        assert result.domain_reference == chosen.references[0]
        assert result.registry_reference == chosen.references[1]
        assert result.contract_reference == chosen.references[2]
        assert len(result.source_snapshot_digest) == 64
        assert result.file_source_bytes_read == (
            core.inputs.source_bytes_read + private.inputs.source_bytes_read
        )
        owners = {owner.canonical_path: owner.root_id for owner in result.path_owners}
        assert owners["03_CODE/GROUP-A/repositories/PROJECT-A"] == "core"
        assert (
            owners["03_CODE/GROUP-A/repositories/PROJECT-A/tools/.internal/scripts/tool.py"]
            == "private"
        )


def test_generated_overlap_retains_both_original_observations_and_longest_root_owner(
    tmp_path: Path,
) -> None:
    """A configured namespace owner never discards parent rows or invents generator proof."""
    with selection(tmp_path / "selection", declared_domain=declared(kind="generated")) as chosen:
        private_tree(chosen, ignored=False)
        result = observe_configured_inventory_inputs(**arguments(chosen))
        parent, child = result.roots
        assert isinstance(parent.inputs, RepositoryFileInputs)
        assert isinstance(child.inputs, DirectoryFileInputs)
        original = next(
            row
            for row in parent.inputs.current_files
            if row.relative_path == "tools/.internal/scripts/tool.py"
        )
        actual = child.inputs.files[0]
        assert original.byte_digest == actual.byte_digest
        assert original.byte_count == actual.byte_count
        assert original.role is None and actual.role == "tool"
        assert original.object_id is not None and actual.object_id is None
        assert child.root.source_kind == "generated"
        assert not hasattr(child.inputs, "baseline_files")
        owners = {owner.canonical_path: owner.root_id for owner in result.path_owners}
        assert (
            owners["03_CODE/GROUP-A/repositories/PROJECT-A/tools/.internal/scripts/tool.py"]
            == "private"
        )


@pytest.mark.parametrize("phase", ("missing", "not-ignored", "tracked", "uncontained"))
def test_declared_ignored_root_requires_actual_presence_ignore_and_untracked_containment(
    tmp_path: Path, phase: str
) -> None:
    """Declared metadata cannot turn a missing, tracked or unverified tree into ignored input."""
    original = declared()
    if phase == "uncontained":
        original = InventoryDomain1.build(
            domain_id=original.domain_id,
            project_id=original.project_id,
            roots=original.roots[1:],
            rules=tuple(rule for rule in original.rules if rule.root_id == "private"),
            budget=implementation_budget(),
        )
    with selection(tmp_path / "selection", declared_domain=original) as chosen:
        args = arguments(chosen)
        if phase == "missing":
            ignore = chosen.repository.root / ".gitignore"
            ignore.write_text(ignore.read_text() + "\ntools/.internal/\n")
        else:
            private_tree(chosen, ignored=phase != "not-ignored")
        if phase == "tracked":
            chosen.repository.git_command("add", "-f", "tools/.internal/scripts/tool.py")
        if phase == "uncontained":
            args["baselines"] = ()
        with pytest.raises((ValueError, OSError)):
            observe_configured_inventory_inputs(**args)


def test_every_disjoint_git_root_requires_its_own_actual_baseline(tmp_path: Path) -> None:
    """A second real Git worktree and its rows cannot disappear behind the primary root."""
    original = declared()
    extra = InventoryDomainRoot("secondary", original.roots[0].canonical_path + "/other", "git")
    complete = InventoryDomain1.build(
        domain_id=original.domain_id,
        project_id=original.project_id,
        roots=(*original.roots, extra),
        rules=original.rules,
        budget=implementation_budget(),
    )
    with selection(tmp_path / "selection", declared_domain=complete) as chosen:
        private_tree(chosen)
        ignore = chosen.repository.root / ".gitignore"
        ignore.write_text(ignore.read_text() + "other/\n")
        second = GitRepository.create(chosen.repository.root / "other")
        second.write_text("source.py", "VALUE = 7\n")
        baseline = second.commit()
        args = arguments(chosen)
        with pytest.raises(ValueError, match="complete configured Git selection"):
            observe_configured_inventory_inputs(**args)
        args["baselines"] = (*args["baselines"], InventoryGitBaseline("secondary", baseline))
        reversed_args = args.copy()
        reversed_args["baselines"] = tuple(reversed(args["baselines"]))
        with pytest.raises(ValueError, match="complete configured Git selection"):
            observe_configured_inventory_inputs(**reversed_args)
        result = observe_configured_inventory_inputs(**args)
        assert tuple(item.root.root_id for item in result.roots) == (
            "core",
            "private",
            "secondary",
        )
        selected = result.roots[2].inputs
        assert isinstance(selected, RepositoryFileInputs)
        assert selected.git.baseline_head == baseline
        assert selected.current_files[1].byte_digest
        owners = {item.canonical_path: item.root_id for item in result.path_owners}
        assert owners[extra.canonical_path + "/source.py"] == "secondary"


def test_invalid_explicit_selection_inputs_refuse_before_an_alternate_domain_can_be_chosen(
    tmp_path: Path,
) -> None:
    """Malformed complete baseline sets, host/code and actual source types cannot fall back."""
    with selection(tmp_path / "selection") as chosen:
        private_tree(chosen)
        valid = arguments(chosen)
        for baselines in (
            cast(tuple[InventoryGitBaseline, ...], []),
            cast(tuple[InventoryGitBaseline, ...], ({},)),
            (),
            valid["baselines"] + valid["baselines"],
            valid["baselines"] + (InventoryGitBaseline("other", valid["baselines"][0].head),),
        ):
            args = valid.copy()
            args["baselines"] = baselines
            with pytest.raises(ValueError):
                observe_configured_inventory_inputs(**args)
        args = valid.copy()
        args["budget"] = cast(PolicyReadBudget1, {})
        with pytest.raises(ValueError, match="policy read budget"):
            observe_configured_inventory_inputs(**args)
        args = valid.copy()
        args["runner"] = cast(GitRunner, {})
        with pytest.raises(ValueError, match="actual Git runner"):
            observe_configured_inventory_inputs(**args)
        args = valid.copy()
        args["implementation"] = cast(OwnerImplementationSnapshot, {})
        with pytest.raises(ValueError, match="complete inventory implementation"):
            observe_configured_inventory_inputs(**args)
        args = valid.copy()
        args["implementation"] = replace(valid["implementation"], implementation_digest="0" * 64)
        with pytest.raises(ValueError, match="implementation or source identity changed"):
            observe_configured_inventory_inputs(**args)
        args = valid.copy()
        args["monorepo_root"] = Path("relative")
        with pytest.raises(ValueError, match="host monorepo root"):
            observe_configured_inventory_inputs(**args)
        args = valid.copy()
        args["domain_source"] = cast(RetainedContextSource, {})
        with pytest.raises(ValueError, match="actual retained"):
            observe_configured_inventory_inputs(**args)
        with pytest.raises(ValueError):
            InventoryGitBaseline("core", "abbreviated")
        with pytest.raises(ValueError):
            InventoryGitBaseline("bad identity", valid["baselines"][0].head)


def test_all_directory_roots_and_root_directory_references_obey_the_combined_reference_ceiling(
    tmp_path: Path,
) -> None:
    """Distinct actual empty roots are counted even when they carry no file rows."""
    base = domain().roots[0].canonical_path + "/generated"
    roots = tuple(
        InventoryDomainRoot(f"root{index:04}", f"{base}/root{index:04}", "generated")
        for index in range(1024)
    )
    complete = InventoryDomain1.build(
        domain_id="all-generated",
        project_id="PROJECT-A",
        roots=roots,
        rules=(),
        budget=implementation_budget(),
    )
    with selection(tmp_path / "selection", declared_domain=complete) as chosen:
        for root in roots:
            (chosen.arguments["monorepo_root"] / root.canonical_path).mkdir(parents=True)
        (chosen.arguments["monorepo_root"] / roots[-1].canonical_path / "extra").write_bytes(b"x")
        args = arguments(chosen)
        args["baselines"] = ()
        args["budget"] = implementation_budget(max_references=1024)
        with pytest.raises(ValueError, match="path ownership exceeds the reference budget"):
            observe_configured_inventory_inputs(**args)


def test_combined_capture_exact_byte_boundary_includes_late_ignore_diagnostics(
    tmp_path: Path,
) -> None:
    """A real Git delegate's extra diagnostic cannot escape an exhausted enclosing limit."""
    with selection(tmp_path / "selection") as chosen:
        private_tree(chosen)
        chosen.repository.write_bytes("large.bin", b"x" * (4 * 1024**2))
        baseline = chosen.repository.commit()
        args = arguments(chosen)
        args["baselines"] = (InventoryGitBaseline("core", baseline),)
        original = observe_configured_inventory_inputs(**args)
        args["budget"] = implementation_budget(
            max_total_source_bytes=original.file_source_bytes_read
        )
        assert observe_configured_inventory_inputs(**args).roots == original.roots
        short = args.copy()
        short["budget"] = implementation_budget(
            max_total_source_bytes=original.file_source_bytes_read - 1
        )
        with pytest.raises((ValueError, RuntimeError)):
            observe_configured_inventory_inputs(**short)
        tools = tmp_path / "tools"
        tools.mkdir()
        executable = tools / "git"
        marker = tmp_path / "first-ignore"
        executable.write_text(
            "#!/bin/sh\ncase \" $* \" in\n*' check-ignore '*)\n"
            '/usr/bin/git "$@"\nresult=$?\n'
            f"if [ -e {shlex.quote(str(marker))} ]; then printf x >&2; "
            f"else printf first > {shlex.quote(str(marker))}; fi\n"
            'exit $result;;\n*) exec /usr/bin/git "$@";;\nesac\n'
        )
        executable.chmod(0o755)
        args["runner"] = GitRunner(GitTrustPolicy(trusted_roots=(str(tools),)))
        with pytest.raises(ValueError, match="combined input budget"):
            observe_configured_inventory_inputs(**args)


def test_later_git_root_cannot_borrow_bytes_after_the_first_capture_exhausts_the_total(
    tmp_path: Path,
) -> None:
    """Actual disjoint Git metadata needs a nonzero remaining allocation."""
    original = declared()
    second_root = InventoryDomainRoot(
        "secondary", original.roots[0].canonical_path + "/other", "git"
    )
    complete = InventoryDomain1.build(
        domain_id=original.domain_id,
        project_id=original.project_id,
        roots=(original.roots[0], second_root),
        rules=tuple(rule for rule in original.rules if rule.root_id == "core"),
        budget=implementation_budget(),
    )
    with selection(tmp_path / "selection", declared_domain=complete) as chosen:
        ignore = chosen.repository.root / ".gitignore"
        ignore.write_text(ignore.read_text() + "\nother/\n")
        chosen.repository.write_bytes("large.bin", b"x" * (4 * 1024**2))
        baseline = chosen.repository.commit()
        second = GitRepository.create(chosen.repository.root / "other")
        second_baseline = second.commit()
        first = observe_repository_file_inputs(
            chosen.repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=implementation_budget(),
        )
        args = arguments(chosen)
        args["baselines"] = (
            InventoryGitBaseline("core", baseline),
            InventoryGitBaseline("secondary", second_baseline),
        )
        args["budget"] = implementation_budget(max_total_source_bytes=first.source_bytes_read)
        with pytest.raises(ValueError, match="configured Git inputs exhaust"):
            observe_configured_inventory_inputs(**args)


def test_actual_empty_generated_root_can_use_zero_remaining_bytes_and_entries(
    tmp_path: Path,
) -> None:
    """An actual empty directory remains captured after a Git transaction uses its last byte."""
    with selection(tmp_path / "selection", declared_domain=declared(kind="generated")) as chosen:
        private = chosen.repository.root / "tools/.internal"
        private.mkdir(parents=True)
        chosen.repository.write_bytes("large.bin", b"x" * (4 * 1024**2))
        baseline = chosen.repository.commit()
        first = observe_repository_file_inputs(
            chosen.repository.root,
            baseline_head=baseline,
            runner=GitRunner(),
            budget=implementation_budget(),
        )
        args = arguments(chosen)
        args["baselines"] = (InventoryGitBaseline("core", baseline),)
        args["budget"] = implementation_budget(max_total_source_bytes=first.source_bytes_read)
        result = observe_configured_inventory_inputs(**args)
        last = result.roots[-1].inputs
        assert isinstance(last, DirectoryFileInputs)
        assert last.files == () and last.directories == () and last.source_bytes_read == 0
        assert result.file_source_bytes_read == first.source_bytes_read


def test_combined_current_entry_ceiling_cannot_be_restarted_for_each_root(tmp_path: Path) -> None:
    """Real roots that fit separately refuse when their combined topology exceeds the ceiling."""
    with selection(tmp_path / "selection") as chosen:
        private_tree(chosen)
        for index in range(600):
            chosen.repository.write_text(f"bulk/file{index:04}", "")
            chosen.repository.write_text(f"tools/.internal/scripts/file{index:04}", "")
        args = arguments(chosen)
        args["budget"] = implementation_budget(max_sources=1024)
        with pytest.raises(ValueError, match="entry budget"):
            observe_configured_inventory_inputs(**args)


@pytest.mark.parametrize(
    ("phase", "message"),
    (
        ("file-overlap", "roots disagree on current file inputs"),
        ("topology-overlap", "roots disagree on file and directory topology"),
        ("implementation", "implementation changed during observation"),
        ("host-root", "host monorepo directory object changed"),
    ),
)
def test_actual_configured_source_and_host_changes_refuse(
    tmp_path: Path, phase: str, message: str
) -> None:
    """Actual source/code/root mutations exercise the complete public collection boundary."""
    with selection(tmp_path / "selection", declared_domain=declared(kind="generated")) as chosen:
        private = chosen.repository.root / "tools/.internal"
        if phase == "topology-overlap":
            source = chosen.repository.write_text("tools/.internal", "before")
        else:
            source = private_tree(chosen, ignored=False)
        import rigor_foundry.configured_inventory_inputs as production

        canonical = Path(production.__file__).parent
        code_parent = tmp_path / "code"
        copied = code_parent / "rigor_foundry"
        shutil.copytree(canonical, copied, ignore=shutil.ignore_patterns("__pycache__"))
        for original in canonical.rglob("*"):
            if original.is_file() and "__pycache__" not in original.parts:
                assert (
                    copied / original.relative_to(canonical)
                ).read_bytes() == original.read_bytes()
        host = chosen.arguments["monorepo_root"]
        alternate = tmp_path / "alternate-host"
        if phase == "host-root":
            shutil.copytree(host, alternate, symlinks=True)
        changed = False
        private_opens = 0
        data_seen = False

        def mutate(stop: SyscallStop) -> bool:
            """Mutate only real fixture objects at the selected owned-child syscall stop."""
            nonlocal changed, private_opens, data_seen
            if stop.entering and stop.number == 257 and stop.path == str(private):
                private_opens += 1
            if (
                not stop.entering
                and stop.number == 0
                and stop.path == str(source)
                and stop.result == 0
            ):
                data_seen = True
            overlap = phase in {"file-overlap", "topology-overlap"}
            selected = (
                overlap
                and stop.entering
                and stop.number == 257
                and stop.path == str(private)
                and private_opens == 3
            ) or (
                not overlap
                and data_seen
                and stop.entering
                and stop.number == 257
                and stop.path == str(copied)
            )
            if not changed and selected:
                if phase == "file-overlap":
                    source.write_text("VALUE = 9\n")
                elif phase == "topology-overlap":
                    private.rename(tmp_path / "retained-file")
                    private.mkdir()
                elif phase == "implementation":
                    with (copied / "__init__.py").open("a") as handle:
                        handle.write("\n# owned fixture input changed\n")
                else:
                    host.rename(tmp_path / "retained-host")
                    alternate.rename(host)
                changed = True
            return False

        config = {
            "host": str(host),
            "baseline": chosen.arguments["baseline_head"],
            "budget": chosen.arguments["budget"].to_dict(),
            "paths": [str(path) for path in chosen.paths],
            "references": [ref.to_dict() for ref in chosen.references],
        }
        worker = """
import hashlib,json,sys
from contextlib import ExitStack
from pathlib import Path
sys.path.insert(0,sys.argv[1]);sys.path.insert(1,sys.argv[2])
from project_registry_syscall_scheduler import arm_native_trace
from rigor_foundry.configured_inventory_inputs import InventoryGitBaseline,observe_configured_inventory_inputs
from rigor_foundry.context_owner_implementation import observe_owner_implementation
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.typed_object_reference import TypedObjectRef1
config=json.loads(sys.argv[3]);budget=PolicyReadBudget1.from_dict(config['budget'])
code=observe_owner_implementation(Path(sys.argv[1])/'rigor_foundry',budget=budget)
stack=ExitStack()
sources=[stack.enter_context(RetainedContextSource(Path(path),reference=TypedObjectRef1.from_dict(ref),raw_digest=hashlib.sha256(Path(path).read_bytes()).hexdigest(),budget=budget)) for path,ref in zip(config['paths'],config['references'],strict=True)]
runner=GitRunner();arm_native_trace()
try:
    observe_configured_inventory_inputs(baselines=(InventoryGitBaseline('core',config['baseline']),),monorepo_root=Path(config['host']),domain_source=sources[0],registry_source=sources[1],contract_source=sources[2],implementation=code,runner=runner,budget=budget)
except (ValueError,RuntimeError,OSError) as exc:
    outcome={'accepted':False,'error':str(exc)}
else:
    outcome={'accepted':True}
stack.close()
print(json.dumps(outcome))
"""
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
        write_trace(tmp_path / "configured-input-trace.json", result)
        assert result.returncode == 0, result.stderr
        assert changed, "selected real native boundary was not observed"
        outcome = json.loads(result.stdout)
        assert outcome["accepted"] is False
        assert message in outcome["error"]
        for original in canonical.rglob("*"):
            if not original.is_file() or "__pycache__" in original.parts:
                continue
            actual = copied / original.relative_to(canonical)
            if original == canonical / "__init__.py":
                assert ast.dump(ast.parse(actual.read_text())) == ast.dump(
                    ast.parse(original.read_text())
                )
            else:
                assert actual.read_bytes() == original.read_bytes()
