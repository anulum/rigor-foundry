# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distributed CI source reader tests
"""Exercise real workflow files and refuse ambiguous category projections."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from workflow_dump_references import yaml_dump_references

from tools._repository import ROOT
from tools.ci_workflows import CI_CATEGORY_JOBS, CI_WORKFLOWS, ci_jobs, read_workflow

WORKFLOW_TEST_FILES = (
    "test_ci_workflows.py",
    "test_check_ci_workflows.py",
    "test_ci_editor_workflows.py",
    "test_ci_native_workflows.py",
)


def write_workflow(path: Path, document: object) -> None:
    """Write one parsed workflow back in its own key order.

    The text-based workflow guards read the file as written, so a key-sorting rewrite alone
    already breaks an unchanged workflow and would let every mutation case pass whatever it
    changed. Every workflow round trip in the workflow tests goes through this one writer.

    Parameters
    ----------
    path : Path
        Workflow file to replace.
    document : object
        Parsed workflow, possibly changed by the test.
    """
    path.write_text(yaml.safe_dump(document, sort_keys=False))


def copy_workflow_repository(destination: Path) -> Path:
    """Copy actual inventory, workflows, owners and guard sources.

    Parameters
    ----------
    destination : Path
        Empty independent repository directory.

    Returns
    -------
    Path
        Repository with byte-identical current workflow and guard inputs.
    """
    for relative in (
        ".github/ci-workflows.json",
        ".github/CODEOWNERS",
        "pyproject.toml",
        "tools/__init__.py",
        "tools/_repository.py",
        "tools/ci_workflows.py",
        "tools/ci_native_workflows.py",
        "tools/ci_editor_workflows.py",
        "tools/check_ci_workflows.py",
        "tools/check_action_pins.py",
        "editors/vscode/native/editor-hosts.json",
        ".github/actions/install-editor-host/action.yml",
        *[str(path.relative_to(ROOT)) for path in (ROOT / ".github/workflows").glob("*.yml")],
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return destination


def test_category_projection_reads_all_actual_jobs_and_caller_needs(tmp_path: Path) -> None:
    """Resolve the whole actual graph from an independent unchanged source copy.

    Parameters
    ----------
    tmp_path : Path
        Independent copied repository.
    """
    root = copy_workflow_repository(tmp_path)
    jobs = ci_jobs(root)
    assert list(jobs) == [job for names in CI_CATEGORY_JOBS.values() for job in names]
    for name, relative in CI_WORKFLOWS.items():
        for identifier in CI_CATEGORY_JOBS[name]:
            actual = read_workflow(root / relative)["jobs"][identifier]
            if name == "coverage":
                assert jobs[identifier] == {
                    **actual,
                    "needs": [
                        "native",
                        "native-primary",
                        "native-quality",
                        "test",
                        "test-coverage",
                    ],
                }
            else:
                assert jobs[identifier] == actual
    assert jobs["test"]["strategy"]["matrix"]["python-version"] == [
        "3.11.15",
        "3.12.13",
        "3.13.14",
    ]
    assert jobs["test"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3, 4, 5, 6, 7]
    assert jobs["test-coverage"]["needs"] == ["native", "native-primary", "native-quality", "test"]


@pytest.mark.parametrize(
    "text",
    ["[", "[]", "jobs: {}\njobs: {}", "on: !!python/object:a {}", "on: {}\ntrue: {}", "true: {}"],
)
def test_reader_refuses_ambiguous_or_nonmapping_yaml(tmp_path: Path, text: str) -> None:
    """Reject real invalid sources without silently projecting a partial mapping.

    Parameters
    ----------
    tmp_path : Path
        Actual file directory.
    text : str
        Invalid YAML input.
    """
    path = tmp_path / "workflow.yml"
    path.write_text(text)
    with pytest.raises(ValueError):
        read_workflow(path)


def test_reader_retains_literal_events_and_refuses_links(tmp_path: Path) -> None:
    """Interpret literal GitHub keys and keep source authority at the actual file.

    Parameters
    ----------
    tmp_path : Path
        Actual file directory.
    """
    path = tmp_path / "workflow.yml"
    path.write_text("on:\n  push:\njobs: {}\n")
    assert read_workflow(path) == {"on": {"push": None}, "jobs": {}}
    path.write_text("jobs: {}\n")
    assert read_workflow(path) == {"jobs": {}}
    link = tmp_path / "linked.yml"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="linked"):
        read_workflow(link)
    with pytest.raises(OSError):
        read_workflow(tmp_path / "absent.yml")


@pytest.mark.parametrize(
    ("relative", "replacement"),
    [
        (".github/workflows/ci.yml", {}),
        (".github/workflows/ci.yml", {"jobs": []}),
        (".github/workflows/ci.yml", {"jobs": {}}),
        (CI_WORKFLOWS["quality"], {"jobs": []}),
        (CI_WORKFLOWS["quality"], {"jobs": {}}),
        (CI_WORKFLOWS["quality"], {"jobs": {"quality": {}, "other": {}}}),
        (CI_WORKFLOWS["quality"], {"jobs": {"quality": None}}),
        (CI_WORKFLOWS["quality"], {"jobs": {"quality": {"uses": "./another.yml"}}}),
    ],
)
def test_category_projection_refuses_incomplete_real_graph(
    tmp_path: Path,
    relative: str,
    replacement: dict[str, object],
) -> None:
    """The compatibility reader cannot erase or redirect actual execution.

    Parameters
    ----------
    tmp_path : Path
        Independent copied repository.
    relative : str
        Actual graph input to replace.
    replacement : dict[str, object]
        Structurally invalid graph document.
    """
    root = copy_workflow_repository(tmp_path)
    write_workflow(root / relative, replacement)
    with pytest.raises(ValueError):
        ci_jobs(root)


def test_every_workflow_rewrite_goes_through_the_order_preserving_writer() -> None:
    """The only YAML dump reference in the workflow tests is the one inside the writer.

    A direct key-sorting dump would make a new mutation case vacuous again, so no workflow
    test may reference a dump function in any form except ``write_workflow`` itself.
    """
    uses = [
        use
        for name in WORKFLOW_TEST_FILES
        for use in yaml_dump_references((ROOT / "tests" / name).read_text(encoding="utf-8"), name)
    ]
    assert uses == [("test_ci_workflows.py", "write_workflow")]


@pytest.mark.parametrize(
    "snippet",
    [
        "import yaml\n_x = lambda d: yaml.safe_dump(d)\n",
        "import yaml\n_x = lambda d: yaml.safe_dump_all([d])\n",
        "import yaml\n_x = lambda d: yaml.dump_all([d])\n",
        "import yaml as y\n_x = lambda d: y.dump(d)\n",
        "from yaml import dump\n_x = lambda d: dump(d)\n",
        "import yaml\n_x = lambda d: getattr(yaml, 'safe_dump')(d)\n",
        "_x = lambda d: __import__('yaml').safe_dump(d)\n",
        "from yaml import SafeDumper\n",
    ],
)
def test_each_dump_form_outside_the_writer_is_found(snippet: str) -> None:
    """Every ordinary way to dump YAML is reported, while ``json.dump`` on ``json`` is not.

    Parameters
    ----------
    snippet : str
        Module-level code that dumps YAML without the writer.
    """
    assert yaml_dump_references("import json\n_y = lambda d, f: json.dump(d, f)\n", "ok.py") == []
    assert ("probe.py", "<module>") in yaml_dump_references(snippet, "probe.py")
