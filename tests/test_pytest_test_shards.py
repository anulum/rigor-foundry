# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Actual pytest partition semantics
"""Exercise real final collection, preserved fixtures and refusal of selectors."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_run_test_shard import execute_shard, shard_environment, shard_repository

from tools.test_shard_evidence import read_record, validate_observations


@pytest.mark.parametrize("hook", ["finish", "late-registered-wrapper"])
def test_actual_final_collection_has_disjoint_complete_parameterized_shards(
    tmp_path: Path,
    hook: str,
) -> None:
    """All partitions observe late collection ordering and execute original items.

    Parameters
    ----------
    tmp_path : Path
        Actual independent fixture root.
    hook : str
        Final collection hook used to reorder the actual item inventory.
    """
    root = shard_repository(tmp_path)
    record_final = '        Path("final-items.json").write_text(json.dumps([item.nodeid for item in session.items]))\n'
    if hook == "finish":
        collection_hook = (
            "def pytest_collection_finish(session):\n"
            "        session.items.reverse()\n" + record_final
        )
    else:
        collection_hook = (
            "class LateWrapper:\n"
            "    @pytest.hookimpl(wrapper=True, tryfirst=True)\n"
            "    def pytest_collection(self, session):\n"
            "        result = yield\n"
            "        session.items.reverse()\n" + record_final + "        return result\n"
            "@pytest.hookimpl(trylast=True)\n"
            "def pytest_configure(config):\n"
            '    config.pluginmanager.register(LateWrapper(), "late-registered-wrapper")\n'
        )
    (root / "conftest.py").write_text(
        "import json, pytest\nfrom pathlib import Path\n" + collection_hook
    )
    control = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q"],
        cwd=root,
        env=shard_environment(root),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert control.returncode == 0, control.stdout + control.stderr
    complete: list[str] = json.loads((root / "final-items.json").read_text())
    seen: list[str] = []
    for index in range(4):
        result = execute_shard(root, index)
        assert result.returncode == 0, result.stdout + result.stderr
        directory = root / ".rigor-test-shard"
        record = json.loads((directory / "observations.json").read_text())
        assert record["collected"] == complete
        assert record["selected"] == complete[index::4]
        assert all("::TestDispatch::test_dispatch[" in item for item in complete)
        seen.extend(record["selected"])
        directory.rename(root / f"retained-{index}")
    assert len(seen) == len(set(seen)) == len(complete) == 4
    assert complete[0].endswith("[version1]")
    assert complete[-1].endswith("[version0]")


@pytest.mark.parametrize(
    "selector",
    [
        "--collect-only",
        "-x",
        "-k nonexistent",
        "-m nonexistent",
        "--lf",
        "--ff",
        "--nf",
        "--sw",
        "--deselect=tests/test_dispatch.py::missing",
        "--ignore=other",
        "--ignore-glob=other*",
        "--pyargs",
        "--keep-duplicates",
    ],
)
def test_real_selection_and_early_exit_options_cannot_produce_a_receipt(
    tmp_path: Path, selector: str
) -> None:
    """Actual pytest configuration filters are rejected before partition admission.

    Parameters
    ----------
    tmp_path : Path
        Actual fixture root.
    selector : str
        Forbidden complete-collection configuration option.
    """
    root = shard_repository(tmp_path)
    config = root / "pyproject.toml"
    config.write_text(
        config.read_text().replace("--strict-markers", "--strict-markers " + selector)
    )
    result = execute_shard(root)
    assert result.returncode != 0
    assert "complete test shard invocation required" in result.stderr
    assert not (root / ".rigor-test-shard/receipt.json").exists()


@pytest.mark.parametrize("case", ["duplicate", "empty", "missing-arguments", "selected-file"])
def test_actual_collection_refuses_duplicates_empty_partitions_and_partial_commands(
    tmp_path: Path, case: str
) -> None:
    """No duplicate, absent or manually selected inventory qualifies as complete.

    Parameters
    ----------
    tmp_path : Path
        Actual fixture root.
    case : str
        Actual collection or command defect.
    """
    root = shard_repository(tmp_path)
    if case == "duplicate":
        (root / "conftest.py").write_text(
            "def pytest_collection_finish(session):\n    session.items.append(session.items[0])\n"
        )
        result = execute_shard(root)
        assert "duplicate collected test identity" in result.stdout + result.stderr
    elif case == "empty":
        result = execute_shard(root, 9, 10)
        assert "empty test shard" in result.stdout + result.stderr
    else:
        args = [sys.executable, "-m", "pytest", "-p", "tools.pytest_test_shards"]
        if case == "selected-file":
            args.extend(
                [
                    "tests/test_dispatch.py",
                    "--test-shard-index=0",
                    "--test-shard-count=4",
                    "--test-shard-observations=observations.json",
                ]
            )
        result = subprocess.run(
            args, cwd=root, env=shard_environment(root), capture_output=True, text=True, timeout=30
        )
        assert "complete test shard invocation required" in result.stderr
    assert result.returncode != 0
    assert not (root / ".rigor-test-shard/receipt.json").exists()


def test_existing_skip_xfail_and_nested_unsharded_pytest_semantics(tmp_path: Path) -> None:
    """Real existing outcomes complete normally and children receive no shard flags.

    Parameters
    ----------
    tmp_path : Path
        Actual fixture root.
    """
    root = shard_repository(tmp_path)
    (root / "tests/test_dispatch.py").write_text(
        (root / "tests/test_dispatch.py").read_text()
        + '\n@pytest.mark.skip(reason="fixture platform case")\ndef test_skipped():\n    pass\n'
        + '@pytest.mark.xfail(reason="fixture expected failure", strict=True)\ndef test_expected():\n    assert False\n'
        + "def test_nested(tmp_path):\n"
        + '    p = tmp_path / "test_child.py"\n'
        + '    p.write_text("def test_first():\\n    pass\\ndef test_second():\\n    pass\\n")\n'
        + '    child = subprocess.run([sys.executable, "-m", "pytest", str(p), "-q", "--noconftest"], capture_output=True, text=True)\n'
        + "    assert child.returncode == 0, child.stdout + child.stderr\n"
        + '    assert "2 passed" in child.stdout\n'
    )
    result = execute_shard(root, count=1)
    assert result.returncode == 0, result.stdout + result.stderr
    record = json.loads((root / ".rigor-test-shard/observations.json").read_text())
    assert len(record["selected"]) == 7
    outcomes = [
        phases
        for phases in record["phases"].values()
        if ["setup", "skipped"] in phases or ["call", "skipped"] in phases
    ]
    assert len(outcomes) == 2


@pytest.mark.parametrize("case", ["complete", "duplicate", "empty"])
def test_public_pytest_entrypoint_observes_real_collection_and_terminal_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Exercise the plugin through pytest's public API under outer quality coverage.

    Parameters
    ----------
    tmp_path : Path
        Actual independent pytest repository.
    monkeypatch : pytest.MonkeyPatch
        Set only the real current directory for this nested pytest invocation.
    case : str
        Complete actual execution, duplicate collection or an empty partition.
    """
    root = shard_repository(tmp_path)
    (root / "tests/test_dispatch.py").write_text(
        "import pytest\nclass TestCases:\n"
        '    @pytest.mark.parametrize("value", [0, 1])\n'
        "    def test_parameter(self, value):\n        assert value in {0, 1}\n"
        '@pytest.mark.skip(reason="existing fixture platform case")\ndef test_platform():\n    pass\n'
        '@pytest.mark.xfail(reason="existing expected outcome", strict=True)\ndef test_expected():\n    assert False\n'
    )
    if case == "duplicate":
        (root / "conftest.py").write_text(
            "def pytest_collection_finish(session):\n    session.items.append(session.items[0])\n"
        )
    monkeypatch.chdir(root)
    index = 9 if case == "empty" else 0
    count = 10 if case == "empty" else 1
    result = pytest.main(
        [
            "tests",
            "-q",
            "--import-mode=importlib",
            "-p",
            "tools.pytest_test_shards",
            f"--test-shard-index={index}",
            f"--test-shard-count={count}",
            "--test-shard-observations=observations.json",
        ]
    )
    if case == "complete":
        assert result == 0
        assert len(validate_observations(read_record(root / "observations.json"), 0, 1)) == 4
    else:
        assert result != 0
