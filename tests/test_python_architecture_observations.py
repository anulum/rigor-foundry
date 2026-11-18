# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — incremental Python architecture integration tests
"""Compare repeated installed scans against fresh processes over real Git inputs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Literal, cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.policy_models import AuditPolicy
from rigor_foundry.python_architecture_observations import observe_python_architecture

_OWNERSHIP = "AR005-no-module-named-test-owner"
_CYCLE = "AR001-first-party-import-cycle"
_DUPLICATION = "AR006-duplicate-python-implementation"
_WILDCARD = "AR002-wildcard-import-boundary"
_FIRST = "src/pkg/first.py"
_SECOND = "src/pkg/second.py"
_BODY = """def compute(value):
    result = value + 1
    result *= 2
    result -= 1
    result += 8
    return result
"""


def _fresh_scan(
    arguments: list[str], *, warning_filter: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Invoke the same installed scan command in a new interpreter."""
    return subprocess.run(
        [sys.executable, "-m", "rigor_foundry", *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=None if warning_filter is None else {**os.environ, "PYTHONWARNINGS": warning_filter},
    )


def _compare(
    repo: GitRepository,
    output: Path,
    label: str,
    base: str,
    capture: pytest.CaptureFixture[str],
) -> dict[str, object]:
    """Compare full report bytes, changed-file stdout and exit status across processes."""
    reused = output / f"{label}-reused.json"
    fresh = output / f"{label}-fresh.json"
    flags = ["scan", "--root", str(repo.root), "--changed-since", base, "--fail-on-candidates"]
    reused_exit = main([*flags, "--json-out", str(reused)])
    observed = capture.readouterr()
    process = _fresh_scan([*flags, "--json-out", str(fresh)])
    assert reused_exit in (0, 1)
    assert process.returncode == reused_exit
    assert process.stdout == observed.out
    assert process.stderr == observed.err == ""
    assert fresh.read_bytes() == reused.read_bytes()
    return cast(dict[str, object], json.loads(reused.read_bytes()))


def _findings(report: dict[str, object], rule: str) -> set[str]:
    """Read exact anchored paths from one report's candidate cohort."""
    candidates = cast(list[dict[str, object]], report["candidates"])
    return {
        str(cast(dict[str, object], candidate["anchor"])["path"])
        for candidate in candidates
        if candidate["rule_id"] == rule
    }


def test_repeated_scans_rebind_graph_ownership_and_duplicate_groups(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Adding an unchanged file's dependency changes existing findings and exact anchors."""
    repo = GitRepository.create(tmp_path / "repository", object_format="sha256")
    first = repo.write_text(_FIRST, "from .second import compute\n\n" + _BODY)
    repo.write_policy()
    base = repo.commit()
    before = _compare(repo, tmp_path, "before", base, capsys)
    assert before["git_object_format"] == "sha256"
    assert before["head"] == base
    assert _findings(before, _OWNERSHIP) == {_FIRST}
    assert _findings(before, _CYCLE) == _findings(before, _DUPLICATION) == set()

    repo.write_text(_SECOND, "import pkg.first\n\n" + _BODY)
    repo.write_text(
        "tests/test_first.py",
        "from pkg.first import compute\n\ndef test_value():\n    assert compute(0) == 9\n",
    )
    head = repo.commit("test: add import dependency and test owner")
    assert (
        repo.git_command("rev-parse", f"{base}:{_FIRST}").stdout
        == repo.git_command("rev-parse", f"{head}:{_FIRST}").stdout
    )
    after = _compare(repo, tmp_path, "after", base, capsys)
    assert _findings(after, _OWNERSHIP) == {_SECOND}
    assert _findings(after, _CYCLE) == _findings(after, _DUPLICATION) == {_FIRST}

    first.write_text("VALUE = 2\n", encoding="utf-8")
    dirty = _compare(repo, tmp_path, "dirty", base, capsys)
    assert dirty["head"] == after["head"]
    assert dirty["tracked_content_digest"] != after["tracked_content_digest"]
    assert _findings(dirty, _CYCLE) == _findings(dirty, _DUPLICATION) == set()

    repo.git_command("restore", "--", _FIRST)
    repo.git_command("mv", _SECOND, "src/pkg/relocated.py")
    moved_head = repo.commit("test: rename dependency without changing bytes")
    repo.git_command("checkout", "--detach", moved_head)
    moved = _compare(repo, tmp_path, "detached", base, capsys)
    assert moved["head"] == moved_head
    assert moved["branch"] == "HEAD"
    assert _findings(moved, _CYCLE) == set()
    assert _findings(moved, _DUPLICATION) == {_FIRST}
    assert _findings(moved, _OWNERSHIP) == {"src/pkg/relocated.py"}


def test_repeated_scans_observe_mode_policy_and_ignored_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exact live input changes survive a warm parse and the changed-files view."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text(_FIRST, _BODY)
    watched = [{"evidence_id": "state", "path": ".rigor/witness.json", "capture": "file-sha256"}]
    witness = repo.write_text(".rigor/witness.json", '{"sequence":1}\n')
    repo.write_policy(ignored_inventory=None if os.name == "nt" else watched)
    base = repo.commit()
    initial = _compare(repo, tmp_path, "initial", base, capsys)
    repo.git_command("update-index", "--chmod=+x", _FIRST)
    mode = _compare(repo, tmp_path, "mode", base, capsys)
    assert mode["tracked_content_digest"] != initial["tracked_content_digest"]
    assert mode["head"] == initial["head"]
    repo.write_policy(ignored_inventory=None if os.name == "nt" else watched, source_threshold=4)
    updated = _compare(repo, tmp_path, "policy", base, capsys)
    assert updated["policy"] != mode["policy"]
    if os.name == "nt":
        # The existing ignored-inventory reader requires POSIX descriptors.
        repo.write_policy(ignored_inventory=watched, source_threshold=4)
        arguments = ["scan", "--root", str(repo.root), "--changed-since", base]
        assert main(arguments) == 2
        observed = capsys.readouterr()
        fresh = _fresh_scan(arguments)
        assert fresh.returncode == 2
        assert fresh.stdout == observed.out == ""
        assert fresh.stderr == observed.err
        assert "platform lacks no-follow descriptor traversal" in fresh.stderr
        return
    witness.write_text('{"sequence":2}\n', encoding="utf-8")
    ignored = _compare(repo, tmp_path, "ignored", base, capsys)
    assert ignored["tracked_content_digest"] == updated["tracked_content_digest"]
    assert ignored["ignored_inventory_digest"] != updated["ignored_inventory_digest"]


def test_complete_live_binary_and_large_module_inputs(tmp_path: Path) -> None:
    """A binary file produces no observations and large text is parsed without retention."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_bytes("src/pkg/blob.py", b"\x00binary")
    repo.write_text("src/pkg/large.py", "#" + " large line" * 220 + "\nfrom math import *\n")
    repo.commit()
    current = load_git_inventory(repo.root)
    files = {item.path: item for item in current.files}
    policy_digest = AuditPolicy().policy_digest
    assert observe_python_architecture(files["src/pkg/blob.py"], "pkg.blob", policy_digest) is None
    large = observe_python_architecture(files["src/pkg/large.py"], "pkg.large", policy_digest)
    assert large is not None
    assert large.wildcard_imports == ((2, "from math import *"),)


def test_escaped_literal_preserves_python_diagnostics_on_repeated_observation(
    tmp_path: Path,
) -> None:
    """Both observations surface the original parser warning for an invalid escape."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text(_FIRST, "VALUE = '" + "\\" + "q'\n")
    repo.commit()
    inventory = load_git_inventory(repo.root)
    file = next(item for item in inventory.files if item.path == _FIRST)
    policy_digest = AuditPolicy().policy_digest
    warning = SyntaxWarning if sys.version_info >= (3, 12) else DeprecationWarning
    for _ in range(2):
        with pytest.warns(warning, match="invalid escape sequence"):
            assert observe_python_architecture(file, "pkg.first", policy_digest) is not None


def test_repeated_public_scans_follow_caller_parser_warning_filters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A warm invalid decimal warning remains visible and can reject a parse."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text(_FIRST, "from math import *\nVALUE = 2and 3\n")
    repo.write_policy()
    repo.commit()
    flags = ["scan", "--root", str(repo.root)]
    treatments: tuple[Literal["always", "error"], ...] = ("always", "always", "error", "always")
    for attempt, treatment in enumerate(treatments):
        fresh = tmp_path / f"fresh-warnings-{attempt}.json"
        repeated = tmp_path / f"repeated-warnings-{attempt}.json"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(treatment)
            status = main([*flags, "--json-out", str(repeated)])
        output = capsys.readouterr()
        process = _fresh_scan([*flags, "--json-out", str(fresh)], warning_filter=treatment)
        assert status == process.returncode == 0
        assert output.out == process.stdout
        assert output.err == ""
        diagnostics = sum(str(item.message) == "invalid decimal literal" for item in caught)
        assert diagnostics == process.stderr.count("Warning: invalid decimal literal")
        assert fresh.read_bytes() == repeated.read_bytes()
        report = cast(dict[str, object], json.loads(repeated.read_bytes()))
        expected = set() if treatment == "error" else {_FIRST}
        assert (diagnostics > 0) == bool(expected)
        assert _findings(report, _WILDCARD) == _findings(report, _OWNERSHIP) == expected


def test_observations_across_retention_capacity(tmp_path: Path) -> None:
    """Exceed the retention capacity with tracked modules and re-observe the oldest."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text(_FIRST, "from math import *\n")
    for index in range(4096):
        repo.write_text(f"src/pkg/module_{index:04d}.py", f"VALUE = {index}\n")
    repo.commit()
    first, *remaining = (
        file for file in load_git_inventory(repo.root).files if file.path.startswith("src/pkg/")
    )
    assert first.path == _FIRST
    policy_digest = AuditPolicy().policy_digest
    before = observe_python_architecture(first, "pkg.first", policy_digest)
    assert before is not None and before.wildcard_imports == ((1, "from math import *"),)
    for file in remaining:
        assert observe_python_architecture(file, f"pkg.{file.absolute_path.stem}", policy_digest)
    after = observe_python_architecture(first, "pkg.first", policy_digest)
    assert after == before and after is not before
