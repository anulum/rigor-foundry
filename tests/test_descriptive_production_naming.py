# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptive production naming guard tests
"""Exercise naming enforcement through real Git-visible worktrees."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tools._repository import ROOT
from tools.check_descriptive_production_naming import descriptive_naming_errors


def _repository(root: Path) -> Path:
    """Initialise one real Git worktree for the public guard."""
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(root)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return root


def _write(root: Path, relative: str, content: str) -> None:
    """Write one visible fixture file below a real worktree."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run_guard(root: Path) -> subprocess.CompletedProcess[str]:
    """Run the public module entry point against one explicit Git worktree."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.check_descriptive_production_naming",
            "--root",
            str(root),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_real_guard_accepts_descriptive_names_standards_and_exact_severity_values(
    tmp_path: Path,
) -> None:
    """Descriptive owners, standards, rule IDs, and exact priorities remain valid."""
    root = _repository(tmp_path)
    priorities = ", ".join(f'"P{index}"' for index in range(5))
    _write(
        root,
        "src/component_evidence_store.py",
        f"SEVERITIES = ({priorities})\n"
        'RULE = "AS001-dynamic-code-execution"\n'
        'DIGEST = "SHA-256"\n',
    )
    documented_priorities = "P" + "0/P" + "1"
    warning_priority = "P" + "2"
    _write(
        root,
        "docs/sarif.md",
        f"Reviewed priorities {documented_priorities} map to SARIF error; "
        f"{warning_priority} maps to warning.\n",
    )

    assert descriptive_naming_errors(root) == []
    completed = _run_guard(root)
    assert completed.returncode == 0
    assert completed.stdout == "Descriptive naming guard passed\n"
    assert completed.stderr == ""


def test_real_guard_rejects_codes_in_paths_identifiers_runtime_text_and_docs(
    tmp_path: Path,
) -> None:
    """One scan covers path, symbol, runtime-message, and public-doc surfaces."""
    root = _repository(tmp_path)
    stage = "p" + "1"
    milestone = "G" + "4"
    _write(
        root,
        f"src/cra_{stage}_store.py",
        "class Cra" + stage.upper() + 'Store:\n    message = "CRA ' + stage.upper() + ' record"\n',
    )
    _write(root, "docs/roadmap.md", f"The {milestone} lane is public.\n")

    errors = descriptive_naming_errors(root)
    assert len(errors) >= 4
    assert any("production path" in error for error in errors)
    assert any("coded CRA identifier" in error for error in errors)
    assert any("CRA campaign stage" in error for error in errors)
    assert any("short campaign identifier" in error for error in errors)

    completed = _run_guard(root)
    assert completed.returncode == 1
    assert completed.stdout == (
        "Descriptive naming guard failed; finding details are redacted from process output.\n"
    )
    assert completed.stderr == ""
    assert stage not in completed.stdout
    assert milestone not in completed.stdout


def test_real_guard_rejects_queue_hierarchy_snake_case_and_priority_prose(
    tmp_path: Path,
) -> None:
    """Known queue forms and coded identifier segments fail without content disclosure."""
    root = _repository(tmp_path)
    queue = "BL" + "-19"
    hierarchy = "MOAT" + "-P2-A2"
    coded_constant = "MAX_" + "M" + "3_STATE"
    priority = "P" + "2"
    _write(
        root,
        "src/owners.py",
        f'{coded_constant} = 1\n# {queue}\n# priority {priority}\nNOTE = f"priority {priority}"\n',
    )
    _write(
        root,
        "src/invalid_literal.py",
        'MESSAGE = "\\x priority ' + priority + '"\n',
    )
    _write(root, "src/unparseable.py", "'''priority " + priority + "\n")
    _write(root, "docs/design.md", f"{hierarchy} enters {priority} next.\n")

    errors = descriptive_naming_errors(root)
    assert any("queue or workstream identifier" in error for error in errors)
    assert any("campaign hierarchy identifier" in error for error in errors)
    assert any("coded identifier segment" in error for error in errors)
    assert any("priority code appears in public prose" in error for error in errors)
    assert any("Python text could not be inspected" in error for error in errors)


def test_real_guard_ignores_private_ignored_state_binary_and_generated_lock_content(
    tmp_path: Path,
) -> None:
    """Private coordination and non-authored content stay outside the naming surface."""
    root = _repository(tmp_path)
    _write(root, ".gitignore", "docs/internal/\n.coverage.*\n")
    _write(root, "docs/internal/TODO.md", "G" + "8 remains private.\n")
    _write(root, ".coordination/session.md", "G" + "8 remains private.\n")
    _write(root, ".coverage.worker.M" + "4", "generated\n")
    _write(root, "asset.bin", "safe\n")
    (root / "asset.bin").write_bytes(b"\x00" + b"G" + b"4\n")
    _write(
        root,
        "editors/vscode/package-lock.json",
        '{"integrity":"' + "M" + '4"}\n',
    )

    assert descriptive_naming_errors(root) == []


def test_local_private_task_registry_rejects_an_unrecognised_future_code(
    tmp_path: Path,
) -> None:
    """A private TODO heading extends the local guard beyond built-in code families."""
    root = _repository(tmp_path)
    _write(root, ".gitignore", "docs/internal/\n")
    future_code = "ZX" + "-47"
    _write(
        root,
        "docs/internal/TODO.md",
        "- [ ] **" + future_code + " — future private owner.**\n",
    )
    _write(root, "docs/design.md", f"The {future_code} owner is public.\n")
    _write(root, f"src/{future_code.lower()}_owner.py", "VALUE = 1\n")

    errors = descriptive_naming_errors(root)
    assert any("private task registry identifier is public" in error for error in errors)
    assert any("private task registry identifier appears in a path" in error for error in errors)


def test_repository_has_no_public_internal_planning_identifier() -> None:
    """The complete current Git-visible owner surface passes its production guard."""
    assert descriptive_naming_errors() == []
