# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real native audit adapter tests
"""Execute real time-bounded audit commands without shell expansion."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapters import run_adapter, run_native_audits
from rigor_foundry.models import AdapterSpec


def _spec(name: str, script: str, *, scope: str = "full", timeout: int = 3) -> AdapterSpec:
    """Return one real Python audit adapter declaration."""
    if scope not in {"staged", "full", "both"}:
        raise ValueError("invalid test adapter scope")
    return AdapterSpec.from_dict(
        {
            "name": name,
            "command": ["{python}", script],
            "timeout_seconds": timeout,
            "scope": scope,
            "working_directory": ".",
            "required": True,
            "domains": ["application-security"],
        },
        0,
    )


def test_adapter_records_real_success_failure_and_bounded_output(tmp_path: Path) -> None:
    """Exit status and complete-output digest come from actual child processes."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "controls/pass.py",
        "import rigor_foundry\nprint('real-control-pass', rigor_foundry.__version__)\n",
    )
    repository.write_text(
        "controls/fail.py",
        "import sys\nprint('real-control-fail', file=sys.stderr)\nraise SystemExit(7)\n",
    )
    repository.write_text("controls/large.py", "print('x' * 20000)\n")
    repository.commit()

    passed = run_adapter(repository.root, _spec("pass", "controls/pass.py"))
    assert passed.passed
    assert passed.returncode == 0
    assert "real-control-pass" in passed.output_excerpt
    assert len(passed.output_digest) == 64
    assert Path(passed.command[0]) == Path(sys.executable).absolute()

    failed = run_adapter(repository.root, _spec("fail", "controls/fail.py"))
    assert not failed.passed
    assert failed.returncode == 7
    assert "real-control-fail" in failed.output_excerpt

    large = run_adapter(repository.root, _spec("large", "controls/large.py"))
    assert large.passed
    assert "output truncated" in large.output_excerpt
    assert len(large.output_excerpt) < 17000


def test_adapter_enforces_real_timeout_and_repository_working_directory(
    tmp_path: Path,
) -> None:
    """A sleeping process times out and working-directory escape is rejected."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("controls/slow.py", "import time\ntime.sleep(2)\n")
    repository.commit()
    timed = run_adapter(repository.root, _spec("slow", "controls/slow.py", timeout=1))
    assert timed.timed_out
    assert timed.returncode == 124
    assert not timed.passed

    escaped = replace(_spec("escape", "controls/slow.py"), working_directory="../outside")
    with pytest.raises(ValueError, match="escapes"):
        run_adapter(repository.root, escaped)
    absent = replace(_spec("absent", "controls/slow.py"), command=("not-installed-control",))
    with pytest.raises(ValueError, match="unavailable"):
        run_adapter(repository.root, absent)


def test_native_audit_selection_is_scope_exact_and_names_are_unique(tmp_path: Path) -> None:
    """Staged and full execution select only declared scopes using real commands."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("controls/pass.py", "print('pass')\n")
    repository.commit()
    staged = _spec("staged", "controls/pass.py", scope="staged")
    full = _spec("full", "controls/pass.py", scope="full")
    both = _spec("both", "controls/pass.py", scope="both")
    staged_results = run_native_audits(repository.root, (staged, full, both), "staged")
    assert tuple(item.name for item in staged_results) == ("staged", "both")
    with pytest.raises(ValueError, match="unique"):
        run_native_audits(repository.root, (staged, staged), "staged")
