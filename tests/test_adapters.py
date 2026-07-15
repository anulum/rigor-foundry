# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real native audit adapter tests
"""Execute real time-bounded audit commands without shell expansion."""

from __future__ import annotations

import json
import os
import subprocess
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
    repository.write_text("controls/large.py", "print('x' * 100000)\n")
    repository.commit()

    passed = run_adapter(repository.root, _spec("pass", "controls/pass.py"), trusted=True)
    assert passed.passed
    assert passed.returncode == 0
    assert len(passed.output_digest) == 64
    assert len(passed.executable_digest) == 64
    assert len(passed.command_digest) == 64
    assert "command" not in passed.to_dict()

    failed = run_adapter(repository.root, _spec("fail", "controls/fail.py"), trusted=True)
    assert not failed.passed
    assert failed.returncode == 7

    large = run_adapter(repository.root, _spec("large", "controls/large.py"), trusted=True)
    assert not large.passed
    assert large.returncode == 125
    assert large.output_truncated
    assert large.output_bytes == 65_536


def test_adapter_enforces_real_timeout_and_repository_working_directory(
    tmp_path: Path,
) -> None:
    """A sleeping process times out and working-directory escape is rejected."""
    repository = GitRepository.create(tmp_path / "repository")
    marker = "RIGOR_CHILD_PROCESS_1f6f7bbd"
    repository.write_text(
        "controls/slow.py",
        "import subprocess\nimport sys\nimport time\n"
        f"subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)', '{marker}'])\n"
        "time.sleep(30)\n",
    )
    repository.commit()
    timed = run_adapter(
        repository.root,
        _spec("slow", "controls/slow.py", timeout=1),
        trusted=True,
    )
    assert timed.timed_out
    assert timed.returncode == 124
    assert not timed.passed
    processes = subprocess.run(  # nosec B603
        ["/usr/bin/ps", "-eo", "args"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert marker not in processes.stdout

    escaped = replace(_spec("escape", "controls/slow.py"), working_directory="../outside")
    with pytest.raises(ValueError, match="escapes"):
        run_adapter(repository.root, escaped, trusted=True)
    absent = replace(_spec("absent", "controls/slow.py"), command=("not-installed-control",))
    with pytest.raises(ValueError, match="unavailable"):
        run_adapter(repository.root, absent, trusted=True)
    outside = replace(_spec("outside", "controls/slow.py"), command=("/tmp/control",))
    with pytest.raises(ValueError, match="outside trusted"):
        run_adapter(repository.root, outside, trusted=True)


def test_adapter_requires_consent_hides_ambient_secrets_and_cannot_mutate_repository(
    tmp_path: Path,
) -> None:
    """The execution boundary is explicit, credential-free, and read-only."""
    sentinel = "RIGOR_SENTINEL_8d55f110"
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "controls/boundary.py",
        """from pathlib import Path
import os
if os.environ.get("RIGOR_AMBIENT_SECRET"):
    raise SystemExit(9)
if Path.home() != Path("/nonexistent"):
    raise SystemExit(10)
try:
    Path("forbidden-write.txt").write_text("mutation", encoding="utf-8")
except OSError:
    pass
else:
    raise SystemExit(11)
print(os.environ)
""",
    )
    repository.commit()
    spec = _spec("boundary", "controls/boundary.py")
    with pytest.raises(ValueError, match="explicit trusted consent"):
        run_adapter(repository.root, spec)
    previous = os.environ.get("RIGOR_AMBIENT_SECRET")
    os.environ["RIGOR_AMBIENT_SECRET"] = sentinel
    try:
        result = run_adapter(repository.root, spec, trusted=True)
    finally:
        if previous is None:
            del os.environ["RIGOR_AMBIENT_SECRET"]
        else:
            os.environ["RIGOR_AMBIENT_SECRET"] = previous
    serialised = json.dumps(result.to_dict(), sort_keys=True)
    assert result.passed
    assert sentinel not in serialised
    assert not (repository.root / "forbidden-write.txt").exists()


def test_native_audit_selection_is_scope_exact_and_names_are_unique(tmp_path: Path) -> None:
    """Staged and full execution select only declared scopes using real commands."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("controls/pass.py", "print('pass')\n")
    repository.commit()
    staged = _spec("staged", "controls/pass.py", scope="staged")
    full = _spec("full", "controls/pass.py", scope="full")
    both = _spec("both", "controls/pass.py", scope="both")
    with pytest.raises(ValueError, match="explicit trusted consent"):
        run_native_audits(repository.root, (staged,), "staged")
    staged_results = run_native_audits(
        repository.root,
        (staged, full, both),
        "staged",
        trusted=True,
    )
    assert tuple(item.name for item in staged_results) == ("staged", "both")
    with pytest.raises(ValueError, match="unique"):
        run_native_audits(repository.root, (staged, staged), "staged", trusted=True)
