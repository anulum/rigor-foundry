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

from rigor_foundry.adapters import AdapterResult, run_adapter, run_native_audits
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
    assert passed.sandbox_provenance.package_name == "bubblewrap"
    assert passed.sandbox_provenance.semantic_version.startswith("0.9.")
    assert len(passed.sandbox_provenance.identity_digest) == 64
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
    assert not timed.complete
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


def test_sandbox_identity_binds_the_complete_bubblewrap_argument_contract(
    tmp_path: Path,
) -> None:
    """A public working-directory change alters the durable launcher identity."""
    repository = GitRepository.create(tmp_path / "repository")
    script = repository.write_text("controls/pass.py", "print('pass')\n")
    repository.commit()
    command = ("{python}", str(script))
    root_spec = replace(
        _spec("sandbox-contract", "unused.py"),
        command=command,
        working_directory=".",
    )
    nested_spec = replace(
        root_spec,
        working_directory="controls",
    )

    first = run_adapter(repository.root, root_spec, trusted=True)
    second = run_adapter(repository.root, nested_spec, trusted=True)

    assert first.passed
    assert second.passed
    assert first.command_digest == second.command_digest
    assert first.sandbox_digest != second.sandbox_digest


def test_adapter_evidence_parser_rejects_tampered_protocol_fields(tmp_path: Path) -> None:
    """Digest, Boolean, and derived pass fields cannot be altered after execution."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("controls/pass.py", "print('pass')\n")
    repository.commit()
    result = run_adapter(repository.root, _spec("pass", "controls/pass.py"), trusted=True)
    assert result.passed

    invalid_digest = result.to_dict()
    invalid_digest["output_digest"] = "A" * 64
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        AdapterResult.from_dict(invalid_digest)

    invalid_boolean = result.to_dict()
    invalid_boolean["required"] = 1
    with pytest.raises(ValueError, match="boolean fields"):
        AdapterResult.from_dict(invalid_boolean)

    inconsistent_pass = result.to_dict()
    inconsistent_pass["passed"] = False
    with pytest.raises(ValueError, match="passed does not match"):
        AdapterResult.from_dict(inconsistent_pass)

    changed_provenance = result.to_dict()
    provenance = dict(changed_provenance["sandbox_provenance"])
    provenance["package_version"] = "0.9.0-tampered"
    changed_provenance["sandbox_provenance"] = provenance
    with pytest.raises(ValueError, match="identity digest"):
        AdapterResult.from_dict(changed_provenance)

    unknown_field = result.to_dict()
    unknown_field["implicit_default"] = True
    with pytest.raises(ValueError, match="fields are invalid"):
        AdapterResult.from_dict(unknown_field)

    unsupported_schema = result.to_dict()
    unsupported_schema["schema_version"] = "9.0"
    with pytest.raises(ValueError, match="schema version is unsupported"):
        AdapterResult.from_dict(unsupported_schema)


def test_adapter_resolves_repository_executables_and_rejects_unsafe_paths(
    tmp_path: Path,
) -> None:
    """Repository executables run while unsafe links, modes, and directories fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    executable = repository.write_text(
        "controls/direct-control",
        "#!/usr/bin/env python3\nprint('direct-control')\n",
    )
    executable.chmod(0o755)
    repository.write_text("controls/not-executable", "plain text\n")
    outside = tmp_path / "outside-control"
    outside.write_text("#!/usr/bin/env python3\nprint('outside')\n", encoding="utf-8")
    outside.chmod(0o755)
    (repository.root / "controls/escaped-control").symlink_to(outside)
    repository.commit()

    direct = replace(
        _spec("direct", "unused.py"),
        command=("controls/direct-control",),
    )
    assert run_adapter(repository.root, direct, trusted=True).passed

    non_executable = replace(direct, name="non-executable", command=("controls/not-executable",))
    with pytest.raises(ValueError, match="not executable"):
        run_adapter(repository.root, non_executable, trusted=True)

    escaped = replace(direct, name="escaped", command=("controls/escaped-control",))
    with pytest.raises(ValueError, match="symlink escapes"):
        run_adapter(repository.root, escaped, trusted=True)

    missing_directory = replace(direct, name="missing-cwd", working_directory="missing")
    with pytest.raises(ValueError, match="working directory escapes"):
        run_adapter(repository.root, missing_directory, trusted=True)

    file_directory = replace(
        direct,
        name="file-cwd",
        working_directory="controls/direct-control",
    )
    with pytest.raises(ValueError, match="not a directory"):
        run_adapter(repository.root, file_directory, trusted=True)


def test_adapter_waits_for_process_after_output_pipes_close(tmp_path: Path) -> None:
    """A control that closes output early is still waited for and attested at exit."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "controls/close_output.py",
        "import os\nimport time\n"
        "sink = os.open('/dev/null', os.O_WRONLY)\n"
        "os.dup2(sink, 1)\nos.dup2(sink, 2)\nos.close(sink)\n"
        "time.sleep(0.2)\n",
    )
    repository.commit()

    result = run_adapter(
        repository.root,
        _spec("closed-output", "controls/close_output.py"),
        trusted=True,
    )

    assert result.passed
    assert result.returncode == 0
    assert result.output_bytes == 0


def test_adapter_timeout_kills_tree_after_output_pipes_close(tmp_path: Path) -> None:
    """Closed pipes cannot bypass the deadline or leave a descendant running."""
    repository = GitRepository.create(tmp_path / "repository")
    marker = "RIGOR_CLOSED_PIPE_CHILD_18e5b83d"
    repository.write_text(
        "controls/close_output_slow.py",
        "import os\nimport subprocess\nimport sys\nimport time\n"
        f"subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)', '{marker}'])\n"
        "os.close(1)\nos.close(2)\ntime.sleep(30)\n",
    )
    repository.commit()

    result = run_adapter(
        repository.root,
        _spec("closed-output-timeout", "controls/close_output_slow.py", timeout=1),
        trusted=True,
    )

    assert result.timed_out
    assert result.returncode == 124
    processes = subprocess.run(  # nosec B603
        ["/usr/bin/ps", "-eo", "args"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert marker not in processes.stdout
