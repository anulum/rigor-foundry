# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — import-profile runs behind the attested write bound, with real tools
"""Verify the bounded import-profile run with real Semgrep, and that the 3 profiles stay unchanged."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from repository_audit_git_repository import GitRepository
from test_adapter_profiles import _write_osv_database

from rigor_foundry import adapters, sarif_import_execution
from rigor_foundry.adapter_profiles import profile_by_name
from rigor_foundry.adapter_runtime import SANDBOX_TOOL, ProcessOutput, stream_process
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.launcher_provenance import PrlimitProvenance, _handle, inspect_prlimit
from rigor_foundry.policy_models import AdapterSpec
from rigor_foundry.sarif_import import import_executed_sarif
from rigor_foundry.sarif_import_binding import verify_executed_binding
from rigor_foundry.sarif_import_channel import SecondOutputChannel
from rigor_foundry.sarif_import_document import MAX_SARIF_BYTES, SarifImportRefused
from rigor_foundry.sarif_import_execution import (
    FILE_SIZE_CAP,
    LAUNCH_VECTOR_VERSION,
    SecondOutputRun,
    run_import_profile,
)
from rigor_foundry.sarif_import_profile import import_profile_by_name

PROFILE = import_profile_by_name("semgrep-local-sarif-import-v1")
RULES = (
    "rules:\n"
    "  - id: rigor-fixture-eval\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    message: Dynamic evaluation of an expression argument.\n"
    "    pattern: eval($X)\n"
)
Calls = list[tuple[tuple[str, ...], tuple[int, ...]]]


def _record(monkeypatch: pytest.MonkeyPatch) -> Calls:
    """Record every sandboxed launch and its inherited descriptors, then run it for real."""
    calls: Calls = []
    real: Callable[..., ProcessOutput] = stream_process

    def recording(command: tuple[str, ...], **options: Any) -> ProcessOutput:
        calls.append((command, tuple(options["pass_fds"])))
        return real(command, **options)

    monkeypatch.setattr(adapters, "stream_process", recording)
    return calls


def _spec(name: str, profile: str, configuration: str, target: str) -> AdapterSpec:
    """Return one parsed built-in profile declaration."""
    return AdapterSpec.from_dict(
        {
            "name": name,
            "profile": profile,
            "configuration_path": configuration,
            "target_paths": [target],
            "timeout_seconds": 120,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )


def _semgrep_repository(root: Path) -> GitRepository:
    """Commit a repository with one Semgrep rule and one finding."""
    repository = GitRepository.create(root)
    repository.write_text("security/semgrep.yml", RULES)
    repository.write_text("src/app/core.py", "VALUE = 1\n")
    repository.write_text(
        "src/app/settings.py", "def run(expression):\n    return eval(expression)\n"
    )
    repository.commit()
    return repository


def _assert_unchanged_launch(calls: Calls, spec: AdapterSpec) -> tuple[str, ...]:
    """Return the built-in arguments after checking the one audit launch is exactly its vector."""
    assert spec.profile is not None and spec.configuration_path is not None
    expected = profile_by_name(spec.profile).command_arguments(
        f"/workspace/{spec.configuration_path}",
        tuple(f"/workspace/{target}" for target in spec.target_paths),
    )
    ((command, descriptors),) = calls
    assert command[-len(expected) - 2 :] == ("--", SANDBOX_TOOL, *expected)
    assert command[0].startswith("/proc/self/fd/") and len(descriptors) == 2
    assert not any(part.startswith(("--fsize", "--sarif-output")) for part in command)
    return expected


def test_the_three_built_in_profiles_keep_their_exact_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a second output, Semgrep, Trivy and OSV launch exactly as before the hook.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocations.
    monkeypatch : pytest.MonkeyPatch
        Records each real launch and sets the offline OSV cache.
    """
    semgrep = _semgrep_repository(tmp_path / "semgrep")
    trivy = GitRepository.create(tmp_path / "trivy")
    trivy.write_text("security/trivy.yaml", "format: json\n")
    trivy.write_text("infra/Dockerfile", "FROM alpine:3.20\nUSER root\n")
    trivy.commit()
    osv = GitRepository.create(tmp_path / "osv")
    osv.write_text("requirements.txt", "urllib3==1.26.0\n")
    _write_osv_database(osv, tmp_path / "osv-cache", "different-package")
    osv.commit()
    monkeypatch.setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", str(tmp_path / "osv-cache"))
    for repository, spec in (
        (semgrep, _spec("semgrep", "semgrep-local-json-v1", "security/semgrep.yml", "src")),
        (trivy, _spec("trivy", "trivy-repository-json-v1", "security/trivy.yaml", "infra")),
        (
            osv,
            _spec(
                "osv",
                "osv-lockfile-offline-json-v1",
                "security/osv-database.json",
                "requirements.txt",
            ),
        ),
    ):
        calls = _record(monkeypatch)
        result = adapters.run_adapter(repository.root, spec, trusted=True)
        assert result.profile_evidence is not None and result.complete, spec.name
        expected = _assert_unchanged_launch(calls, spec)
        executable = profile_by_name(spec.profile or "").executable
        assert result.command_digest == canonical_digest((executable, *expected))


def test_a_real_semgrep_run_writes_sarif_that_imports_as_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bounded run's second output binds to its JSON and imports as executed.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Records the real launch.
    """
    repository = _semgrep_repository(tmp_path / "repository")
    calls = _record(monkeypatch)
    run = run_import_profile(
        repository.root,
        PROFILE,
        configuration_path="security/semgrep.yml",
        target_paths=("src",),
        timeout_seconds=120,
    )
    ((command, descriptors),) = calls
    assert command[1:3] == (f"--fsize={FILE_SIZE_CAP}:{FILE_SIZE_CAP}", "--")
    assert command[0].startswith("/proc/self/fd/") and command[3].startswith("/proc/self/fd/")
    assert len(descriptors) == 4 and command[-2] == "src"
    assert command[-1].startswith("--sarif-output=/dev/fd/")
    assert (
        run.evidence.status == "findings" and run.launch_vector["version"] == LAUNCH_VECTOR_VERSION
    )
    inventory = load_git_inventory(repository.root)
    report, binding = import_executed_sarif(
        PROFILE,
        run.evidence,
        stdout=run.stdout,
        stderr=run.stderr,
        sarif=run.sarif,
        inventory=inventory,
        head=inventory.head,
    )
    (candidate,) = report.imported_candidates
    assert (candidate.anchor.path, candidate.anchor.line_start) == ("src/app/settings.py", 2)
    assert (
        report.provenance == "executed"
        and report.profile_evidence_digest == binding.binding_digest
    )
    assert verify_executed_binding(json.loads(binding.to_json()))["consistent_findings"] == 1


def test_a_cap_below_the_output_size_fails_the_run_instead_of_cutting_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At a 600-byte cap the tool's own write fails, so nothing is bound.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Lowers the file-size cap for this run.
    """
    repository = _semgrep_repository(tmp_path / "repository")
    monkeypatch.setattr(sarif_import_execution, "FILE_SIZE_CAP", 600)
    with pytest.raises(SarifImportRefused) as refused:
        run_import_profile(
            repository.root,
            PROFILE,
            configuration_path="security/semgrep.yml",
            target_paths=("src",),
            timeout_seconds=120,
        )
    assert refused.value.reason == "incomplete-evidence"


def test_an_incomplete_run_never_reads_its_second_output(tmp_path: Path) -> None:
    """A run whose configuration is invalid is partial, so the channel is closed unread.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("security/semgrep.yml", "rules: [not, a, rule]\n")
    repository.write_text("src/app/core.py", "VALUE = 1\n")
    repository.commit()
    with pytest.raises(SarifImportRefused) as refused:
        run_import_profile(
            repository.root,
            PROFILE,
            configuration_path="security/semgrep.yml",
            target_paths=("src",),
            timeout_seconds=120,
        )
    assert refused.value.reason == "incomplete-evidence"


def test_the_bound_is_soft_and_hard_one_byte_past_the_limit_through_the_attested_launcher() -> (
    None
):
    """The wrapped vector starts with the descriptor-bound launcher and its exact bound."""
    attested = inspect_prlimit()
    assert FILE_SIZE_CAP == MAX_SARIF_BYTES + 1
    with (
        _handle(Path(attested.policy.executable_path), attested.policy) as launcher,
        SecondOutputChannel() as channel,
    ):
        run = SecondOutputRun(PROFILE, channel, launcher)
        launch, descriptors = run.wrap(("/proc/self/fd/9", "--unshare-all"), (9, 10))
        assert launch == (
            launcher.execution_path,
            f"--fsize={MAX_SARIF_BYTES + 1}:{MAX_SARIF_BYTES + 1}",
            "--",
            "/proc/self/fd/9",
            "--unshare-all",
        )
        assert descriptors == (9, 10, launcher.descriptor, channel.descriptor)
        assert (
            run.command_arguments("/workspace/r.yaml", ("src",))[-1]
            == f"--sarif-output={channel.path}"
        )


def _answering(answers: list[PrlimitProvenance]) -> Callable[..., PrlimitProvenance]:
    """Return an inspection that gives the listed attestations in order."""
    sequence = iter(answers)

    def inspect(*_: object) -> PrlimitProvenance:
        return next(sequence)

    return inspect


def test_a_launcher_that_is_not_the_attested_one_refuses_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A launcher whose bytes differ from the attestation, before or after the run, is refused.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Replaces the attestation the run compares the launcher with.
    """
    repository = _semgrep_repository(tmp_path / "repository")
    real = inspect_prlimit()
    other = dataclasses.replace(real, executable_digest="0" * 64)
    for answers in ([other, other], [real, other]):
        monkeypatch.setattr(sarif_import_execution, "inspect_prlimit", _answering(answers))
        with pytest.raises(SarifImportRefused) as refused:
            run_import_profile(
                repository.root,
                PROFILE,
                configuration_path="security/semgrep.yml",
                target_paths=("src",),
                timeout_seconds=120,
            )
        assert refused.value.reason == "launcher-changed"
