# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — executed SARIF binding tests on a real sandboxed Semgrep run
"""Verify the binding of real sandboxed Semgrep SARIF to its JSON run, and every refusal."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapter_profiles import (
    AdapterProfileEvidence,
    ProfileName,
    ProfileReason,
    ProfileStatus,
    profile_by_name,
)
from rigor_foundry.adapter_runtime import process_output_digest, stream_process
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.git_inventory import GitInventory, load_git_inventory
from rigor_foundry.launcher_provenance import PrlimitCompatibilityPolicy, PrlimitProvenance
from rigor_foundry.rules import RULES_BY_ID, rule_pack_digest
from rigor_foundry.sarif_import import import_executed_sarif, import_sarif
from rigor_foundry.sarif_import_binding import (
    BINDING_SCHEMA,
    bind_executed_sarif,
    complete_output_digest,
    exact_version,
    json_findings,
    verify_executed_binding,
    verify_executed_import,
)
from rigor_foundry.sarif_import_document import SarifImportRefused
from rigor_foundry.sarif_import_execution import FILE_SIZE_CAP, LAUNCH_VECTOR_VERSION, ImportRun
from rigor_foundry.sarif_import_profile import ImportProfile, import_profile_by_name
from rigor_foundry.sarif_import_report import verify_import_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sarif_import"
SARIF = (FIXTURES / "semgrep-1.186.0-producer-repository.sarif").read_bytes()
STDOUT = (FIXTURES / "semgrep-1.186.0-sandboxed-json-stdout.json").read_bytes()
PROFILE = import_profile_by_name("semgrep-local-sarif-import-v1")
LAUNCHER = PrlimitProvenance(
    policy=PrlimitCompatibilityPolicy(),
    executable_digest="4" * 64,
    semantic_version="2.39.3",
    package_query_digest="5" * 64,
    package_version="2.39.3-9ubuntu6.6",
    package_architecture="amd64",
    capability_digest="6" * 64,
)


def _evidence(
    stdout: bytes = STDOUT,
    stderr: bytes = b"",
    *,
    profile: ProfileName = "semgrep-local-json-v1",
    findings: int = 1,
    tool_version: str = "1.186.0",
    status: ProfileStatus = "findings",
    reason: ProfileReason = "findings",
) -> AdapterProfileEvidence:
    """Build the base profile evidence of one complete run whose exact output is given."""
    return AdapterProfileEvidence.build(
        profile=profile_by_name(profile),
        status=status,
        reason=reason,
        tool_version=tool_version,
        version_output_digest="1" * 64,
        configuration_digest="2" * 64,
        input_digest="3" * 64,
        output_digest=complete_output_digest(stdout, stderr),
        finding_count=findings,
        scanned_target_count=2,
    )


def _run(inventory: GitInventory, **changes: Any) -> ImportRun:
    """Return the recorded real run of the import profile on the inventory's content."""
    run = ImportRun(
        PROFILE, _evidence(), STDOUT, b"", SARIF, LAUNCHER, inventory.tracked_content_digest
    )
    return dataclasses.replace(run, **changes)


@pytest.fixture
def inventory(tmp_path: Path) -> GitInventory:
    """Commit the producer repository that the sandboxed run scanned.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.

    Returns
    -------
    GitInventory
        Its verified inventory.
    """
    repository = GitRepository.create(tmp_path / "repository")
    manifest = json.loads((FIXTURES / "producer-repository.json").read_text(encoding="utf-8"))
    for relative, text in manifest["files"].items():
        repository.write_text(relative, text)
    repository.commit("fixture: producer repository")
    return load_git_inventory(repository.root)


def test_the_real_sandboxed_run_imports_as_executed_and_its_binding_verifies(
    inventory: GitInventory,
) -> None:
    """The run's SARIF binds to its JSON, and the executed report cites the binding."""
    digest, registered = rule_pack_digest(), dict(RULES_BY_ID)
    report, binding = import_executed_sarif(
        _run(inventory), inventory=inventory, head=inventory.head
    )
    assert (report.provenance, report.profile_evidence_digest) == (
        "executed",
        binding.binding_digest,
    )
    assert verify_import_report(json.loads(report.to_json()))["provenance"] == "executed"
    record = verify_executed_binding(json.loads(binding.to_json()))
    assert record["schema"] == BINDING_SCHEMA and record["consistent_findings"] == 1
    assert record["import_profile_digest"] == PROFILE.profile_digest
    assert record["sarif_sha256"] == hashlib.sha256(SARIF).hexdigest()
    assert (record["sarif_bytes"], record["driver_version"]) == (len(SARIF), "1.186.0")
    assert AdapterProfileEvidence.from_dict(record["evidence"]) == _evidence()
    assert record["tracked_content_digest"] == inventory.tracked_content_digest
    assert record["launch_vector"] == {
        "version": LAUNCH_VECTOR_VERSION,
        "launcher_identity": LAUNCHER.identity_digest,
        "file_size_cap": FILE_SIZE_CAP,
    }
    assert rule_pack_digest() == digest and dict(RULES_BY_ID) == registered


def _bind(inventory: GitInventory, **changes: Any) -> None:
    """Bind the real run with some inputs replaced."""
    report = changes.pop("report", None)
    run = _run(inventory, **changes)
    bind_executed_sarif(
        run, report=report or import_sarif(run.sarif, "semgrep", inventory, head=inventory.head)
    )


def _reason(inventory: GitInventory, **changes: Any) -> str:
    """Return the reason the binding of a changed run is refused."""
    with pytest.raises(SarifImportRefused) as refused:
        _bind(inventory, **changes)
    return refused.value.reason


def test_evidence_of_another_or_an_incomplete_run_is_never_bound(inventory: GitInventory) -> None:
    """Another profile's evidence, a partial run or other output bytes refuse the binding."""
    assert (
        _reason(inventory, evidence=_evidence(profile="trivy-repository-json-v1"))
        == "other-evidence"
    )
    partial = _evidence(status="partial", reason="scan-errors")
    assert _reason(inventory, evidence=partial) == "incomplete-evidence"
    assert _reason(inventory, stderr=b"error\n") == "output-mismatch"
    other = import_sarif(SARIF, "semgrep", inventory, head=inventory.head)
    assert _reason(inventory, sarif=SARIF + b" ", report=other) == "sarif-mismatch"


@pytest.mark.parametrize(
    "version", ["1.186.0 | extra", "1.186", "v1.186.0", "1.185.0", "1.186.0-rc1"]
)
def test_only_one_exact_release_equal_to_the_driver_is_accepted(
    inventory: GitInventory, version: str
) -> None:
    """A second line, a short form, a prefix, another release or a suffix refuses the binding.

    Parameters
    ----------
    inventory : GitInventory
        The producer repository's inventory.
    version : str
        The tool version the run reported.
    """
    assert _reason(inventory, evidence=_evidence(tool_version=version)) == "version-mismatch"
    assert exact_version("1.186.0", "1.186.0") == "1.186.0"
    with pytest.raises(SarifImportRefused):
        exact_version("1.186.0", None)


def _results(document: dict[str, Any], key: str) -> list[Any]:
    """Return the result list of a Semgrep JSON or SARIF document."""
    results: list[Any] = document[key] if key == "results" else document["runs"][0]["results"]
    return results


def _variant(stdout_lines: list[int], sarif_lines: list[int]) -> tuple[bytes, bytes]:
    """Return JSON and SARIF whose single real finding is repeated at the given lines."""
    stdout: dict[str, Any] = json.loads(STDOUT)
    (json_result,) = stdout["results"]
    stdout["results"] = []
    for line in stdout_lines:
        item = copy.deepcopy(json_result)
        item["start"]["line"] = item["end"]["line"] = line
        stdout["results"].append(item)
    sarif: dict[str, Any] = json.loads(SARIF)
    (sarif_result,) = sarif["runs"][0]["results"]
    sarif["runs"][0]["results"] = []
    for index, line in enumerate(sarif_lines):
        item = copy.deepcopy(sarif_result)
        region = item["locations"][0]["physicalLocation"]["region"]
        region["startLine"] = region["endLine"] = line
        item["message"]["text"] += f" ({index})"
        sarif["runs"][0]["results"].append(item)
    return json.dumps(stdout).encode(), json.dumps(sarif).encode()


@pytest.mark.parametrize(
    ("stdout_lines", "sarif_lines"),
    [([7, 7, 3], [7, 3, 3]), ([7, 7], [7]), ([7], [3]), ([], [7]), ([7, 3], [7, 7])],
)
def test_the_findings_must_agree_as_a_multiset(
    inventory: GitInventory, stdout_lines: list[int], sarif_lines: list[int]
) -> None:
    """Equal counts and equal sets are not enough: every multiplicity must agree.

    Parameters
    ----------
    inventory : GitInventory
        The producer repository's inventory.
    stdout_lines : list[int]
        The lines of the JSON findings.
    sarif_lines : list[int]
        The lines of the SARIF findings.
    """
    stdout, sarif = _variant(stdout_lines, sarif_lines)
    evidence = _evidence(
        stdout,
        findings=len(stdout_lines),
        status="findings" if stdout_lines else "clean",
        reason="findings" if stdout_lines else "clean",
    )
    assert (
        _reason(inventory, evidence=evidence, stdout=stdout, sarif=sarif)
        == "inconsistent-second-output"
    )


def test_agreeing_multisets_bind_and_the_evidence_count_must_match(
    inventory: GitInventory,
) -> None:
    """Two findings in either order bind; an evidence count that differs from the JSON does not."""
    stdout, sarif = _variant([7, 3], [3, 7])
    _bind(inventory, evidence=_evidence(stdout, findings=2), stdout=stdout, sarif=sarif)
    assert _reason(inventory, evidence=_evidence(findings=2)) == "inconsistent-second-output"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema", "rigor.executed-sarif-binding.v0", "binding schema must be"),
        ("import_profile_digest", "0" * 64, "not the built-in profile's"),
        ("import_profile", "semgrep-local-json-v1", "import profile is not declared"),
        ("binding_digest", "0" * 64, "binding digest does not match"),
        ("extra", True, "fields do not match the schema"),
        ("tracked_content_digest", "0" * 63, "tracked content digest is not a SHA-256"),
        ("tracked_content_digest", 0, "tracked content digest is not a SHA-256"),
        ("launch_vector", [], "launch vector"),
        ("launch_vector.version", "rigor-foundry-bwrap-v1", "not the bounded import launch"),
        ("launch_vector.file_size_cap", FILE_SIZE_CAP - 1, "not the bounded import launch"),
        ("launch_vector.file_size_cap", float(FILE_SIZE_CAP), "not the bounded import launch"),
        ("launch_vector.launcher_identity", "A" * 64, "launcher identity is not a SHA-256"),
        ("launch_vector.extra", True, "fields do not match the schema"),
    ],
)
def test_a_changed_binding_record_is_refused(
    inventory: GitInventory, field: str, value: object, message: str
) -> None:
    """A changed schema, profile, digest or field set is refused on verification.

    Parameters
    ----------
    inventory : GitInventory
        The producer repository's inventory.
    field : str
        The changed field.
    value : object
        Its new value.
    message : str
        Text the refusal must contain.
    """
    _, binding = import_executed_sarif(_run(inventory), inventory=inventory, head=inventory.head)
    record = json.loads(binding.to_json())
    name, _, member = field.partition(".")
    if member:
        record[name][member] = value
    else:
        record[name] = value
    with pytest.raises(ValueError, match=message):
        verify_executed_binding(record)


def test_a_binding_whose_evidence_names_another_profile_is_refused(
    inventory: GitInventory,
) -> None:
    """Valid evidence of another profile, re-digested into the record, is refused."""
    _, binding = import_executed_sarif(_run(inventory), inventory=inventory, head=inventory.head)
    record = json.loads(binding.to_json())
    record["evidence"] = _evidence(profile="trivy-repository-json-v1").to_dict()
    record["binding_digest"] = canonical_digest(
        {key: item for key, item in record.items() if key != "binding_digest"}
    )
    with pytest.raises(ValueError, match="evidence names another profile"):
        verify_executed_binding(record)


def _json_variant(change: Any) -> bytes:
    """Return the real JSON stdout with one structural change applied."""
    document: dict[str, Any] = json.loads(STDOUT)
    change(document)
    return json.dumps(document).encode()


def test_the_json_findings_are_read_only_from_typed_semgrep_results() -> None:
    """The real stdout yields one finding; results that are not typed refuse the read."""
    assert json_findings(STDOUT) == {("rigor-fixture-eval", "src/app/settings.py", 7): 1}

    def results_object(document: dict[str, Any]) -> None:
        document["results"] = {}

    def line_text(document: dict[str, Any]) -> None:
        document["results"][0]["start"]["line"] = "7"

    def no_path(document: dict[str, Any]) -> None:
        del document["results"][0]["path"]

    with pytest.raises(ValueError, match="results are not an array"):
        json_findings(_json_variant(results_object))
    for change in (line_text, no_path):
        with pytest.raises(ValueError, match="lacks its rule, path or line"):
            json_findings(_json_variant(change))


def test_one_digest_formula_serves_the_runtime_and_the_binding() -> None:
    """A real process's recorded output digest equals the binding's recomputation of it."""
    code = "import sys; sys.stdout.write('out'); sys.stderr.write('err')"
    process = stream_process(
        (sys.executable, "-c", code), environment=dict(os.environ), timeout_seconds=30
    )
    assert (process.stdout, process.stderr) == (b"out", b"err")
    assert process.output_digest == complete_output_digest(process.stdout, process.stderr)


def test_two_findings_of_one_rule_on_one_line_are_refused_as_executed(
    inventory: GitInventory,
) -> None:
    """Same-line findings at different columns share one candidate id, so the binding fails closed.

    Parameters
    ----------
    inventory : GitInventory
        The producer repository's inventory.
    """
    stdout_document: dict[str, Any] = json.loads(STDOUT)
    (json_result,) = stdout_document["results"]
    second = copy.deepcopy(json_result)
    second["start"]["col"] = second["end"]["col"] = 30
    stdout_document["results"].append(second)
    sarif_document: dict[str, Any] = json.loads(SARIF)
    (sarif_result,) = sarif_document["runs"][0]["results"]
    other = copy.deepcopy(sarif_result)
    other["locations"][0]["physicalLocation"]["region"]["startColumn"] = 30
    sarif_document["runs"][0]["results"].append(other)
    stdout, sarif = json.dumps(stdout_document).encode(), json.dumps(sarif_document).encode()
    declared = import_sarif(sarif, "semgrep", inventory, head=inventory.head)
    assert len(declared.imported_candidates) == 1
    assert [item.reason for item in declared.skipped] == ["duplicate-candidate"]
    assert (
        _reason(inventory, evidence=_evidence(stdout, findings=2), stdout=stdout, sarif=sarif)
        == "inconsistent-second-output"
    )


def test_the_output_digest_formula_is_pinned() -> None:
    """Any change to the shared formula changes this value, so stored evidence stays readable."""
    assert (
        process_output_digest(
            stdout_digest="a" * 64,
            stdout_bytes=1,
            stderr_digest="b" * 64,
            stderr_bytes=2,
            truncated=False,
            timed_out=True,
        )
        == "71a990c54882589b8180b35e90bcd0af8fadcd238240cb5a195c65af945df805"
    )


def test_a_profile_of_another_producer_never_binds_a_semgrep_import(
    inventory: GitInventory,
) -> None:
    """The binding checks the report's producer against the profile's own producer.

    Parameters
    ----------
    inventory : GitInventory
        The producer repository's inventory.
    """
    other = ImportProfile("semgrep-local-sarif-import-v1", "codeql", PROFILE.base)
    report = import_sarif(SARIF, "semgrep", inventory, head=inventory.head)
    with pytest.raises(SarifImportRefused) as refused:
        bind_executed_sarif(_run(inventory, profile=other), report=report)
    assert refused.value.reason == "other-evidence"
    with pytest.raises(SarifImportRefused) as imported:
        import_executed_sarif(
            _run(inventory, profile=other), inventory=inventory, head=inventory.head
        )
    assert imported.value.reason == "unsupported-schema"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("provenance", "declared", "provenance is not executed"),
        ("profile_evidence_digest", "0" * 64, "does not cite this binding"),
        ("sarif_sha256", "0" * 64, "imports other SARIF bytes"),
        ("tracked_content_digest", "0" * 64, "anchored against other tracked content"),
        ("producer_id", "codeql", "producer is not the import profile's producer"),
    ],
)
def test_a_report_and_binding_that_do_not_belong_together_are_refused(
    inventory: GitInventory, field: str, value: str, message: str
) -> None:
    """Each fact that ties an executed report to its binding is checked.

    Parameters
    ----------
    inventory : GitInventory
        The producer repository's inventory.
    field : str
        The report field changed.
    value : str
        Its new value.
    message : str
        Text the refusal must contain.
    """
    report, binding = import_executed_sarif(
        _run(inventory), inventory=inventory, head=inventory.head
    )
    record, bound = json.loads(report.to_json()), json.loads(binding.to_json())
    verify_executed_import(record, bound)
    changed = {**record, field: value}
    with pytest.raises(ValueError, match=message):
        verify_executed_import(changed, bound)
    other_version = {**record, "driver": {**record["driver"], "version": "1.185.0"}}
    with pytest.raises(ValueError, match="driver version is not the bound version"):
        verify_executed_import(other_version, bound)


def test_a_run_on_other_tracked_content_is_never_bound(inventory: GitInventory) -> None:
    """A run whose scanned content is not the content the SARIF is anchored to is refused."""
    assert _reason(inventory, tracked_content_digest="0" * 64) == "other-content"
