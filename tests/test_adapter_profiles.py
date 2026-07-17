# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — built-in adapter profile tests
"""Exercise strict profile parsing and real sandboxed Semgrep/Trivy scans."""

from __future__ import annotations

import json
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapter_profiles import (
    AdapterProfileEvidence,
    interpret_profile_output,
    normalise_version_output,
    profile_by_name,
)
from rigor_foundry.adapters import AdapterResult, run_adapter
from rigor_foundry.models import AdapterSpec, canonical_digest


def _profile_spec(name: str, profile: str, configuration: str, target: str) -> AdapterSpec:
    """Return one parsed built-in adapter declaration."""
    return AdapterSpec.from_dict(
        {
            "name": name,
            "profile": profile,
            "configuration_path": configuration,
            "target_paths": [target],
            "timeout_seconds": 60,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )


def _redigest_profile(
    evidence: AdapterProfileEvidence,
    **changes: object,
) -> dict[str, object]:
    """Return a self-consistent imported record with selected field changes."""
    changed = {**evidence.to_dict(), **changes}
    fields = {key: value for key, value in changed.items() if key != "evidence_digest"}
    changed["evidence_digest"] = canonical_digest(fields)
    return changed


def test_profile_evidence_round_trip_rejects_static_contradictions() -> None:
    """Imported profile evidence cannot change status, counts, or content digests."""
    profile = profile_by_name("semgrep-local-json-v1")
    evidence = AdapterProfileEvidence.build(
        profile=profile,
        status="clean",
        reason="clean",
        tool_version="1.170.0",
        version_output_digest="a" * 64,
        configuration_digest="b" * 64,
        input_digest="c" * 64,
        output_digest="d" * 64,
        finding_count=0,
        scanned_target_count=2,
    )
    assert AdapterProfileEvidence.from_dict(evidence.to_dict()) == evidence

    for key, value, message in (
        ("status", "findings", "digest does not match"),
        ("profile_digest", "e" * 64, "digest does not match"),
        ("finding_count", 1, "digest does not match"),
        ("evidence_digest", "f" * 64, "digest does not match"),
    ):
        changed = {**evidence.to_dict(), key: value}
        with pytest.raises(ValueError, match=message):
            AdapterProfileEvidence.from_dict(changed)

    with pytest.raises(ValueError, match="cannot contain findings"):
        AdapterProfileEvidence.build(
            profile=profile,
            status="clean",
            reason="clean",
            tool_version="1.170.0",
            version_output_digest="a" * 64,
            configuration_digest="b" * 64,
            input_digest="c" * 64,
            output_digest="d" * 64,
            finding_count=1,
            scanned_target_count=1,
        )


def test_profile_registry_and_evidence_schema_fail_closed() -> None:
    """Unsupported profiles and every contradictory evidence relation are rejected."""
    with pytest.raises(ValueError, match="unsupported"):
        profile_by_name("unknown-profile")
    trivy = profile_by_name("trivy-repository-json-v1")
    with pytest.raises(ValueError, match="exactly one target"):
        trivy.command_arguments("config.yml", ("first", "second"))

    profile = profile_by_name("semgrep-local-json-v1")
    base = {
        "profile": profile,
        "status": "clean",
        "reason": "clean",
        "tool_version": "1.170.0",
        "version_output_digest": "a" * 64,
        "configuration_digest": "b" * 64,
        "input_digest": "c" * 64,
        "output_digest": "d" * 64,
        "finding_count": 0,
        "scanned_target_count": 1,
    }
    invalid_relations = (
        ({"status": "unsupported"}, "status or reason"),
        ({"reason": "findings"}, "reason contradicts"),
        ({"status": "findings", "reason": "findings"}, "at least one finding"),
        ({"scanned_target_count": 0}, "requires scanned targets"),
        ({"tool_version": ""}, "must be a non-empty"),
        (
            {
                "status": "unavailable",
                "reason": "executable-unavailable",
                "tool_version": "1.170.0",
            },
            "cannot claim a tool version",
        ),
        (
            {
                "status": "unavailable",
                "reason": "executable-unavailable",
                "tool_version": "",
                "finding_count": 1,
            },
            "requires zero result counts",
        ),
        (
            {
                "status": "partial",
                "reason": "invalid-output",
                "finding_count": 1,
                "scanned_target_count": 1,
            },
            "requires zero result counts",
        ),
        (
            {
                "status": "partial",
                "reason": "no-scanned-targets",
                "scanned_target_count": 1,
            },
            "requires zero scanned targets",
        ),
        (
            {
                "status": "partial",
                "reason": "invalid-returncode",
                "scanned_target_count": 0,
            },
            "requires scanned targets",
        ),
    )
    for changes, message in invalid_relations:
        with pytest.raises(ValueError, match=message):
            AdapterProfileEvidence.build(**{**base, **changes})  # type: ignore[arg-type]

    evidence = AdapterProfileEvidence.build(**base)  # type: ignore[arg-type]
    for changes, message in (
        ({"implicit": True}, "fields do not match"),
        ({"schema_version": "9.0"}, "schema version"),
        ({"evidence_digest": "A" * 64}, "lowercase SHA-256"),
    ):
        with pytest.raises(ValueError, match=message):
            AdapterProfileEvidence.from_dict({**evidence.to_dict(), **changes})

    wrong_profile = evidence.to_dict()
    wrong_profile["profile_digest"] = "e" * 64
    fields = {key: value for key, value in wrong_profile.items() if key != "evidence_digest"}
    wrong_profile["evidence_digest"] = canonical_digest(fields)
    with pytest.raises(ValueError, match="does not match built-in profile"):
        AdapterProfileEvidence.from_dict(wrong_profile)

    for changes, message in (
        (
            {
                "status": "partial",
                "reason": "invalid-output",
                "finding_count": 7,
                "scanned_target_count": 9,
            },
            "requires zero result counts",
        ),
        (
            {
                "status": "partial",
                "reason": "no-scanned-targets",
                "scanned_target_count": 1,
            },
            "requires zero scanned targets",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            AdapterProfileEvidence.from_dict(_redigest_profile(evidence, **changes))

    trivy = profile_by_name("trivy-repository-json-v1")
    with pytest.raises(ValueError, match="only by the Semgrep profile"):
        AdapterProfileEvidence.build(
            profile=trivy,
            status="partial",
            reason="scan-errors",
            tool_version="Version: 0.72.0",
            version_output_digest="a" * 64,
            configuration_digest="b" * 64,
            input_digest="c" * 64,
            output_digest="d" * 64,
            finding_count=0,
            scanned_target_count=1,
        )


@pytest.mark.parametrize(
    "payload,returncode,expected",
    [
        (
            {"results": [], "errors": [], "paths": {"scanned": ["src/safe.py"]}},
            0,
            ("clean", "clean", 0, 1),
        ),
        (
            {
                "results": [{"check_id": "dangerous-eval"}],
                "errors": [],
                "paths": {"scanned": ["src/unsafe.py"]},
            },
            1,
            ("findings", "findings", 1, 1),
        ),
        (
            {
                "results": [],
                "errors": [{"message": "parse failure"}],
                "paths": {"scanned": ["src/broken.py"]},
            },
            2,
            ("partial", "scan-errors", 0, 1),
        ),
    ],
)
def test_semgrep_parser_preserves_clean_findings_and_partial_states(
    payload: dict[str, object],
    returncode: int,
    expected: tuple[str, str, int, int],
) -> None:
    """Semgrep JSON only becomes complete evidence with scanned paths and no errors."""
    observed = interpret_profile_output(
        profile_by_name("semgrep-local-json-v1"),
        stdout=json.dumps(payload).encode(),
        returncode=returncode,
        timed_out=False,
        truncated=False,
    )
    assert observed == expected


def test_profile_parser_never_launders_invalid_or_empty_json_into_pass() -> None:
    """Malformed, duplicate-key, non-finite, and empty evidence remains partial."""
    profile = profile_by_name("semgrep-local-json-v1")
    for payload in (
        b"not-json",
        b'{"results":[],"results":[],"errors":[],"paths":{"scanned":["x"]}}',
        b'{"results":[],"errors":[],"paths":{"scanned":[]},"value":NaN}',
        b'{"results":[],"errors":[],"paths":{"scanned":[]}}',
    ):
        status, _reason, _findings, _scanned = interpret_profile_output(
            profile,
            stdout=payload,
            returncode=0,
            timed_out=False,
            truncated=False,
        )
        assert status == "partial"


@pytest.mark.parametrize(
    ("payload", "returncode", "expected_reason"),
    [
        ({"results": {}, "errors": [], "paths": {"scanned": ["x"]}}, 0, "invalid-output"),
        ({"results": [1], "errors": [], "paths": {"scanned": ["x"]}}, 0, "invalid-output"),
        ({"results": [], "errors": [], "paths": {"scanned": [""]}}, 0, "invalid-output"),
        ({"results": [], "errors": [], "paths": {"scanned": ["x"]}}, 2, "invalid-returncode"),
        ({"results": [], "errors": [], "paths": {"scanned": ["x"]}}, 1, "invalid-returncode"),
        (
            {"results": [{"check_id": "x"}], "errors": [], "paths": {"scanned": ["x"]}},
            0,
            "invalid-returncode",
        ),
    ],
)
def test_semgrep_parser_rejects_invalid_shapes_and_return_relations(
    payload: dict[str, object],
    returncode: int,
    expected_reason: str,
) -> None:
    """Malformed arrays and contradictory exit codes remain partial evidence."""
    observed = interpret_profile_output(
        profile_by_name("semgrep-local-json-v1"),
        stdout=json.dumps(payload).encode(),
        returncode=returncode,
        timed_out=False,
        truncated=False,
    )
    assert observed[0:2] == ("partial", expected_reason)


def test_profile_interpreter_prioritises_timeout_and_truncation() -> None:
    """Execution bounds take precedence over any apparently valid analyser JSON."""
    profile = profile_by_name("semgrep-local-json-v1")
    payload = b'{"results":[],"errors":[],"paths":{"scanned":["x"]}}'
    assert interpret_profile_output(
        profile, stdout=payload, returncode=0, timed_out=True, truncated=False
    ) == ("partial", "timed-out", 0, 0)
    assert interpret_profile_output(
        profile, stdout=payload, returncode=0, timed_out=False, truncated=True
    ) == ("partial", "output-truncated", 0, 0)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"SchemaVersion": 1, "Results": []},
        {"SchemaVersion": 2, "Results": {}},
        {"SchemaVersion": 2, "Results": [{"Target": "", "Class": "x", "Type": "x"}]},
        {"SchemaVersion": 2, "Results": [{"Target": "x", "Class": "x", "Type": ""}]},
        {
            "SchemaVersion": 2,
            "Results": [{"Target": "x", "Class": "x", "Type": "x", "Misconfigurations": {}}],
        },
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "x",
                    "Class": "x",
                    "Type": "x",
                    "Misconfigurations": [{"Status": "UNKNOWN"}],
                }
            ],
        },
        {
            "SchemaVersion": 2,
            "Results": [{"Target": "x", "Class": "x", "Type": "x", "Secrets": ["invalid"]}],
        },
    ],
)
def test_trivy_parser_rejects_every_ambiguous_shape(payload: dict[str, object]) -> None:
    """Unsupported Trivy schemas, identities, arrays, and findings stay partial."""
    observed = interpret_profile_output(
        profile_by_name("trivy-repository-json-v1"),
        stdout=json.dumps(payload).encode(),
        returncode=0,
        timed_out=False,
        truncated=False,
    )
    assert observed == ("partial", "invalid-output", 0, 0)


def test_trivy_parser_counts_only_failures_and_secrets() -> None:
    """Pass/exception checks remain evidence while failures and secrets count findings."""
    payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "infra/Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {"Status": "PASS"},
                    {"Status": "EXCEPTION"},
                    {"Status": "FAIL"},
                ],
                "Secrets": [{"RuleID": "secret"}],
            }
        ],
    }
    assert interpret_profile_output(
        profile_by_name("trivy-repository-json-v1"),
        stdout=json.dumps(payload).encode(),
        returncode=1,
        timed_out=False,
        truncated=False,
    ) == ("findings", "findings", 2, 1)


def test_tool_version_normalisation_is_bounded_utf8() -> None:
    """Version evidence accepts bounded lines and rejects ambiguous encodings or size."""
    assert normalise_version_output(b"tool 1.0\ncommit abc\n") == "tool 1.0 | commit abc"
    for payload in (b"", b"\xff", b"\n".join([b"line"] * 9), b"x" * 4097):
        with pytest.raises(ValueError, match=r"version output|not UTF-8"):
            normalise_version_output(payload)


def test_real_semgrep_profile_scans_safe_and_vulnerable_commits(tmp_path: Path) -> None:
    """The public adapter boundary records real Semgrep clean and finding outcomes."""
    repository = GitRepository.create(tmp_path / "semgrep-repository")
    repository.write_text(
        "security/semgrep.yml",
        "rules:\n"
        "  - id: dangerous-eval\n"
        "    languages: [python]\n"
        "    message: dynamic evaluation is forbidden\n"
        "    severity: ERROR\n"
        "    pattern: eval(...)\n",
    )
    repository.write_text(
        "src/example.py", "def add(left: int, right: int) -> int:\n    return left + right\n"
    )
    repository.commit()
    spec = _profile_spec(
        "semgrep-security",
        "semgrep-local-json-v1",
        "security/semgrep.yml",
        "src",
    )

    clean = run_adapter(repository.root, spec, trusted=True)
    assert clean.passed, json.dumps(clean.to_dict(), indent=2, sort_keys=True)
    assert clean.complete
    assert clean.profile_evidence is not None
    assert clean.profile_evidence.status == "clean"
    assert clean.profile_evidence.scanned_target_count == 1
    assert AdapterResult.from_dict(clean.to_dict()) == clean

    mismatched_output = clean.to_dict()
    mismatched_output["output_digest"] = "e" * 64
    with pytest.raises(ValueError, match="output digest does not match execution"):
        AdapterResult.from_dict(mismatched_output)

    mismatched_returncode = clean.to_dict()
    mismatched_returncode["returncode"] = 1
    with pytest.raises(ValueError, match="clean profile return code"):
        AdapterResult.from_dict(mismatched_returncode)

    impossible_invalid_returncode = clean.to_dict()
    impossible_invalid_returncode.update(
        {
            "profile_evidence": _redigest_profile(
                clean.profile_evidence,
                status="partial",
                reason="invalid-returncode",
            ),
            "passed": False,
        }
    )
    with pytest.raises(ValueError, match="agrees with findings"):
        AdapterResult.from_dict(impossible_invalid_returncode)
    valid_invalid_returncode = {**impossible_invalid_returncode, "returncode": 1}
    parsed_invalid_returncode = AdapterResult.from_dict(valid_invalid_returncode)
    assert not parsed_invalid_returncode.complete
    assert parsed_invalid_returncode.profile_evidence is not None
    assert parsed_invalid_returncode.profile_evidence.reason == "invalid-returncode"

    contradictory_bound = clean.to_dict()
    contradictory_bound["timed_out"] = True
    with pytest.raises(ValueError, match="bounds contradict evidence"):
        AdapterResult.from_dict(contradictory_bound)

    for reason, returncode, timed_out, truncated in (
        ("timed-out", 124, True, False),
        ("output-truncated", 125, False, True),
    ):
        bounded_evidence = AdapterProfileEvidence.build(
            profile=profile_by_name("semgrep-local-json-v1"),
            status="partial",
            reason=reason,  # type: ignore[arg-type]
            tool_version="1.170.0",
            version_output_digest=clean.profile_evidence.version_output_digest,
            configuration_digest=clean.profile_evidence.configuration_digest,
            input_digest=clean.profile_evidence.input_digest,
            output_digest=clean.output_digest,
            finding_count=0,
            scanned_target_count=0,
        )
        bounded = clean.to_dict()
        bounded.update(
            {
                "returncode": returncode,
                "timed_out": timed_out,
                "output_truncated": truncated,
                "profile_evidence": bounded_evidence.to_dict(),
                "passed": False,
            }
        )
        parsed = AdapterResult.from_dict(bounded)
        assert not parsed.complete
        invalid_bound = {**bounded, "returncode": 0}
        with pytest.raises(ValueError, match="profile execution fields are invalid"):
            AdapterResult.from_dict(invalid_bound)

    repository.write_text(
        "src/example.py", "def execute(source: str) -> object:\n    return eval(source)\n"
    )
    repository.commit("test: add vulnerable Semgrep input")
    finding = run_adapter(repository.root, spec, trusted=True)
    assert not finding.passed
    assert finding.complete
    assert finding.profile_evidence is not None
    assert finding.profile_evidence.status == "findings"
    assert finding.profile_evidence.finding_count == 1
    assert finding.profile_evidence.input_digest != clean.profile_evidence.input_digest
    invalid_finding_returncode = finding.to_dict()
    invalid_finding_returncode["returncode"] = 0
    with pytest.raises(ValueError, match="findings profile return code"):
        AdapterResult.from_dict(invalid_finding_returncode)


def test_real_trivy_profile_scans_tracked_repository_configuration(tmp_path: Path) -> None:
    """The public adapter boundary executes pinned Trivy with no network or CVE claim."""
    repository = GitRepository.create(tmp_path / "trivy-repository")
    repository.write_text("security/trivy.yaml", "format: json\n")
    repository.write_text(
        "infra/Dockerfile",
        "FROM alpine:latest\nRUN apk add --no-cache curl\nUSER root\n",
    )
    repository.commit()
    spec = _profile_spec(
        "trivy-repository-security",
        "trivy-repository-json-v1",
        "security/trivy.yaml",
        "infra",
    )

    result = run_adapter(repository.root, spec, trusted=True)

    assert result.profile_evidence is not None
    assert result.profile_evidence.profile == "trivy-repository-json-v1"
    assert result.profile_evidence.tool_version.startswith("Version: 0.72.0")
    assert result.profile_evidence.status in {"clean", "findings"}
    assert result.profile_evidence.scanned_target_count >= 1
    assert result.complete


def test_profile_unavailable_evidence_is_durable_and_fail_closed(tmp_path: Path) -> None:
    """A real non-executable built-in tool produces unavailable evidence, never pass."""
    repository = GitRepository.create(tmp_path / "trivy-unavailable")
    repository.write_text("security/trivy.yaml", "format: json\n")
    repository.write_text("infra/Dockerfile", "FROM alpine:3.20\nUSER 1000\n")
    repository.commit()
    spec = _profile_spec(
        "trivy-unavailable",
        "trivy-repository-json-v1",
        "security/trivy.yaml",
        "infra",
    )
    executable = Path(sys.prefix) / "bin" / "trivy"
    original_mode = stat.S_IMODE(executable.stat().st_mode)
    executable.chmod(0o600)
    try:
        result = run_adapter(repository.root, spec, trusted=True)
    finally:
        executable.chmod(original_mode)
    assert not result.passed
    assert not result.complete
    assert result.returncode == 126
    assert result.profile_evidence is not None
    assert result.profile_evidence.status == "unavailable"
    assert result.profile_evidence.reason == "executable-unavailable"
    assert AdapterResult.from_dict(result.to_dict()) == result
    invalid_outer = result.to_dict()
    invalid_outer["returncode"] = 0
    with pytest.raises(ValueError, match="unavailable profile execution fields"):
        AdapterResult.from_dict(invalid_outer)


def test_profile_rejects_unsafe_executable_mode_as_unavailable(tmp_path: Path) -> None:
    """Group-writable analyser bytes cannot cross the descriptor trust boundary."""
    repository = GitRepository.create(tmp_path / "trivy-unsafe-mode")
    repository.write_text("security/trivy.yaml", "format: json\n")
    repository.write_text("infra/Dockerfile", "FROM alpine:3.20\nUSER 1000\n")
    repository.commit()
    spec = _profile_spec(
        "trivy-unsafe-mode",
        "trivy-repository-json-v1",
        "security/trivy.yaml",
        "infra",
    )
    executable = Path(sys.prefix) / "bin" / "trivy"
    original_mode = stat.S_IMODE(executable.stat().st_mode)
    executable.chmod(0o720)
    try:
        result = run_adapter(repository.root, spec, trusted=True)
    finally:
        executable.chmod(original_mode)
    assert result.profile_evidence is not None
    assert result.profile_evidence.reason == "executable-unavailable"


@pytest.mark.parametrize(
    "wrapper",
    [
        "#!/bin/sh\nexit 9\n",
        "#!/usr/bin/python3\nimport os\nos.write(1, b'\\xff')\n",
        "#!/bin/sh\nsleep 5\n",
    ],
)
def test_profile_version_failures_are_durable_unavailable_evidence(
    tmp_path: Path,
    wrapper: str,
) -> None:
    """Real failing and non-UTF-8 version commands cannot produce scan evidence."""
    repository = GitRepository.create(tmp_path / "trivy-version-failure")
    repository.write_text("security/trivy.yaml", "format: json\n")
    repository.write_text("infra/Dockerfile", "FROM alpine:3.20\nUSER 1000\n")
    repository.commit()
    spec = replace(
        _profile_spec(
            "trivy-version-failure",
            "trivy-repository-json-v1",
            "security/trivy.yaml",
            "infra",
        ),
        timeout_seconds=1,
    )
    executable = Path(sys.prefix) / "bin" / "trivy"
    retained = executable.with_name(".trivy-retained-for-version-test")
    executable.rename(retained)
    try:
        executable.write_text(wrapper, encoding="utf-8")
        executable.chmod(0o700)
        result = run_adapter(repository.root, spec, trusted=True)
    finally:
        executable.unlink(missing_ok=True)
        retained.rename(executable)
    assert result.profile_evidence is not None
    assert result.profile_evidence.status == "unavailable"
    assert result.profile_evidence.reason == "version-unavailable"


def test_profile_specification_must_remain_canonical(tmp_path: Path) -> None:
    """Direct dataclass mutation cannot override a built-in command contract."""
    repository = GitRepository.create(tmp_path / "noncanonical-profile")
    repository.write_text("security/semgrep.yml", "rules: []\n")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.commit()
    canonical = _profile_spec(
        "semgrep",
        "semgrep-local-json-v1",
        "security/semgrep.yml",
        "src",
    )
    with pytest.raises(ValueError, match="not canonical"):
        run_adapter(
            repository.root,
            replace(canonical, command=("untrusted-override",)),
            trusted=True,
        )
