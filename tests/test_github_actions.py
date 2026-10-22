# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native GitHub Actions scanner integration tests
"""Exercise workflow security through real tracked repositories, reports and CLI."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.github_actions import MAX_ACTION_EXECUTION_POSITIONS
from rigor_foundry.models import AuditReport
from rigor_foundry.rule_maturity import RuleMaturityPolicy, RuleMaturityReport
from rigor_foundry.rules import RULES_BY_ID
from rigor_foundry.sarif import report_sarif
from rigor_foundry.scanner import scan_repository
from rigor_foundry.workflow_yaml import MAX_WORKFLOW_BYTES

_PIN = "0123456789abcdef0123456789abcdef01234567"
_WORKFLOW = ".github/workflows/contribution.yml"


def _repository(tmp_path: Path) -> GitRepository:
    """Create a real Git owner with explicit repository audit policy."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy()
    return repository


def _workflow(steps: str, trigger: str = "[pull_request_target]") -> str:
    """Return a complete workflow containing concrete caller-supplied steps."""
    return f"on: {trigger}\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"


def test_all_three_rules_reach_public_scan_with_exact_anchors_and_no_mutation(
    tmp_path: Path,
) -> None:
    """The actual API exposes each requested signal on the original tracked blob."""
    repository = _repository(tmp_path)
    source = _workflow(
        "      - uses: actions/checkout@main\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: |\n"
        "          echo '${{ github.event.pull_request.title }}'\n"
        "          touch MUST_NOT_EXECUTE\n"
    )
    path = repository.write_text(_WORKFLOW, source)
    repository.commit()
    before = (
        path.read_bytes(),
        path.stat(),
        repository.git_command("status", "--porcelain").stdout,
    )
    report = scan_repository(repository.root)
    candidates = tuple(item for item in report.candidates if item.category == "github-actions")
    assert {item.rule_id for item in candidates} == {
        "GA001-unpinned-action-reference",
        "GA002-run-context-interpolation",
        "GA003-pull-request-target-checkout",
    }
    expected = {"GA001": (6, 6), "GA003": (8, 8), "GA002": (9, 11)}
    for candidate in candidates:
        assert (candidate.anchor.line_start, candidate.anchor.line_end) == expected[
            candidate.rule_id[:5]
        ]
        assert candidate.anchor.kind == "tracked-blob"
        assert (
            candidate.anchor.to_dict()["blob_oid"]
            == repository.git_command("rev-parse", f"HEAD:{_WORKFLOW}").stdout.strip()
        )
        assert (
            candidate.anchor.to_dict()["content_sha256"]
            == hashlib.sha256(source.encode()).hexdigest()
        )
        assert "MUST_NOT_EXECUTE" not in candidate.evidence
        assert "pull_request.title" not in candidate.evidence
    assert AuditReport.from_dict(report.to_dict()) == report
    assert scan_repository(repository.root).report_digest == report.report_digest
    assert (
        path.read_bytes(),
        path.stat(),
        repository.git_command("status", "--porcelain").stdout,
    ) == before
    assert not (repository.root / "MUST_NOT_EXECUTE").exists()
    sarif = cast(dict[str, object], json.loads(report_sarif(report)))
    runs = cast(list[dict[str, object]], sarif["runs"])
    results = cast(list[dict[str, object]], runs[0]["results"])
    ga_results = [result for result in results if str(result["ruleId"]).startswith("GA")]
    assert len(ga_results) == 3
    assert all(result["kind"] == "review" and result["level"] == "note" for result in ga_results)


def test_structural_safe_controls_and_composite_metadata_are_distinct(tmp_path: Path) -> None:
    """Comments, strings, env, local actions and trusted base checkout stay distinct."""
    repository = _repository(tmp_path)
    repository.write_text(
        _WORKFLOW,
        _workflow(
            f"      - uses: actions/checkout@{_PIN}\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.base.ref }}\n"
            "      - uses: ./local\n"
            f"      - uses: docker://alpine@sha256:{'a' * 64}\n"
            "      - env:\n"
            "          TITLE: ${{ github.event.pull_request.title }}\n"
            "        run: |\n"
            "          # uses: malicious/action@main\n"
            '          echo "$TITLE"\n'
            "          echo '${{ github.sha }}'\n"
        ),
    )
    repository.write_text("fixtures/not-a-workflow.yml", "uses: malicious/action@main\n")
    repository.write_text(".github/workflows/nested/ignored.yml", "not: executable\n")
    repository.write_text(
        "local/action.yaml",
        "runs:\n  using: composite\n  steps:\n"
        "    - uses: owner/tool@v1\n"
        "    - run: echo '${{ inputs.message }}'\n      shell: bash\n",
    )
    repository.write_text("js/action.yml", "runs: {using: node24, main: index.js}\n")
    repository.commit()
    report = scan_repository(repository.root)
    selected = [item for item in report.candidates if item.category == "github-actions"]
    assert {(item.path, item.rule_id) for item in selected} == {
        ("local/action.yaml", "GA001-unpinned-action-reference"),
        ("local/action.yaml", "GA002-run-context-interpolation"),
    }
    assert not [item for item in report.candidates if item.rule_id.startswith("GV006")]


@pytest.mark.parametrize(
    ("trigger", "expected"),
    [
        ("pull_request_target", True),
        ("[push, pull_request_target]", True),
        ("{pull_request_target: {types: [opened]}}", True),
        ("pull_request", False),
        ("{pull_request: {}}", False),
    ],
)
def test_target_trigger_forms_and_ordinary_pull_request_remain_distinct(
    tmp_path: Path, trigger: str, expected: bool
) -> None:
    """An identical head checkout is target-specific across real YAML trigger shapes."""
    repository = _repository(tmp_path)
    repository.write_text(
        _WORKFLOW,
        _workflow(
            f"      - uses: actions/checkout@{_PIN}\n"
            "        with: {repository: '${{ github.event.pull_request.head.repo.full_name }}'}\n",
            trigger,
        ),
    )
    repository.commit()
    candidates = scan_repository(repository.root).candidates
    assert any(item.rule_id.startswith("GA003") for item in candidates) is expected


def test_external_reusable_local_and_docker_references_use_exact_immutable_pins(
    tmp_path: Path,
) -> None:
    """Only actual job/step uses positions participate in action reference checks."""
    repository = _repository(tmp_path)
    refs = (
        ("owner/action@v1", False),
        (f"owner/action/subdirectory@{_PIN.upper()}", True),
        ("./local", True),
        ("./../escape", False),
        ("docker://alpine:latest", False),
        (f"docker://alpine@sha256:{'a' * 63}", False),
        ("owner/action@" + "a" * 39, False),
        ("owner/action@" + "a" * 41, False),
    )
    steps = "".join(f"      - uses: {reference}\n" for reference, _safe in refs)
    repository.write_text(_WORKFLOW, _workflow(steps, "push"))
    repository.write_text(
        ".github/workflows/reuse.yaml",
        "on: workflow_dispatch\njobs:\n"
        "  external:\n    uses: owner/repo/.github/workflows/check.yml@main\n"
        f"  pinned:\n    uses: owner/repo/.github/workflows/check.yml@{_PIN}\n"
        "  local:\n    uses: ./.github/workflows/check.yml\n",
    )
    repository.commit()
    candidates = [
        item
        for item in scan_repository(repository.root).candidates
        if item.rule_id.startswith("GA001")
    ]
    assert len(candidates) == sum(not safe for _reference, safe in refs) + 1
    assert {item.symbol for item in candidates if item.path == _WORKFLOW} == {
        f"job/0/step/{index}" for index, (_reference, safe) in enumerate(refs) if not safe
    }


def test_incomplete_yaml_and_execution_shapes_emit_governance_candidates(tmp_path: Path) -> None:
    """Invalid or unsupported owners cannot silently disappear from scan scope."""
    repository = _repository(tmp_path)
    sources = (
        "",
        "on: [",
        "on: push\non: pull_request_target\njobs: {}",
        "on: *unknown\njobs: {}",
        "on: &cycle {again: *cycle}\njobs: {}",
        "on: !unexpected push\njobs: {}",
        "on: push\njobs: []",
        "jobs: {}",
        "on: push",
        "on: push\njobs: {job: {name: only-name}}",
        "on: push\njobs: {job: {uses: owner/action@main, steps: []}}",
        "on: push\njobs: {job: {steps: [{uses: owner/action@main, run: echo}]}}",
        _workflow("      - run: '${{ github.event.title'\n"),
        _workflow("      - name: no-execution\n"),
        _workflow("      - run: echo\n", "[pull_request_target, {}]"),
        "#" + "x" * MAX_WORKFLOW_BYTES,
    )
    for index, source in enumerate(sources):
        repository.write_text(f".github/workflows/refusal-{index}.yml", source)
    for name, source in (
        ("missing-runs", "name: incomplete"),
        ("missing-runtime", "runs: {}"),
        ("missing-steps", "runs: {using: composite}"),
    ):
        repository.write_text(f"{name}/action.yml", source)
    binary = repository.root / ".github/workflows/binary.yml"
    binary.write_bytes(b"on:\x00push")
    (repository.root / ".github/workflows/link.yml").symlink_to("refusal-0.yml")
    repository.commit()
    report = scan_repository(repository.root)
    incomplete = [item for item in report.candidates if item.rule_id.startswith("GV006")]
    assert len(incomplete) == len(sources) + 5
    assert {item.symbol for item in incomplete} >= {
        "missing-workflow-trigger",
        "missing-workflow-jobs",
        "invalid-actions-expression",
        "yaml-byte-limit",
        "unreadable-actions-owner",
    }
    assert all(item.anchor.line_start >= 1 for item in incomplete)
    assert AuditReport.from_dict(report.to_dict()) == report


def test_new_workflow_rules_have_no_automatic_maturity_activation() -> None:
    """Registry enrollment does not manufacture adjudicated calibration evidence."""
    policy = RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=3,
        minimum_distinct_repositories=2,
        minimum_distinct_reviewers=1,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=0,
        maximum_median_effort_seconds=300,
        maximum_p90_effort_seconds=600,
    )
    maturity = RuleMaturityReport.build(policy, ())
    assert maturity.active_rule_ids == ()
    for rule in (
        "GA001-unpinned-action-reference",
        "GA002-run-context-interpolation",
        "GA003-pull-request-target-checkout",
        "GV006-unscanned-github-actions",
    ):
        assert RULES_BY_ID[rule].introduced == "rigor-foundry/1.19.0"
        assessment = maturity.assessment_for(rule)
        assert assessment.status == "probation"
        assert assessment.review_count == 0
    assert RuleMaturityReport.from_dict(maturity.to_dict()) == maturity


def test_small_alias_graph_cannot_amplify_execution_analysis_beyond_its_budget(
    tmp_path: Path,
) -> None:
    """Repeated real job aliases receive an explicit incomplete analysis outcome."""
    repository = _repository(tmp_path)
    steps = 128
    jobs = MAX_ACTION_EXECUTION_POSITIONS // steps + 2
    source = (
        "on: push\njobs:\n  first: &job\n    runs-on: ubuntu-latest\n    steps:\n"
        + "      - uses: ./local\n" * steps
        + "".join(f"  repeated{index}: *job\n" for index in range(jobs))
    )
    repository.write_text(_WORKFLOW, source)
    repository.commit()
    candidates = [
        item
        for item in scan_repository(repository.root).candidates
        if item.rule_id.startswith("GV006")
    ]
    assert len(candidates) == 1
    assert candidates[0].symbol == "actions-execution-position-limit"
    assert candidates[0].path == _WORKFLOW


def test_aliases_folded_crlf_scripts_and_dynamic_checkout_keep_native_source_identity(
    tmp_path: Path,
) -> None:
    """Aliases retain definition anchors while folded scripts retain physical spans."""
    repository = _repository(tmp_path)
    repository.write_text(
        ".github/workflows/aliases.yml",
        _workflow(
            "      - &action\n        uses: owner/action@main\n      - *action\n",
            "push",
        ),
    )
    folded = _workflow(
        "      - run: >-\n"
        "          echo '${{\n"
        "          github['event'].issue.title\n"
        "          }}'\n",
        "pull_request",
    ).replace("\n", "\r\n")
    repository.write_text(".github/workflows/folded.yml", folded)
    repository.write_text(
        ".github/workflows/dynamic.yml",
        _workflow(
            f"      - uses: actions/checkout@{_PIN}\n"
            "        with: {ref: '${{ env.SELECTED_REF }}'}\n"
        ),
    )
    repository.commit()
    report = scan_repository(repository.root)
    aliases = [item for item in report.candidates if item.path.endswith("aliases.yml")]
    assert len(aliases) == 2
    assert {item.rule_id for item in aliases} == {"GA001-unpinned-action-reference"}
    assert len({item.candidate_id for item in aliases}) == 2
    assert {(item.line, item.anchor.line_end) for item in aliases} == {(7, 7)}
    script = next(item for item in report.candidates if item.rule_id.startswith("GA002"))
    assert script.path.endswith("folded.yml")
    assert (script.line, script.anchor.line_end) == (6, 9)
    dynamic = next(item for item in report.candidates if item.rule_id.startswith("GA003"))
    assert dynamic.path.endswith("dynamic.yml")
    assert "SELECTED_REF" not in dynamic.evidence


def test_real_cli_exports_workflow_candidates_and_explicit_failure_status(tmp_path: Path) -> None:
    """Installed module CLI uses the same scanner and preserves the audited checkout."""
    repository = _repository(tmp_path)
    repository.write_text(_WORKFLOW, _workflow("      - uses: actions/checkout@main\n"))
    repository.commit()
    output = tmp_path / "report.json"
    before = repository.git_command("status", "--porcelain").stdout
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "rigor_foundry",
            "scan",
            "--root",
            str(repository.root),
            "--json-out",
            str(output),
            "--fail-on-candidates",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    report = AuditReport.from_path(output)
    assert any(item.rule_id.startswith("GA001") for item in report.candidates)
    assert report.report_digest == scan_repository(repository.root).report_digest
    assert repository.git_command("status", "--porcelain").stdout == before


def test_composed_checkout_selectors_reach_scan_and_cli_with_exact_source_anchors(
    tmp_path: Path,
) -> None:
    """Composed values require review even when their individual contexts are trusted."""
    repository = _repository(tmp_path)
    selectors = (
        ("ref", "${{ format('refs/{0}/42/merge', 'pull') }}", True),
        ("ref", "refs/${{ 'pull' }}/42/head", True),
        ("repository", "${{ format('{0}/fork', github.repository) }}", True),
        ("ref", "${{ github.sha }}", False),
        ("ref", "${{ 'main' }}", False),
        ("repository", "${{ github['repository'] }}", False),
        ("ref", "${{ ' refs/pull/42/head ' }}", True),
        ("ref", "${{ '\trefs/pull/42/head\t' }}", True),
        ("ref", "${{ '\u00a0refs/pull/42/head\u00a0' }}", True),
        ("ref", "${{ '\ufeffrefs/pull/42/head\ufeff' }}", True),
        ("ref", "${{ ' main ' }}", False),
        ("ref", "${{ '\ufeffmain\ufeff' }}", False),
    )
    source = _workflow(
        "".join(
            f"      - uses: actions/checkout@{_PIN}\n"
            f"        with:\n          {key}: >-\n            {selector}\n"
            for key, selector, _expected in selectors
        )
    )
    path = repository.write_text(_WORKFLOW, source)
    repository.commit()
    before = (path.read_bytes(), path.stat(), repository.git_command("status", "--porcelain"))
    report = scan_repository(repository.root)
    candidates = [item for item in report.candidates if item.rule_id.startswith("GA003")]
    assert {item.symbol for item in candidates} == {
        f"job/0/step/{index}/{key}"
        for index, (key, _selector, expected) in enumerate(selectors)
        if expected
    }
    blob = repository.git_command("rev-parse", f"HEAD:{_WORKFLOW}").stdout.strip()
    for item in candidates:
        assert item.anchor.kind == "tracked-blob"
        assert item.anchor.to_dict()["blob_oid"] == blob
        assert (
            item.anchor.to_dict()["content_sha256"] == hashlib.sha256(source.encode()).hexdigest()
        )
        index = int(item.symbol.split("/")[3])
        assert (item.line, item.anchor.line_end) == (8 + 4 * index, 9 + 4 * index)
        assert "format(" not in item.evidence
    assert not any(item.rule_id.startswith("GV006") for item in report.candidates)
    output = tmp_path / "composed-report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "rigor_foundry",
            "scan",
            "--root",
            str(repository.root),
            "--json-out",
            str(output),
            "--fail-on-candidates",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    assert AuditReport.from_path(output) == report
    assert (
        path.read_bytes(),
        path.stat(),
        repository.git_command("status", "--porcelain"),
    ) == before
