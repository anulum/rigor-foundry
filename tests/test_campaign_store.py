# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable campaign storage tests
"""Verify canonical ignored storage paths and create-only persistence."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_compare import compare_campaign
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import AuditCampaign, AuditRunAttestation
from rigor_foundry.campaign_store import (
    StoredAuditRun,
    campaign_relative_path,
    load_campaign,
    load_campaign_reviews,
    load_comparison_record,
    load_runs,
    prepare_campaign_storage_root,
    store_campaign,
    store_comparison_record,
    store_run,
)
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.models import ReviewRecord, canonical_digest, reviews_to_json
from rigor_foundry.scanner import scan_repository


def _inference_identity() -> InferenceIdentity:
    """Return one explicit campaign-run inference identity."""
    return InferenceIdentity.build(
        provider="provider.example",
        model="model-v1",
        model_family="model-family",
        operator="operator-one",
    )


def _repository(path: Path) -> GitRepository:
    """Create one real repository suitable for a frozen campaign."""
    repository = GitRepository.create(path)
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_policy()
    repository.commit()
    return repository


def _campaign_bundle(
    path: Path,
) -> tuple[GitRepository, Path, AuditCampaign, StoredAuditRun]:
    """Create one real persisted campaign and run bundle."""
    repository = _repository(path / "repository")
    campaign_path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="storage-contract",
        actor="coordinator/one",
        expected_runs=1,
    )
    execute_campaign(
        campaign_path,
        run_id="agent-one",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        inference_identity=_inference_identity(),
    )
    return repository, campaign_path, campaign, load_runs(campaign_path)[0]


def _rewrite_attestation(run_directory: Path, changed: dict[str, object]) -> None:
    """Write one internally content-addressed attestation after controlled corruption."""
    body = dict(changed)
    body.pop("attestation_digest", None)
    changed["attestation_digest"] = canonical_digest(body)
    (run_directory / "attestation.json").write_text(
        json.dumps(changed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _rebuild_attestation(
    attestation: object,
    **changes: object,
) -> AuditRunAttestation:
    """Return a parser-verified attestation carrying selected relation changes."""
    assert isinstance(attestation, AuditRunAttestation)
    document = {**attestation.to_dict(), **changes}
    document.pop("attestation_digest")
    document["attestation_digest"] = canonical_digest(document)
    return AuditRunAttestation.from_dict(document)


def test_campaign_storage_is_canonical_ignored_and_create_only(tmp_path: Path) -> None:
    """A campaign has one ignored path and cannot overwrite its immutable manifest."""
    repository = _repository(tmp_path / "repository")
    path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="campaign-one",
        actor="coordinator/one",
        expected_runs=1,
    )

    expected = campaign_relative_path(
        Path(".rigor/audits"),
        "SAMPLE-PROJECT",
        "campaign-one",
    )
    assert path == repository.root / expected
    assert repository.git_command("check-ignore", expected.as_posix()).returncode == 0
    assert load_runs(path) == ()
    with pytest.raises(FileExistsError):
        store_campaign(repository.root, Path(".rigor/audits"), campaign)


def test_storage_rejects_absolute_and_unignored_roots(tmp_path: Path) -> None:
    """Campaign evidence cannot leave ignored repository-owned storage."""
    repository, _campaign_path, campaign, _stored = _campaign_bundle(tmp_path)

    with pytest.raises(ValueError, match="repository-relative"):
        store_campaign(repository.root, tmp_path / "outside", campaign)
    with pytest.raises(ValueError, match="Git ignore"):
        store_campaign(repository.root, Path("public/audits"), campaign)

    linked = _repository(tmp_path / "linked-root")
    (linked.root / ".rigor").mkdir()
    (linked.root / "ignored-target").mkdir()
    (linked.root / ".rigor/audits").symlink_to(linked.root / "ignored-target")
    with pytest.raises(ValueError, match="must not contain symlinks"):
        prepare_campaign_storage_root(linked.root, Path(".rigor/audits"))

    blocked = _repository(tmp_path / "blocked-root")
    (blocked.root / ".rigor").mkdir()
    (blocked.root / ".rigor/audits").write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot create campaign storage root"):
        prepare_campaign_storage_root(blocked.root, Path(".rigor/audits"))


def test_campaign_and_comparison_records_reject_malformed_or_replayed_input(
    tmp_path: Path,
) -> None:
    """Durable JSON is readable, identifier-safe, and create-only."""
    repository, campaign_path, _campaign, _stored = _campaign_bundle(tmp_path)
    malformed = repository.write_text(".rigor/malformed-campaign.json", "{\n")
    with pytest.raises(ValueError, match="cannot read audit campaign"):
        load_campaign(malformed)

    campaign = load_campaign(campaign_path)
    value = compare_campaign(
        campaign,
        load_runs(campaign_path),
        (),
        comparison_id="comparison-one",
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
    ).to_dict()
    stored_path = store_comparison_record(campaign_path, "comparison-one", value)
    assert stored_path.is_file()
    assert load_comparison_record(campaign_path, stored_path).to_dict() == value
    mismatched_name = dict(value)
    mismatched_name["comparison_id"] = "comparison-other"
    mismatched_name.pop("comparison_digest")
    mismatched_name["comparison_digest"] = canonical_digest(mismatched_name)
    with pytest.raises(ValueError, match="identifier does not match"):
        store_comparison_record(campaign_path, "comparison-name", mismatched_name)

    mismatched_campaign = dict(value)
    mismatched_campaign["comparison_id"] = "comparison-foreign"
    mismatched_campaign["campaign_id"] = "OTHER-PROJECT"
    mismatched_campaign["input_contract_digest"] = "0" * 64
    mismatched_campaign.pop("comparison_digest")
    mismatched_campaign["comparison_digest"] = canonical_digest(mismatched_campaign)
    with pytest.raises(ValueError, match="does not match its campaign"):
        store_comparison_record(
            campaign_path,
            "comparison-foreign",
            mismatched_campaign,
        )
    with pytest.raises(ValueError, match="immutable audit record already exists"):
        store_comparison_record(campaign_path, "comparison-one", value)
    with pytest.raises(ValueError, match="portable identifier"):
        store_comparison_record(campaign_path, "../comparison", value)

    mismatched_requirements = dict(value)
    mismatched_requirements["comparison_id"] = "comparison-requirements"
    mismatched_requirements["expected_run_count"] = 2
    mismatched_requirements.pop("comparison_digest")
    mismatched_requirements["comparison_digest"] = canonical_digest(mismatched_requirements)
    with pytest.raises(ValueError, match="requirements do not match"):
        store_comparison_record(
            campaign_path,
            "comparison-requirements",
            mismatched_requirements,
        )

    outside_campaign = tmp_path / "outside-campaign" / "campaign.json"
    outside_campaign.parent.mkdir()
    shutil.copy2(campaign_path, outside_campaign)
    with pytest.raises(ValueError, match="outside its repository"):
        store_comparison_record(outside_campaign, "comparison-one", value)


def test_comparison_loading_rejects_path_aliases_links_size_and_invalid_json(
    tmp_path: Path,
) -> None:
    """Promotion evidence loads only from one bounded canonical regular file."""
    _repository, campaign_path, campaign, _stored = _campaign_bundle(tmp_path)
    comparison = compare_campaign(
        campaign,
        load_runs(campaign_path),
        (),
        comparison_id="comparison-load",
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
    )
    path = store_comparison_record(
        campaign_path,
        comparison.comparison_id,
        comparison.to_dict(),
    )
    comparisons = path.parent

    with pytest.raises(ValueError, match="cannot read audit comparison"):
        load_comparison_record(campaign_path, comparisons / "missing.json")

    outside = campaign_path.parent / "outside.json"
    outside.write_bytes(path.read_bytes())
    with pytest.raises(ValueError, match="outside the campaign comparison directory"):
        load_comparison_record(campaign_path, outside)

    wrong_name = comparisons / "wrong-name.json"
    wrong_name.write_bytes(path.read_bytes())
    with pytest.raises(ValueError, match="identifier does not match"):
        load_comparison_record(campaign_path, wrong_name)

    linked = comparisons / "linked.json"
    linked.symlink_to(path)
    with pytest.raises(ValueError, match="cannot read audit comparison"):
        load_comparison_record(campaign_path, linked)
    linked.unlink()

    hard_link = comparisons / "hard-link.json"
    hard_link.hardlink_to(path)
    with pytest.raises(ValueError, match="bounded single-link"):
        load_comparison_record(campaign_path, path)
    hard_link.unlink()

    invalid = comparisons / "invalid.json"
    invalid.write_text("{\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot parse audit comparison"):
        load_comparison_record(campaign_path, invalid)

    oversized = comparisons / "oversized.json"
    oversized.write_bytes(b" " * (4 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="bounded single-link"):
        load_comparison_record(campaign_path, oversized)

    foreign = comparison.to_dict()
    foreign["comparison_id"] = "foreign"
    foreign["campaign_id"] = "OTHER-PROJECT"
    foreign["input_contract_digest"] = "0" * 64
    foreign.pop("comparison_digest")
    foreign["comparison_digest"] = canonical_digest(foreign)
    foreign_path = comparisons / "foreign.json"
    foreign_path.write_text(json.dumps(foreign), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match its campaign"):
        load_comparison_record(campaign_path, foreign_path)

    mismatched_requirements = comparison.to_dict()
    mismatched_requirements["comparison_id"] = "requirements-load"
    mismatched_requirements["expected_run_count"] = campaign.expected_runs + 1
    mismatched_requirements.pop("comparison_digest")
    mismatched_requirements["comparison_digest"] = canonical_digest(mismatched_requirements)
    requirements_path = comparisons / "requirements-load.json"
    requirements_path.write_text(
        json.dumps(mismatched_requirements),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="requirements do not match"):
        load_comparison_record(campaign_path, requirements_path)


def test_campaign_storage_reproduces_frozen_git_provenance(tmp_path: Path) -> None:
    """Ignored-path validation cannot substitute another trusted Git binary."""
    repository, campaign_path, campaign, _stored = _campaign_bundle(tmp_path)
    tools = tmp_path / "alternate-tools"
    tools.mkdir()
    shutil.copy2(repository.git, tools / "git")
    policy = GitTrustPolicy(trusted_roots=(str(tools),))
    comparison = compare_campaign(
        campaign,
        load_runs(campaign_path),
        (),
        comparison_id="different-git",
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
    )

    with pytest.raises(RuntimeError, match="does not match expected identity"):
        store_comparison_record(
            campaign_path,
            "different-git",
            comparison.to_dict(),
            git_trust_policy=policy,
        )


def test_store_run_rejects_cross_campaign_and_noncanonical_bundles(tmp_path: Path) -> None:
    """Run persistence binds campaign, input contract, report digest, and canonical path."""
    _repository, campaign_path, _campaign, stored = _campaign_bundle(tmp_path)
    attestation = stored.attestation
    cases = (
        (
            _rebuild_attestation(
                attestation,
                run_id="wrong-campaign",
                campaign_id="OTHER-PROJECT",
            ),
            "different campaign",
        ),
        (
            _rebuild_attestation(
                attestation,
                run_id="wrong-contract",
                input_contract_digest="0" * 64,
            ),
            "input contract",
        ),
        (
            _rebuild_attestation(
                attestation,
                run_id="wrong-report",
                report_digest="0" * 64,
            ),
            "report digest",
        ),
        (
            _rebuild_attestation(
                attestation,
                run_id="wrong-path",
                report_relative_path="runs/elsewhere/report.json",
            ),
            "not canonical",
        ),
    )
    for changed, message in cases:
        with pytest.raises(ValueError, match=message):
            store_run(campaign_path, stored.report, changed)

    outside = tmp_path / "outside-campaign" / "campaign.json"
    outside.parent.mkdir()
    shutil.copy2(campaign_path, outside)
    with pytest.raises(ValueError, match="outside its repository"):
        store_run(outside, stored.report, attestation)


def test_campaign_storage_rejects_report_from_another_real_git_executable(
    tmp_path: Path,
) -> None:
    """Store, reload, and comparison cannot launder alternate Git provenance."""
    _repository, campaign_path, campaign, stored = _campaign_bundle(tmp_path)
    tools = tmp_path / "alternate-tools"
    tools.mkdir()
    shutil.copy2(stored.report.git_provenance.resolved_path, tools / "git")
    alternate = scan_repository(
        Path(campaign.repository_root),
        Path(campaign.policy_path),
        git_trust_policy=GitTrustPolicy(trusted_roots=(str(tools),)),
    )
    forged = _rebuild_attestation(
        stored.attestation,
        run_id="alternate-git",
        report_relative_path="runs/alternate-git/report.json",
        report_digest=alternate.report_digest,
        candidate_count=len(alternate.candidates),
    )

    with pytest.raises(ValueError, match="git_provenance"):
        store_run(campaign_path, alternate, forged)

    run_directory = campaign_path.parent / "runs" / stored.attestation.run_id
    (run_directory / "report.json").write_text(alternate.to_json(), encoding="utf-8")
    persisted = _rebuild_attestation(
        stored.attestation,
        report_digest=alternate.report_digest,
        candidate_count=len(alternate.candidates),
    )
    _rewrite_attestation(run_directory, persisted.to_dict())
    with pytest.raises(ValueError, match="campaign input divergence: git_provenance"):
        load_runs(campaign_path)

    comparison = compare_campaign(
        campaign,
        (StoredAuditRun(attestation=forged, report=alternate),),
        (),
        comparison_id="alternate-git",
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
    )
    assert comparison.unresolved
    assert comparison.input_divergence == (
        "run alternate-git: git_provenance differs from campaign contract",
    )


def test_load_runs_rejects_self_consistent_wrong_bindings(tmp_path: Path) -> None:
    """Rehashed but misbound records remain invalid at the durable load boundary."""
    cases = (
        ("campaign_id", "OTHER-PROJECT", "different campaign"),
        ("input_contract_digest", "0" * 64, "different input contract"),
        ("report_digest", "0" * 64, "report digest mismatch"),
        ("candidate_count", 1, "candidate count mismatch"),
    )
    for index, (field, value, message) in enumerate(cases):
        _repository, campaign_path, _campaign, stored = _campaign_bundle(
            tmp_path / f"binding-{index}"
        )
        run_directory = campaign_path.parent / "runs" / stored.attestation.run_id
        changed = stored.attestation.to_dict()
        changed[field] = value
        _rewrite_attestation(run_directory, changed)
        with pytest.raises(ValueError, match=message):
            load_runs(campaign_path)


def test_load_runs_rejects_malformed_escaping_and_duplicate_records(tmp_path: Path) -> None:
    """Run discovery fails closed on unreadable, escaping, or aliased evidence."""
    _repository, campaign_path, _campaign, stored = _campaign_bundle(tmp_path / "malformed")
    run_directory = campaign_path.parent / "runs" / stored.attestation.run_id
    (run_directory / "attestation.json").write_text("{\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read audit attestation"):
        load_runs(campaign_path)

    _repository, campaign_path, _campaign, stored = _campaign_bundle(tmp_path / "escaping")
    run_directory = campaign_path.parent / "runs" / stored.attestation.run_id
    other = campaign_path.parent / "runs" / "other"
    other.mkdir()
    shutil.copy2(run_directory / "report.json", other / "report.json")
    changed = stored.attestation.to_dict()
    changed["report_relative_path"] = "runs/other/report.json"
    _rewrite_attestation(run_directory, changed)
    with pytest.raises(ValueError, match="report path escapes its run"):
        load_runs(campaign_path)

    _repository, campaign_path, _campaign, stored = _campaign_bundle(tmp_path / "duplicate")
    original = campaign_path.parent / "runs" / stored.attestation.run_id
    copied = campaign_path.parent / "runs" / "copied"
    shutil.copytree(original, copied)
    changed = stored.attestation.to_dict()
    changed["report_relative_path"] = "runs/copied/report.json"
    _rewrite_attestation(copied, changed)
    with pytest.raises(ValueError, match="duplicate run identifiers"):
        load_runs(campaign_path)


def test_campaign_review_loading_is_ordered_and_symlink_safe(tmp_path: Path) -> None:
    """Independent review documents load in stable order from regular files only."""
    _repository, campaign_path, _campaign, stored = _campaign_bundle(tmp_path)
    assert load_campaign_reviews(campaign_path) == ()

    reviews = campaign_path.parent / "reviews"
    reviews.mkdir()
    first = ReviewRecord.template(stored.report.report_digest, "candidate-first")
    second = ReviewRecord.template(stored.report.report_digest, "candidate-second")
    (reviews / "20-second.json").write_text(reviews_to_json((second,)), encoding="utf-8")
    first_path = reviews / "10-first.json"
    first_path.write_text(reviews_to_json((first,)), encoding="utf-8")
    loaded = load_campaign_reviews(campaign_path)
    assert tuple(document[0].candidate_id for document in loaded) == (
        "candidate-first",
        "candidate-second",
    )

    (reviews / "30-linked.json").symlink_to(first_path)
    with pytest.raises(ValueError, match="regular non-symlink"):
        load_campaign_reviews(campaign_path)
