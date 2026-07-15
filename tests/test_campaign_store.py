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
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_models import AuditCampaign
from rigor_foundry.campaign_store import (
    StoredAuditRun,
    campaign_relative_path,
    load_campaign,
    load_campaign_reviews,
    load_runs,
    store_campaign,
    store_comparison_record,
    store_run,
)
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.models import ReviewRecord, canonical_digest, reviews_to_json


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
        expected_independent_runs=1,
    )
    execute_campaign(
        campaign_path,
        run_id="agent-one",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
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
        expected_independent_runs=1,
    )

    expected = campaign_relative_path(
        Path(".rigor/audits"),
        "SAMPLE-PROJECT",
        "campaign-one",
    )
    assert path == repository.root / expected
    assert repository.git_command("check-ignore", expected.as_posix()).returncode == 0
    with pytest.raises(FileExistsError):
        store_campaign(repository.root, Path(".rigor/audits"), campaign)


def test_storage_rejects_absolute_and_unignored_roots(tmp_path: Path) -> None:
    """Campaign evidence cannot leave ignored repository-owned storage."""
    repository, _campaign_path, campaign, _stored = _campaign_bundle(tmp_path)

    with pytest.raises(ValueError, match="repository-relative"):
        store_campaign(repository.root, tmp_path / "outside", campaign)
    with pytest.raises(ValueError, match="Git ignore"):
        store_campaign(repository.root, Path("public/audits"), campaign)


def test_campaign_and_comparison_records_reject_malformed_or_replayed_input(
    tmp_path: Path,
) -> None:
    """Durable JSON is readable, identifier-safe, and create-only."""
    repository, campaign_path, _campaign, _stored = _campaign_bundle(tmp_path)
    malformed = repository.write_text(".rigor/malformed-campaign.json", "{\n")
    with pytest.raises(ValueError, match="cannot read audit campaign"):
        load_campaign(malformed)

    value: dict[str, object] = {"comparison_id": "comparison-one"}
    stored_path = store_comparison_record(campaign_path, "comparison-one", value)
    assert stored_path.is_file()
    with pytest.raises(ValueError, match="immutable audit record already exists"):
        store_comparison_record(campaign_path, "comparison-one", value)
    with pytest.raises(ValueError, match="portable identifier"):
        store_comparison_record(campaign_path, "../comparison", value)


def test_store_run_rejects_cross_campaign_and_noncanonical_bundles(tmp_path: Path) -> None:
    """Run persistence binds campaign, input contract, report digest, and canonical path."""
    _repository, campaign_path, _campaign, stored = _campaign_bundle(tmp_path)
    attestation = stored.attestation
    cases = (
        (
            replace(attestation, run_id="wrong-campaign", campaign_id="OTHER-PROJECT"),
            "different campaign",
        ),
        (
            replace(attestation, run_id="wrong-contract", input_contract_digest="0" * 64),
            "input contract",
        ),
        (
            replace(attestation, run_id="wrong-report", report_digest="0" * 64),
            "report digest",
        ),
        (
            replace(
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
