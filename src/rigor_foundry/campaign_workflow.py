# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — multi-agent audit campaign workflow
"""Create, execute, and compare immutable independent audit campaigns."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .adapters import run_native_audits
from .campaign_compare import AuditComparison, compare_campaign
from .campaign_evidence import ToolchainIdentity
from .campaign_identity import InferenceIdentity
from .campaign_inputs import validate_campaign_input
from .campaign_models import (
    AuditCampaign,
    AuditRunAttestation,
    CampaignPurpose,
)
from .campaign_store import (
    load_campaign,
    load_campaign_reviews,
    load_runs,
    prepare_campaign_storage_root,
    store_campaign,
    store_comparison_record,
    store_run,
)
from .domains import audit_domain_coverage
from .git_inventory import load_git_inventory
from .git_provenance import GitRunner, GitTrustPolicy
from .ignored_inventory import collect_ignored_inventory, ignored_inventory_digest
from .models import canonical_digest
from .review import validate_reviews
from .scanner import scan_repository


def _now() -> str:
    """Return the current UTC time in the protocol timestamp form."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def create_campaign(
    repository_root: Path,
    policy_path: Path,
    *,
    audit_root: Path,
    project: str,
    campaign_id: str,
    actor: str,
    expected_runs: int,
    purpose: CampaignPurpose = "diagnostic",
    required_model_witnesses: int | None = None,
    git_trust_policy: GitTrustPolicy | None = None,
) -> tuple[Path, AuditCampaign]:
    """Freeze and persist one exact multi-agent audit input contract."""
    prepare_campaign_storage_root(
        repository_root,
        audit_root,
        git_trust_policy=git_trust_policy,
    )
    report = scan_repository(
        repository_root,
        policy_path,
        git_trust_policy=git_trust_policy,
    )
    repository = Path(report.repository_root).resolve(strict=True)
    policy_absolute = (
        policy_path.resolve(strict=True)
        if policy_path.is_absolute()
        else (repository / policy_path).resolve(strict=True)
    )
    try:
        relative_policy = policy_absolute.relative_to(repository)
    except ValueError as exc:
        raise ValueError("campaign policy must be stored inside the repository") from exc
    witness_requirement = (
        (2 if purpose == "promotion" else 1)
        if required_model_witnesses is None
        else required_model_witnesses
    )
    campaign = AuditCampaign.build(
        report,
        campaign_id=campaign_id,
        project=project,
        policy_path=relative_policy.as_posix(),
        toolchain=ToolchainIdentity.current(),
        created_by=actor,
        created_at=_now(),
        purpose=purpose,
        expected_runs=expected_runs,
        required_model_witnesses=witness_requirement,
    )
    path = store_campaign(
        repository,
        audit_root,
        campaign,
        git_trust_policy=git_trust_policy,
    )
    return path, campaign


def execute_campaign(
    campaign_path: Path,
    *,
    run_id: str,
    agent_identity: str,
    session_identity: str,
    inference_identity: InferenceIdentity,
    trusted_native_audits: bool = False,
    git_trust_policy: GitTrustPolicy | None = None,
) -> tuple[Path, AuditRunAttestation]:
    """Run and persist one independent full-scope audit attestation."""
    campaign = load_campaign(campaign_path)
    repository = Path(campaign.repository_root).resolve(strict=True)
    policy_path = Path(campaign.policy_path)
    started_at = _now()
    toolchain = ToolchainIdentity.current()
    report = scan_repository(
        repository,
        policy_path,
        git_trust_policy=git_trust_policy,
    )
    validate_campaign_input(campaign, report, toolchain)
    adapter_results = run_native_audits(
        repository,
        report.policy.native_audits,
        "full",
        trusted=trusted_native_audits,
    )
    post_runner = GitRunner(git_trust_policy)
    post_inventory = load_git_inventory(
        repository,
        git_runner=post_runner,
    )
    post_ignored = collect_ignored_inventory(
        post_inventory,
        report.policy.ignored_inventory,
        git_runner=post_runner,
    )
    post_state = (
        post_inventory.head,
        post_inventory.head_tree,
        post_inventory.object_format,
        post_inventory.branch,
        post_inventory.tracked_content_digest,
        post_inventory.dirty_paths,
        post_inventory.git_provenance.identity_digest,
    )
    report_state = (
        report.head,
        report.head_tree,
        report.git_object_format,
        report.branch,
        report.tracked_content_digest,
        report.dirty_paths,
        report.git_provenance.identity_digest,
    )
    if post_state != report_state:
        raise RuntimeError("native audit mutated tracked repository state; run not attested")
    if (
        post_ignored != report.ignored_inventory_evidence
        or ignored_inventory_digest(post_ignored) != report.ignored_inventory_digest
    ):
        raise RuntimeError("native audit mutated ignored inventory state; run not attested")
    attempted = frozenset(result.name for result in adapter_results)
    coverage = audit_domain_coverage(report.policy, attempted_adapters=attempted)
    covered_domains = tuple(
        item.domain for item in coverage if item.applicability == "required" and item.controls
    )
    omitted_domains = tuple(
        item.domain for item in coverage if item.applicability == "required" and not item.controls
    )
    limitations = tuple(
        f"required native audit failed: {result.name} (exit {result.returncode})"
        for result in adapter_results
        if result.required and not result.passed
    )
    command_digest = canonical_digest(
        {
            "operation": "campaign-run",
            "campaign": campaign.contract_digest,
            "scope": "full",
            "policy_path": campaign.policy_path,
            "adapter_evidence": [
                {
                    "name": result.name,
                    "spec_digest": result.spec_digest,
                    "executable_digest": result.executable_digest,
                    "command_digest": result.command_digest,
                    "environment_digest": result.environment_digest,
                    "sandbox_digest": result.sandbox_digest,
                    "sandbox_provenance_identity": (result.sandbox_provenance.identity_digest),
                }
                for result in adapter_results
            ],
            "git_provenance": report.git_provenance.identity_digest,
            "inference_identity": inference_identity.identity_digest,
        }
    )
    report_relative_path = f"runs/{run_id}/report.json"
    attestation = AuditRunAttestation.build(
        run_id=run_id,
        campaign=campaign,
        agent_identity=agent_identity,
        session_identity=session_identity,
        inference_identity=inference_identity,
        started_at=started_at,
        finished_at=_now(),
        status="complete",
        report_relative_path=report_relative_path,
        report=report,
        covered_domains=covered_domains,
        omitted_domains=omitted_domains,
        adapter_results=adapter_results,
        toolchain=toolchain,
        command_digest=command_digest,
        limitations=limitations,
    )
    directory = store_run(
        campaign_path,
        report,
        attestation,
        git_trust_policy=git_trust_policy,
    )
    return directory, attestation


def compare_campaign_runs(
    campaign_path: Path,
    *,
    comparison_id: str,
    actor: str,
    git_trust_policy: GitTrustPolicy | None = None,
) -> tuple[Path, AuditComparison]:
    """Compare all durable campaign runs and independent review records."""
    campaign = load_campaign(campaign_path)
    runs = load_runs(campaign_path)
    reviews = load_campaign_reviews(campaign_path)
    report_by_digest = {stored.report.report_digest: stored.report for stored in runs}
    for index, review_set in enumerate(reviews):
        digests = {review.report_digest for review in review_set}
        if len(digests) != 1:
            raise ValueError(f"review document {index} mixes report digests")
        report = report_by_digest.get(next(iter(digests)))
        if report is None:
            raise ValueError(f"review document {index} has no matching campaign report")
        errors = validate_reviews(report, review_set)
        if errors:
            raise ValueError(f"review document {index} is invalid: " + "; ".join(errors))
    comparison = compare_campaign(
        campaign,
        runs,
        reviews,
        comparison_id=comparison_id,
        created_by=actor,
        created_at=_now(),
    )
    path = store_comparison_record(
        campaign_path,
        comparison_id,
        comparison.to_dict(),
        git_trust_policy=git_trust_policy,
    )
    return path, comparison
