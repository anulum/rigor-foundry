# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — campaign comparison schema relation tests
"""Verify correlation witness and durable comparison schema relations."""

from pathlib import Path

import pytest
from campaign_compare_support import (
    build_inference_identity,
    campaign_runs,
    stored_run,
)

from rigor_foundry.campaign_compare import AuditComparison, compare_campaign
from rigor_foundry.campaign_identity import ModelWitness
from rigor_foundry.campaign_models import AuditCampaign
from rigor_foundry.models import canonical_digest


def test_promotion_comparison_requires_cross_model_and_operator_independence(
    tmp_path: Path,
) -> None:
    """Two distinct model families and operators satisfy identity diligence."""
    _diagnostic, runs = campaign_runs(tmp_path)
    baseline = runs[0]
    campaign = AuditCampaign.build(
        baseline.report,
        campaign_id="promotion-independent",
        project="SAMPLE-PROJECT",
        policy_path="rigor-foundry-policy.json",
        toolchain=baseline.attestation.toolchain,
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
        purpose="promotion",
        expected_runs=2,
        required_model_witnesses=2,
    )
    independent = tuple(
        stored_run(
            campaign,
            baseline,
            run_id=f"independent-{index}",
            report=baseline.report,
            toolchain=campaign.toolchain,
            agent_identity=f"SAMPLE-PROJECT/agent-{index}",
            inference_identity=build_inference_identity(f"family-{index}"),
        )
        for index in (1, 2)
    )

    comparison = compare_campaign(
        campaign,
        independent,
        ((),),
        comparison_id="independent-comparison",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.actual_model_witnesses == 2
    assert not comparison.unresolved
    assert comparison.promotion_eligible
    assert comparison.diligence_gaps == ()


def test_comparison_parser_rejects_schema_relations_and_digest_tampering(
    tmp_path: Path,
) -> None:
    """Durable comparisons reject malformed arrays, counts, status, and identity."""
    campaign, runs = campaign_runs(tmp_path)
    comparison = compare_campaign(
        campaign,
        runs,
        ((),),
        comparison_id="parser-comparison",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )
    assert AuditComparison.from_dict(comparison.to_dict()) == comparison

    cases: tuple[tuple[str, object, str], ...] = (
        ("schema_version", "2.0", "schema version"),
        ("purpose", "release", "comparison purpose"),
        ("model_witnesses", {}, "must be an array"),
        ("unresolved", "false", "must be booleans"),
        ("comparison_id", "../comparison", "portable identifier"),
        ("created_at", "not-a-time", "ISO-8601 UTC timestamp"),
        ("run_ids", ["agent-2", "agent-1"], "sorted and contain unique"),
        ("promotion_eligible", True, "eligibility does not match"),
        ("unresolved", True, "unresolved status does not match"),
        ("actual_run_count", 1, "run count does not match"),
        ("actual_model_witnesses", 1, "witness count does not match"),
        ("required_model_witnesses", 3, "required witnesses exceed"),
        ("report_digests", [], "report digests do not match"),
        ("agent_identities", [], "agent identities do not match"),
    )
    for field, value, message in cases:
        changed = comparison.to_dict()
        changed[field] = value
        with pytest.raises(ValueError, match=message):
            AuditComparison.from_dict(changed)

    missing_attestation = comparison.to_dict()
    missing_attestation["attestation_digests"] = list(comparison.attestation_digests[:-1])
    with pytest.raises(ValueError, match="run count does not match attestations"):
        AuditComparison.from_dict(missing_attestation)

    reversed_witnesses = comparison.to_dict()
    reversed_witnesses["model_witnesses"] = list(reversed(reversed_witnesses["model_witnesses"]))
    with pytest.raises(ValueError, match="sorted with unique correlation components"):
        AuditComparison.from_dict(reversed_witnesses)

    excess_witnesses = comparison.to_dict()
    excess_witnesses["model_witnesses"] = [
        *excess_witnesses["model_witnesses"],
        ModelWitness.build(
            model_families=("family-3",),
            exact_models=(("provider-family-3", "family-3-v1"),),
            operators=("operator-family-3",),
            run_ids=("agent-1",),
        ).to_dict(),
    ]
    excess_witnesses["actual_model_witnesses"] = 3
    with pytest.raises(ValueError, match="model witnesses exceed actual runs"):
        AuditComparison.from_dict(excess_witnesses)

    overlapping_witnesses = comparison.to_dict()
    witness_documents = list(overlapping_witnesses["model_witnesses"])
    first_witness = dict(witness_documents[0])
    first_witness["run_ids"] = ["agent-2"]
    first_witness.pop("witness_digest")
    first_witness["witness_digest"] = canonical_digest(first_witness)
    witness_documents[0] = first_witness
    overlapping_witnesses["model_witnesses"] = witness_documents
    with pytest.raises(ValueError, match="do not partition run identifiers"):
        AuditComparison.from_dict(overlapping_witnesses)

    repeated_family = comparison.to_dict()
    repeated_family_witnesses = list(repeated_family["model_witnesses"])
    repeated_family_second = dict(repeated_family_witnesses[1])
    repeated_family_second["model_families"] = list(repeated_family_witnesses[0]["model_families"])
    repeated_family_second.pop("witness_digest")
    repeated_family_second["witness_digest"] = canonical_digest(repeated_family_second)
    repeated_family_witnesses[1] = repeated_family_second
    repeated_family["model_witnesses"] = repeated_family_witnesses
    repeated_family.pop("comparison_digest")
    repeated_family["comparison_digest"] = canonical_digest(repeated_family)
    with pytest.raises(ValueError, match="model family appears in multiple"):
        AuditComparison.from_dict(repeated_family)

    repeated_exact_model = comparison.to_dict()
    repeated_exact_witnesses = list(repeated_exact_model["model_witnesses"])
    repeated_exact_second = dict(repeated_exact_witnesses[1])
    repeated_exact_second["exact_models"] = list(repeated_exact_witnesses[0]["exact_models"])
    repeated_exact_second["providers"] = list(repeated_exact_witnesses[0]["providers"])
    repeated_exact_second["models"] = list(repeated_exact_witnesses[0]["models"])
    repeated_exact_second.pop("witness_digest")
    repeated_exact_second["witness_digest"] = canonical_digest(repeated_exact_second)
    repeated_exact_witnesses[1] = repeated_exact_second
    repeated_exact_model["model_witnesses"] = repeated_exact_witnesses
    repeated_exact_model.pop("comparison_digest")
    repeated_exact_model["comparison_digest"] = canonical_digest(repeated_exact_model)
    with pytest.raises(ValueError, match="exact model appears in multiple"):
        AuditComparison.from_dict(repeated_exact_model)

    changed_digest = comparison.to_dict()
    changed_digest["created_by"] = "coordinator/two"
    with pytest.raises(ValueError, match="digest does not match"):
        AuditComparison.from_dict(changed_digest)

    unrecognised = comparison.to_dict()
    unrecognised["extra"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        AuditComparison.from_dict(unrecognised)

    with pytest.raises(ValueError, match="portable identifier"):
        compare_campaign(
            campaign,
            runs,
            ((),),
            comparison_id="../comparison",
            created_by="coordinator/one",
            created_at="2026-07-15T13:00:00Z",
        )
    with pytest.raises(ValueError, match="must use UTC"):
        compare_campaign(
            campaign,
            runs,
            ((),),
            comparison_id="comparison-time",
            created_by="coordinator/one",
            created_at="2026-07-15T15:00:00+02:00",
        )
