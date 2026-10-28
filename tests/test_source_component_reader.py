# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual original component resolution tests
"""Resolve original control, authority and freshness records without changing their wires."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import cast

import pytest
from test_assessment_evidence_validation import attestation
from test_control_assessment import evidence
from test_policy_model_inputs import budget
from test_standard_pack import control
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.control_assessment import EvidenceReference
from rigor_foundry.policy_model_inputs import policy_wire_size
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2
from rigor_foundry.source_component_reader import (
    PolicyComponent,
    PolicyComponent1,
    resolve_policy_component,
)
from rigor_foundry.standard_pack import EvidenceContract, RemediationContract
from rigor_foundry.typed_object_reference import TypedObjectRef1


@pytest.mark.parametrize("signed_review", [False, True])
def test_original_evidence_and_signed_review_keep_complete_owner_wire(signed_review: bool) -> None:
    """Headerless evidence and spaced signed reviewer identities retain exact original bytes."""
    original = (
        attestation(reviewer_id="Independent Source Reviewer") if signed_review else evidence()
    )
    source = PolicyComponent1(original, budget())
    ref = source.reference()
    assert source.to_dict() == original.to_dict()
    assert PolicyComponent1.from_dict(ref.kind, source.to_dict(), budget=budget()) == source
    assert resolve_policy_component(ref, (source,), budget=budget()) == source
    if signed_review:
        assert ref.kind == "review-attestation" and ref.format_version == "2.0"
        assert ref.object_id == ref.object_digest == source.to_dict()["attestation_digest"]
        assert source.to_dict()["reviewer_id"] == "Independent Source Reviewer"
        assert source.to_dict()["signature_domain"] == "rigor-foundry.reviewer-attestation.v1"
        assert len(source.to_dict()) == 13
    else:
        assert (ref.kind, ref.format_version, ref.object_id, ref.object_digest) == (
            "evidence-reference",
            "1.0",
            evidence().evidence_id,
            evidence().evidence_digest,
        )
        assert len(source.to_dict()) == 11
        assert "schema_version" not in source.to_dict() and "object_kind" not in source.to_dict()


def test_fixed_legacy_evidence_reader_closes_the_permissive_original_before_parsing() -> None:
    """An actual original positive control demonstrates why header/extra keys must refuse first."""
    original = evidence()
    data = original.to_dict()
    extensions: tuple[dict[str, object], ...] = (
        {"extra": True},
        {"schema_version": "1.0"},
        {"object_kind": "evidence-reference"},
    )
    for extension in extensions:
        extended = {**data, **extension}
        assert EvidenceReference.from_dict(extended) == original
        with pytest.raises(ValueError, match="original evidence reference"):
            PolicyComponent1.from_dict("evidence-reference", extended, budget=budget())
    alias = {**data, "observed_at": original.observed_at.replace("Z", "+00:00")}
    assert EvidenceReference.from_dict(alias) == original
    with pytest.raises(ValueError, match="wire must remain unchanged"):
        PolicyComponent1.from_dict("evidence-reference", alias, budget=budget())
    for field, value in [
        ("evidence_digest", "0" * 64),
        ("artifact_size", True),
        ("classification", "caller"),
    ]:
        with pytest.raises(ValueError):
            PolicyComponent1.from_dict(
                "evidence-reference", {**data, field: value}, budget=budget()
            )
    with pytest.raises(ValueError, match="document byte budget"):
        PolicyComponent1(original, budget(size=1))


def test_review_reader_preserves_original_domain_and_rejects_wire_aliases() -> None:
    """A schema2 attestation never acquires a v2 signature domain or a portable reviewer ID."""
    original = attestation(reviewer_id="Reviewer With Spaces")
    wire = original.to_dict()
    for field, value in [
        ("schema_version", "1.0"),
        ("signature_domain", "rigor-foundry.reviewer-attestation.v2"),
        ("attestation_digest", "0" * 64),
        ("extra", "discard"),
    ]:
        with pytest.raises(ValueError):
            PolicyComponent1.from_dict(
                "review-attestation", {**wire, field: value}, budget=budget()
            )
    alias = {**wire, "reviewed_at": original.reviewed_at.replace("Z", "+00:00")}
    from rigor_foundry.review_attestation import ReviewerAttestation

    assert ReviewerAttestation.from_dict(alias) == original
    with pytest.raises(ValueError, match="wire must remain unchanged"):
        PolicyComponent1.from_dict("review-attestation", alias, budget=budget())


def test_standalone_original_evidence_owner_retains_numeric_obligations() -> None:
    """A quality projection resolves the actual legacy contract rather than a fabricated lock."""
    original = control().evidence
    source = PolicyComponent1(original, budget())
    ref = source.reference()
    assert (ref.kind, ref.format_version, ref.object_id, ref.object_digest) == (
        "evidence-contract",
        "1.0",
        original.contract_id,
        original.contract_digest,
    )
    assert source.to_dict() == original.to_dict()
    assert resolve_policy_component(ref, (source,), budget=budget()).record == original
    assert PolicyComponent1.from_dict(ref.kind, original.to_dict(), budget=budget()) == source
    for field in ["freshness_seconds", "minimum_independent_reviewers"]:
        wire = original.to_dict()
        wire[field] = 0
        wire.pop("contract_digest")
        wire["contract_digest"] = canonical_digest(wire)
        with pytest.raises(ValueError):
            PolicyComponent1.from_dict("evidence-contract", wire, budget=budget())
    for malformed in [
        replace(original, required_adapters=cast(tuple[str, ...], ["adapter"])),
        replace(original, evidence_types=tuple(f"type-{i}" for i in range(129))),
    ]:
        with pytest.raises(ValueError):
            PolicyComponent1(malformed, budget())
    with pytest.raises(ValueError, match="reference budget"):
        PolicyComponent1.from_dict(
            "evidence-contract", original.to_dict(), budget=budget(references=1)
        )
    with pytest.raises(ValueError):
        PolicyComponent1.from_dict(
            "evidence-contract", {**original.to_dict(), "extension": True}, budget=budget()
        )


def components() -> tuple[PolicyComponent1, ...]:
    """Build all supported original owners using their unchanged public builders."""
    authority = AuthorityClauseV2.build(
        clause_id="authority",
        successor_id="successor",
        statement_digest="1" * 64,
        source_receipt_digest="2" * 64,
        transition_digest="3" * 64,
        issuer_class="source-owner",
        grantor_classes=("owner",),
        scope_digest="4" * 64,
        scope_selector_digest="5" * 64,
        effect_class="local-write",
        adapter_id="file-adapter",
    )
    freshness = FreshnessPolicyV2.build(
        policy_id="freshness",
        claim_type="source-state",
        subject_class="source",
        mode="mutable-state",
        risk_class="high",
        invalidator_ids=("source-change",),
        proof_adapter_id="source-adapter",
    )
    return tuple(PolicyComponent1(item, budget()) for item in (control(), authority, freshness))


@pytest.mark.parametrize("index", [0, 1, 2])
def test_original_component_bytes_ids_and_owning_digests_are_preserved(index: int) -> None:
    """Each fixed reader resolves its actual parser and original digest field."""
    cohort = components()
    value = cohort[index]
    ref = value.reference()
    assert PolicyComponent1.from_dict(ref.kind, value.to_dict(), budget=budget()) == value
    assert resolve_policy_component(ref, cohort, budget=budget()) == value
    assert value.to_dict() == value.record.to_dict()
    assert "object_kind" not in value.to_dict()
    assert ref.object_digest in {
        value.to_dict().get("control_digest"),
        value.to_dict().get("clause_digest"),
        value.to_dict().get("policy_digest"),
    }
    assert cohort[0].reference().object_id == control().versioned_id
    assert cohort[0].to_dict()["evidence"] == control().evidence.to_dict()
    condition = control().condition
    assert condition is not None
    assert cohort[0].to_dict()["condition"] == condition.to_dict()


def test_missing_foreign_kind_wrong_digest_and_duplicate_targets_all_refuse() -> None:
    """A same-looking reference or duplicate cohort cannot substitute the original owner."""
    cohort = components()
    ref = cohort[0].reference()
    for missing in [(), cohort[1:]]:
        with pytest.raises(ValueError, match="unresolved"):
            resolve_policy_component(ref, missing, budget=budget())
    false_ref = TypedObjectRef1.build(
        kind=ref.kind,
        format_version=ref.format_version,
        object_id=ref.object_id,
        object_digest="0" * 64,
    )
    with pytest.raises(ValueError, match="original owning digest"):
        resolve_policy_component(false_ref, cohort, budget=budget())
    with pytest.raises(ValueError, match="duplicate identity"):
        resolve_policy_component(ref, (*cohort, cohort[0]), budget=budget())
    with pytest.raises(ValueError, match="unsupported original"):
        resolve_policy_component(reference(), cohort, budget=budget())
    with pytest.raises(ValueError, match="actual typed"):
        resolve_policy_component(cast(TypedObjectRef1, {}), cohort, budget=budget())
    with pytest.raises(ValueError, match="unsupported policy component kind"):
        PolicyComponent1.from_dict("appointed-reader", {}, budget=budget())


def test_unselected_corruption_and_nonowner_readers_refuse_before_returning_a_match() -> None:
    """The target's early match never hides a malformed later member of the supplied cohort."""
    cohort = components()
    object.__setattr__(cohort[-1].record, "policy_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        resolve_policy_component(cohort[0].reference(), cohort, budget=budget())
    with pytest.raises(ValueError, match="actual original readers"):
        resolve_policy_component(
            cohort[0].reference(), (cast(PolicyComponent1, {}),), budget=budget()
        )
    with pytest.raises(ValueError, match="actual supported original"):
        PolicyComponent1(cast(PolicyComponent, {}), budget())


def test_exact_collection_and_aggregate_cohort_budgets_apply() -> None:
    """Count and whole-cohort bytes are bounded even when each original record fits."""
    cohort = components()
    ref = cohort[0].reference()
    with pytest.raises(ValueError, match="immutable reference budget"):
        resolve_policy_component(
            ref, cast(tuple[PolicyComponent1, ...], list(cohort)), budget=budget()
        )
    limits = budget().to_dict()
    limits.pop("budget_digest")
    limits["max_references"] = 1
    with pytest.raises(ValueError, match="immutable reference budget"):
        resolve_policy_component(
            ref,
            cohort,
            budget=PolicyReadBudget1.from_dict(
                {**limits, "budget_digest": canonical_digest(limits)}
            ),
        )
    # All individual bodies fit, but their complete encoded cohort does not.
    size = 2 + max(policy_wire_size(item.to_dict(), budget=budget()) for item in cohort)
    with pytest.raises(ValueError, match="aggregate byte budget"):
        resolve_policy_component(ref, cohort, budget=budget(size=size))


def test_original_serializers_cannot_run_mutable_or_unbounded_child_sequences() -> None:
    """Direct legacy records must retain actual child owners and immutable bounded arrays."""
    original = control()
    for invalid_control in [
        replace(original, evidence=cast(EvidenceContract, {})),
        replace(original, remediation=cast(RemediationContract, {})),
    ]:
        with pytest.raises(ValueError, match="actual evidence and remediation"):
            PolicyComponent1(invalid_control, budget())
    for value in [
        replace(
            original,
            evidence=replace(original.evidence, required_adapters=cast(tuple[str, ...], [])),
        ),
        replace(
            original, remediation=replace(original.remediation, acceptance_gates=("gate",) * 129)
        ),
    ]:
        with pytest.raises(ValueError):
            PolicyComponent1(value, budget())
    with pytest.raises(ValueError, match="condition"):
        PolicyComponent1(replace(original, condition=cast(ConditionExpression, {})), budget())


def test_original_parser_refuses_normalization_unknown_child_fields_and_finite_overflow() -> None:
    """Original numeric freshness/review obligations are never dropped or replaced by placeholders."""
    original = control()
    data = original.to_dict()
    remediation = cast(dict[str, object], data["remediation"])
    remediation["ignored_extension"] = True
    with pytest.raises(ValueError, match="remain unchanged"):
        PolicyComponent1.from_dict("control-definition", data, budget=budget())
    data = deepcopy(original.to_dict())
    expression = cast(dict[str, object], data["condition"])
    expression["value"] = 10**400
    expression.pop("expression_digest")
    expression["expression_digest"] = canonical_digest(expression)
    with pytest.raises(ValueError, match="finite numeric domain"):
        PolicyComponent1.from_dict("control-definition", data, budget=budget())
    data = original.to_dict()
    evidence = cast(dict[str, object], data["evidence"])
    evidence["freshness_seconds"] = 0
    with pytest.raises(ValueError):
        PolicyComponent1.from_dict("control-definition", data, budget=budget())


def test_original_unconditional_control_keeps_its_legacy_default_and_numeric_contract() -> None:
    """An absent old condition remains absent rather than becoming a fabricated scope expression."""
    data = control().to_dict()
    data["condition"] = None
    data.pop("control_digest")
    data["control_digest"] = canonical_digest(data)
    value = PolicyComponent1.from_dict("control-definition", data, budget=budget())
    assert value.to_dict() == data
    assert value.to_dict()["default_applicable"] is True
    assert value.to_dict()["evidence"] == control().evidence.to_dict()


def test_wire_collection_bounds_precede_original_child_parser_allocations() -> None:
    """Complete valid legacy inputs refuse a smaller allocation ceiling before child construction."""
    with pytest.raises(ValueError, match="reference budget"):
        PolicyComponent1.from_dict(
            "control-definition", control().to_dict(), budget=budget(references=5)
        )
    data = components()[1].to_dict()
    data["grantor_classes"] = "owner"
    with pytest.raises(ValueError, match="closed child sequences"):
        PolicyComponent1.from_dict("authority-clause", data, budget=budget())


def reviewer_source(*, revoked: bool = False) -> PolicyComponent1:
    """Bind real public keys and the unchanged original identity/lifecycle policy."""
    from signing_fixtures import public_key_hex

    from rigor_foundry.semantic_acceptance_policy import (
        ReviewerIdentityBinding,
        ReviewerIdentityPolicy,
    )
    from rigor_foundry.trust import TrustedPublicKey
    from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

    keys = tuple(
        VerificationKeyPolicy.build(
            key=TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id)),
            valid_from="2026-10-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            revoked_at="2026-10-20T00:00:00Z" if revoked else "",
            enrolled_identity=identity,
        )
        for key_id, identity in [
            ("first-reviewer", "review/primary"),
            ("second-reviewer", "review/secondary"),
        ]
    )
    trust = OfflineTrustPolicy.build(keys)
    policy = ReviewerIdentityPolicy.build(
        trust_policy=trust,
        bindings=(
            ReviewerIdentityBinding("first-reviewer", "review/primary"),
            ReviewerIdentityBinding("second-reviewer", "review/secondary"),
        ),
    )
    return PolicyComponent1(policy, budget())


def adapter_source() -> PolicyComponent1:
    """Retain the actual interpreter bytes and complete original adapter custody fields."""
    import hashlib
    import sys
    from pathlib import Path

    from rigor_foundry.effective_profile import AdapterLock

    executable = Path(sys.executable).resolve(strict=True)
    adapter = AdapterLock.build(
        adapter_id="python-runtime",
        version=".".join(str(value) for value in sys.version_info[:3]),
        executable_digest=hashlib.sha256(executable.read_bytes()).hexdigest(),
        config_digest=hashlib.sha256(b"complete fixture configuration\n").hexdigest(),
        command_digest=canonical_digest([str(executable), "--version"]),
        environment_digest=canonical_digest({"LANG": "C.UTF-8"}),
        domains=("operations-and-observability",),
    )
    return PolicyComponent1(adapter, budget())


def test_original_review_and_adapter_sources_retain_exact_bytes_and_meaning() -> None:
    """Identity is content-addressed and adapter reference format adds no original wire fields."""
    from datetime import UTC, datetime

    from rigor_foundry.effective_profile import AdapterLock
    from rigor_foundry.semantic_acceptance_policy import (
        REVIEWER_IDENTITY_POLICY_SCHEMA,
        ReviewerIdentityPolicy,
    )

    sources = (adapter_source(), reviewer_source())
    for source in sources:
        ref = source.reference()
        assert PolicyComponent1.from_dict(ref.kind, source.to_dict(), budget=budget()) == source
        assert resolve_policy_component(ref, sources, budget=budget()) == source
        assert source.to_dict() == source.record.to_dict()
    adapter, reviewer = sources
    assert isinstance(adapter.record, AdapterLock)
    assert adapter.reference().object_id == adapter.record.adapter_id
    assert adapter.reference().object_digest == adapter.record.adapter_digest
    assert "schema_version" not in adapter.to_dict()
    assert "object_kind" not in adapter.to_dict()
    assert isinstance(reviewer.record, ReviewerIdentityPolicy)
    assert reviewer.reference().object_id == reviewer.record.policy_digest
    assert reviewer.reference().format_version == REVIEWER_IDENTITY_POLICY_SCHEMA
    revoked = reviewer_source(revoked=True)
    assert isinstance(revoked.record, ReviewerIdentityPolicy)
    assert (
        revoked.record.trust_policy.key_status(
            "first-reviewer", datetime(2026, 10, 28, tzinfo=UTC)
        )
        == "revoked"
    )
    assert (
        PolicyComponent1.from_dict(revoked.reference().kind, revoked.to_dict(), budget=budget())
        == revoked
    )
    assert "accepted" not in revoked.to_dict()


def test_review_sources_refuse_wrong_direct_children_before_original_serialization() -> None:
    """Only the original public trust, key-policy, key and identity-binding types can serialize."""
    from rigor_foundry.semantic_acceptance_policy import (
        ReviewerIdentityBinding,
        ReviewerIdentityPolicy,
    )
    from rigor_foundry.trust import TrustedPublicKey
    from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

    source = reviewer_source()
    assert isinstance(source.record, ReviewerIdentityPolicy)
    policy = source.record
    invalid_policies = [
        replace(policy, trust_policy=cast(OfflineTrustPolicy, {})),
        replace(policy, bindings=(cast(ReviewerIdentityBinding, {}),)),
        replace(
            policy,
            trust_policy=replace(policy.trust_policy, keys=(cast(VerificationKeyPolicy, {}),)),
        ),
        replace(
            policy,
            trust_policy=replace(
                policy.trust_policy,
                keys=(replace(policy.trust_policy.keys[0], key=cast(TrustedPublicKey, {})),),
            ),
        ),
    ]
    for invalid in invalid_policies:
        with pytest.raises(ValueError, match="actual original"):
            PolicyComponent1(invalid, budget())
    with pytest.raises(ValueError, match="reference budget"):
        PolicyComponent1.from_dict(
            source.reference().kind, source.to_dict(), budget=budget(references=3)
        )
    data = source.to_dict()
    data["bindings"] = "appointed-reviewer"
    with pytest.raises(ValueError, match="closed child sequences"):
        PolicyComponent1.from_dict(source.reference().kind, data, budget=budget())
    data = adapter_source().to_dict()
    data["schema_version"] = "1.0"
    with pytest.raises(ValueError, match="fields do not match"):
        PolicyComponent1.from_dict("adapter-lock", data, budget=budget())


def test_original_adapter_permissive_parser_does_not_relax_the_new_closed_source_boundary() -> (
    None
):
    """Exercise the real original extra-field behavior and require exact pre-parser keys."""
    from rigor_foundry.effective_profile import AdapterLock

    source = adapter_source()
    original = source.to_dict()
    extended = {**original, "unexpected": True}
    assert AdapterLock.from_dict(extended).to_dict() == original
    for invalid in [extended, {key: value for key, value in original.items() if key != "domains"}]:
        with pytest.raises(ValueError, match="fields do not match"):
            PolicyComponent1.from_dict("adapter-lock", invalid, budget=budget())
    assert source.reference().format_version == "1.0"
    assert "schema_version" not in source.to_dict()
