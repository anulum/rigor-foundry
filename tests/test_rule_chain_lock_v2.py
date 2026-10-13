# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed v2 effective lock structural tests
"""Exercise exact signed pack/profile/lock linkage without Guard admission."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_rule_chain_candidate_v2 import _chain
from test_rule_chain_pack_v2 import _clause, _freshness, _host_source, _pack
from test_semantic_acceptance_host_v2 import _host as acceptance_host

from rigor_foundry.adapter_operations_v2 import AdapterOperationsV2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.effective_profile import AdapterLock, PolicyContradiction
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.models import canonical_digest
from rigor_foundry.pack_source_host import HostPackSourceVerifier
from rigor_foundry.rule_chain_candidate_v2 import (
    RuleChainCandidateReportV2,
    inspect_rule_chain_candidate_v2,
)
from rigor_foundry.rule_chain_lock_v2 import EffectiveProfileLockV2, ResolutionStatus
from rigor_foundry.rule_chain_pack_v2 import (
    AuthorityClauseV2,
    FreshnessPolicyV2,
    StandardPackV2,
)
from rigor_foundry.rule_chain_profile_v2 import ProjectProfileV2
from rigor_foundry.signed_rule_chain_v2 import (
    RuleChainV2Signature,
    RuleChainV2TrustRoles,
    rule_chain_v2_payload_digest,
)

_NOW = datetime(2026, 9, 23, 0, 30, tzinfo=UTC)
_SIGNED_AT = "2026-09-23T00:10:00Z"
_RESOLVER_DIGEST = "d" * 64
_HOST_SELECTION = "e" * 64
_ISSUERS = ("owner",)
_KEY = "v2-lock-resolver"
_OPERATIONS_DIGEST = AdapterOperationsV2.empty(
    vocabulary=EffectVocabularyV2.build(),
    target_table=EffectTargetTableV2.build(),
    extractors=ExtractorRegistryV2.empty(),
).operations_digest


@dataclass(frozen=True)
class _Case:
    """Retain one signed chain and its live source verifier in a context."""

    report: RuleChainCandidateReportV2
    pack: StandardPackV2
    profile: ProjectProfileV2
    roles: RuleChainV2TrustRoles
    source: HostPackSourceVerifier
    adapters: tuple[AdapterLock, ...]
    lock: EffectiveProfileLockV2


def _adapter(adapter_id: str) -> AdapterLock:
    """Bind an exact synthetic host adapter identity for the lock."""
    return AdapterLock.build(
        adapter_id=adapter_id,
        version="1.0.0",
        executable_digest="1" * 64,
        config_digest="2" * 64,
        command_digest="3" * 64,
        environment_digest="4" * 64,
        domains=("application-security",),
    )


def _lock(
    report: RuleChainCandidateReportV2,
    pack: StandardPackV2,
    profile: ProjectProfileV2,
    source: HostPackSourceVerifier,
    adapters: tuple[AdapterLock, ...],
    *,
    clauses: tuple[AuthorityClauseV2, ...] | None = None,
    freshness: tuple[FreshnessPolicyV2, ...] | None = None,
    source_proof_digest: str | None = None,
    status: ResolutionStatus = "effective",
    contradictions: tuple[PolicyContradiction, ...] = (),
    resolved_at: str = _SIGNED_AT,
    effect_operations_digest: str = _OPERATIONS_DIGEST,
) -> EffectiveProfileLockV2:
    """Sign a candidate lock with a real test key and exact source proof."""
    proof = source.verify(
        pack_id=pack.pack_id, source_uri=pack.source_uri, source_digest=pack.source_digest
    )
    selected_proof = (
        cast(str, proof["source_verification_digest"])
        if source_proof_digest is None
        else source_proof_digest
    )
    body = EffectiveProfileLockV2.body(
        project_id=profile.project_id,
        profile_id=profile.profile_id,
        profile_digest=profile.profile_digest,
        selector_scope_digest=profile.selector_scope_digest,
        acceptance_digest=report.acceptance_digest,
        acceptance_host_selection_digest=_HOST_SELECTION,
        reviewer_policy_digest=report.reviewer_policy_digest,
        effect_operations_digest=effect_operations_digest,
        pack_digests=(pack.pack_digest,),
        pack_source_verification_digests=(selected_proof,),
        authority_clauses=pack.authority_clauses if clauses is None else clauses,
        successor_clause_digests=report.successor_clause_digests,
        freshness_policies=pack.freshness_policies if freshness is None else freshness,
        local_constraint_digests=profile.local_constraint_digests,
        excluded_clause_ids=profile.excluded_clause_ids,
        adapter_custody=adapters,
        issuer_order=_ISSUERS,
        resolution_status=status,
        contradictions=contradictions,
        resolved_at=resolved_at,
        resolver_code_digest=_RESOLVER_DIGEST,
    )
    digest = canonical_digest(body)
    payload = rule_chain_v2_payload_digest(
        object_kind="effective-profile-lock", body_digest=digest, signed_at=_SIGNED_AT
    )
    signature = RuleChainV2Signature.build(
        object_kind="effective-profile-lock",
        key_id=_KEY,
        body_digest=digest,
        signed_at=_SIGNED_AT,
        signature_hex=sign_message(_KEY, "rigor-foundry.effective-profile-lock.v2", payload),
    )
    return EffectiveProfileLockV2.build(
        project_id=profile.project_id,
        profile_id=profile.profile_id,
        profile_digest=profile.profile_digest,
        selector_scope_digest=profile.selector_scope_digest,
        acceptance_digest=report.acceptance_digest,
        acceptance_host_selection_digest=_HOST_SELECTION,
        reviewer_policy_digest=report.reviewer_policy_digest,
        effect_operations_digest=effect_operations_digest,
        pack_digests=(pack.pack_digest,),
        pack_source_verification_digests=(selected_proof,),
        authority_clauses=pack.authority_clauses if clauses is None else clauses,
        successor_clause_digests=report.successor_clause_digests,
        freshness_policies=pack.freshness_policies if freshness is None else freshness,
        local_constraint_digests=profile.local_constraint_digests,
        excluded_clause_ids=profile.excluded_clause_ids,
        adapter_custody=adapters,
        issuer_order=_ISSUERS,
        resolution_status=status,
        contradictions=contradictions,
        resolved_at=resolved_at,
        resolver_code_digest=_RESOLVER_DIGEST,
        signature=signature,
    )


@contextmanager
def _case(root: Path, *, nested: bool = False) -> Iterator[_Case]:
    """Inspect the four exact successors and sign a structural lock candidate."""
    proposal, state, inputs, pack, profile, roles = _chain(root, nested=nested)
    with _host_source() as source:
        report = inspect_rule_chain_candidate_v2(
            proposal=proposal,
            proposal_artifact=cast(bytes, inputs["proposal_artifact"]),
            proposal_source=cast(bytes, inputs["proposal_source"]),
            original_owner_question=cast(bytes, inputs["original_owner_question"]),
            original_owner_reply=cast(bytes, inputs["original_owner_reply"]),
            normative_source=cast(bytes, inputs["normative_source"]),
            ratification_manifest=cast(bytes, inputs["ratification_manifest"]),
            ratification_question=cast(bytes, inputs["ratification_question"]),
            ratification_reply=cast(bytes, inputs["ratification_reply"]),
            findings=cast(bytes, inputs["findings"]),
            acceptance_verifier=acceptance_host(state),
            packs=(pack,),
            profile=profile,
            source_verifiers={pack.pack_id: source},
            roles=roles,
            expected_project_id=profile.project_id,
            expected_scope_digest=profile.selector_scope_digest,
            now=_NOW,
        )
        adapters = (_adapter("fs-adapter"), _adapter("git-adapter"))
        yield _Case(
            report,
            pack,
            profile,
            roles,
            source,
            adapters,
            _lock(report, pack, profile, source, adapters),
        )


def _verify(
    case: _Case,
    lock: EffectiveProfileLockV2 | None = None,
    *,
    resolver_digest: str = _RESOLVER_DIGEST,
    issuer_order: tuple[str, ...] = _ISSUERS,
    operations_digest: str = _OPERATIONS_DIGEST,
) -> bool:
    """Exercise the complete public structural signature and source check."""
    selected = case.lock if lock is None else lock
    return selected.verify_structural_lock(
        candidate=case.report,
        profile=case.profile,
        packs=(case.pack,),
        source_verifiers={case.pack.pack_id: case.source},
        current_adapters=case.adapters,
        roles=case.roles,
        expected_acceptance_host_selection_digest=_HOST_SELECTION,
        expected_effect_operations_digest=operations_digest,
        expected_resolver_code_digest=resolver_digest,
        expected_issuer_order=issuer_order,
        now=_NOW,
    )


def test_exact_four_successor_lock_round_trip_is_structural_only(tmp_path: Path) -> None:
    """A real Ed25519 resolver signature binds the complete retained chain."""
    with _case(tmp_path) as case:
        assert EffectiveProfileLockV2.from_dict(case.lock.to_dict()) == case.lock
        assert _verify(case)
        assert case.report.guard_admissible is False
        assert not hasattr(case.lock, "guard_admissible")


@pytest.mark.parametrize(
    "field",
    [
        "lock_digest",
        "rule_projection_digest",
        "resolver_code_digest",
        "effect_operations_digest",
        "pack_digests",
        "schema_version",
    ],
)
def test_changed_lock_wire_refuses_exact_parser(tmp_path: Path, field: str) -> None:
    """Digest, selected inputs and version cannot change after signing."""
    with _case(tmp_path) as case:
        wire = case.lock.to_dict()
        wire[field] = "0" * 64
        with pytest.raises(ValueError):
            EffectiveProfileLockV2.from_dict(wire)


def test_host_resolver_digest_and_issuer_order_are_exact(tmp_path: Path) -> None:
    """A host-measured resolver change or different issuer policy holds the lock."""
    with _case(tmp_path) as case:
        assert not _verify(case, resolver_digest="0" * 64)
        assert not _verify(case, issuer_order=("owner", "vendor"))
        assert not _verify(case, issuer_order=("vendor", "owner"))
        assert not _verify(case, operations_digest="0" * 64)


def test_v2_lock_requires_operations_digest_field(tmp_path: Path) -> None:
    """An older lock cannot silently inherit effect-operation authority."""
    with _case(tmp_path) as case:
        wire = case.lock.to_dict()
        del wire["effect_operations_digest"]
        with pytest.raises(ValueError):
            EffectiveProfileLockV2.from_dict(wire)


def test_signed_resolver_cannot_substitute_pack_clause_contents(tmp_path: Path) -> None:
    """Matching IDs and text cannot conceal a changed scope in a signed lock."""
    with _case(tmp_path) as case:
        first = case.pack.authority_clauses[0]
        changed = AuthorityClauseV2.build(
            clause_id=first.clause_id,
            successor_id=first.successor_id,
            statement_digest=first.statement_digest,
            source_receipt_digest=first.source_receipt_digest,
            transition_digest=first.transition_digest,
            issuer_class=first.issuer_class,
            grantor_classes=first.grantor_classes,
            scope_digest="f" * 64,
            scope_selector_digest=first.scope_selector_digest,
            effect_class=first.effect_class,
            adapter_id=first.adapter_id,
        )
        clauses = (changed, *case.pack.authority_clauses[1:])
        forged_report = replace(
            case.report,
            successor_clause_digests=tuple(item.clause_digest for item in clauses),
        )
        forged_lock = _lock(
            forged_report, case.pack, case.profile, case.source, case.adapters, clauses=clauses
        )
        assert not _verify(replace(case, report=forged_report, lock=forged_lock))


def test_signed_resolver_cannot_substitute_pack_freshness(tmp_path: Path) -> None:
    """A valid resolver signature cannot change an event-bound source policy."""
    with _case(tmp_path) as case:
        selected = case.pack.freshness_policies[0]
        changed = FreshnessPolicyV2.build(
            policy_id=selected.policy_id,
            claim_type=selected.claim_type,
            subject_class=selected.subject_class,
            mode=selected.mode,
            risk_class="medium",
            invalidator_ids=selected.invalidator_ids,
            proof_adapter_id=selected.proof_adapter_id,
        )
        forged = _lock(
            case.report,
            case.pack,
            case.profile,
            case.source,
            case.adapters,
            freshness=(changed,),
        )
        assert not _verify(case, lock=forged)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("pack_digests", []),
        ("pack_source_verification_digests", []),
        ("authority_clauses", []),
        ("freshness_policies", []),
        ("successor_clause_digests", []),
        ("successor_clause_digests", ["0" * 64] * 4),
        ("local_constraint_digests", ["b" * 64, "b" * 64]),
        ("excluded_clause_ids", ["core/authority-1"]),
        ("issuer_order", ["vendor"]),
        ("acceptance_digest", "0" * 64),
        ("resolution_status", "held"),
        ("resolution_status", "unknown"),
    ],
)
def test_malformed_resolved_projection_refuses_before_signature(
    tmp_path: Path, field: str, replacement: object
) -> None:
    """Selected packs, rules, evidence, grantors and held status stay exact."""
    with _case(tmp_path) as case:
        wire = case.lock.to_dict()
        wire[field] = replacement
        with pytest.raises(ValueError):
            EffectiveProfileLockV2.from_dict(wire)


def test_duplicate_selected_objects_and_nonblocking_hold_refuse(tmp_path: Path) -> None:
    """Repeated IDs and a nonblocking contradiction cannot form an effective lock."""
    with _case(tmp_path) as case:
        for field in ("authority_clauses", "freshness_policies", "adapter_custody"):
            wire = case.lock.to_dict()
            items = cast(list[object], wire[field])
            wire[field] = [*items, items[0]]
            with pytest.raises(ValueError):
                EffectiveProfileLockV2.from_dict(wire)
        warning = PolicyContradiction.build(
            code="warning",
            subject="scope",
            sources=("core",),
            detail="nonblocking",
            blocking=False,
        )
        wire = case.lock.to_dict()
        wire["contradictions"] = [warning.to_dict()]
        with pytest.raises(ValueError, match="hold status"):
            EffectiveProfileLockV2.from_dict(wire)


def test_invalid_host_inputs_key_lifecycle_and_source_proof_refuse(tmp_path: Path) -> None:
    """A signature cannot override current host code, key lifecycle or source."""
    with _case(tmp_path) as case:
        assert not _verify(case, resolver_digest="invalid")
        assert not _verify(case, issuer_order=())
        assert not case.lock.verify_structural_lock(
            candidate=case.report,
            profile=case.profile,
            packs=(case.pack,),
            source_verifiers={case.pack.pack_id: case.source},
            current_adapters=case.adapters,
            roles=case.roles,
            expected_acceptance_host_selection_digest=_HOST_SELECTION,
            expected_effect_operations_digest=_OPERATIONS_DIGEST,
            expected_resolver_code_digest=_RESOLVER_DIGEST,
            expected_issuer_order=_ISSUERS,
            now=datetime(2026, 10, 22, tzinfo=UTC),
        )
        wrong_source = _lock(
            case.report,
            case.pack,
            case.profile,
            case.source,
            case.adapters,
            source_proof_digest="0" * 64,
        )
        assert not _verify(case, lock=wrong_source)
        assert not _verify(case, lock=replace(case.lock, rule_projection_digest="0" * 64))


def test_invalid_build_status_and_signed_hold_remain_non_admissible(tmp_path: Path) -> None:
    """Only typed held locks with blocking contradictions can be retained."""
    with _case(tmp_path) as case:
        with pytest.raises(ValueError, match="resolution status"):
            _lock(
                case.report,
                case.pack,
                case.profile,
                case.source,
                case.adapters,
                status=cast(ResolutionStatus, "unknown"),
            )
        blocker = PolicyContradiction.build(
            code="conflict", subject="effect", sources=("core",), detail="held"
        )
        held = _lock(
            case.report,
            case.pack,
            case.profile,
            case.source,
            case.adapters,
            status="held",
            contradictions=(blocker,),
        )
        assert EffectiveProfileLockV2.from_dict(held.to_dict()) == held
        assert not _verify(case, lock=held)


def test_resolution_cannot_be_later_than_resolver_signature(tmp_path: Path) -> None:
    """A backdated resolver signature cannot claim a later resolved state."""
    with _case(tmp_path) as case:
        forged = _lock(
            case.report,
            case.pack,
            case.profile,
            case.source,
            case.adapters,
            resolved_at="2026-09-23T00:11:00Z",
        )
        assert not _verify(case, lock=forged)


@pytest.mark.parametrize("duplicate", ["clause", "freshness"])
def test_cross_pack_duplicate_ids_refuse_lock_resolution(tmp_path: Path, duplicate: str) -> None:
    """A second signed pack cannot replace one selected source rule by ID."""
    with _case(tmp_path, nested=True) as case:
        aux = _pack(
            pack_id="core/shared",
            transition=case.report.acceptance_digest,
            clauses=(
                _clause(
                    clause_id=(
                        "core/shared/authority-1"
                        if duplicate == "clause"
                        else "core/shared/other-authority"
                    ),
                    transition_digest=case.report.acceptance_digest,
                ),
            ),
            policies=(
                _freshness(
                    policy_id=(
                        "core/shared/freshness"
                        if duplicate == "freshness"
                        else "core/shared/other-freshness"
                    )
                ),
            ),
        )
        assert not case.lock.verify_structural_lock(
            candidate=case.report,
            profile=case.profile,
            packs=(case.pack, aux),
            source_verifiers={case.pack.pack_id: case.source},
            current_adapters=case.adapters,
            roles=case.roles,
            expected_acceptance_host_selection_digest=_HOST_SELECTION,
            expected_effect_operations_digest=_OPERATIONS_DIGEST,
            expected_resolver_code_digest=_RESOLVER_DIGEST,
            expected_issuer_order=_ISSUERS,
            now=_NOW,
        )
