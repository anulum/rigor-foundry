# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — scope-bound signed selected-chain integration
"""Exercise one signed pack, selected lock, and exact clause semantics together."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import cast

from signing_fixtures import sign_message
from test_clause_semantics_set_v2 import _entry
from test_project_registry_models import group, project
from test_project_registry_models import registry as project_registry
from test_rule_chain_lock_v2 import _lock
from test_rule_chain_pack_v2 import _pack
from test_rule_chain_profile_v2 import _profile
from test_selected_rule_chain_host_v2 import _selected

from rigor_foundry.clause_semantics_binding_v2 import bind_clause_semantics_v2
from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.constraint_evaluator_registry_v2 import ConstraintEvaluatorRegistryV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.models import canonical_digest
from rigor_foundry.rule_chain_candidate_v2 import inspect_rule_chain_candidate_v2
from rigor_foundry.rule_chain_pack_v2 import AuthorityClauseV2
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    HostSelectedRuleChainVerifierV2,
)
from rigor_foundry.signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2
from rigor_foundry.signed_rule_chain_v2 import (
    RuleChainV2Signature,
    RuleObjectKind,
    rule_chain_v2_payload_digest,
)

_GROUP = "AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS"
_AUTHOR_KEY = "v2-semantic-author"
_REVIEWER_KEY = "fixture-ceo-reviewer-key"


def _signature(kind: str, digest: str, signed_at: str) -> RuleChainV2Signature:
    """Sign one fixture body with the selected author or CEO reviewer key."""
    if kind == "clause-semantics-set-author":
        key, domain = _AUTHOR_KEY, "rigor-foundry.clause-semantics-set-author.v2"
    else:
        key, domain = _REVIEWER_KEY, "rigor-foundry.clause-semantics-set.v2"
    payload = rule_chain_v2_payload_digest(
        object_kind=cast(RuleObjectKind, kind), body_digest=digest, signed_at=signed_at
    )
    return RuleChainV2Signature.build(
        object_kind=cast(RuleObjectKind, kind),
        key_id=key,
        body_digest=digest,
        signed_at=signed_at,
        signature_hex=sign_message(key, domain, payload),
    )


def _scope_bound_state(
    state: HostSelectedRuleChainStateV2,
    *,
    entry_mutator: Callable[[int, dict[str, object]], None] | None = None,
) -> tuple[HostSelectedRuleChainStateV2, SignedClauseSemanticsSetV2]:
    """Re-sign four successors and matching semantics, including fixture variants."""
    original = state.packs[0]
    vocabulary = EffectVocabularyV2.build()
    evaluators = ConstraintEvaluatorRegistryV2.build()
    target_table = EffectTargetTableV2.build()
    entries: list[dict[str, object]] = []
    clauses: list[AuthorityClauseV2] = []
    for number, old in enumerate(original.authority_clauses, start=1):
        entry = _entry(number, "admit")
        if entry_mutator is not None:
            entry_mutator(number, entry)
        scope = cast(dict[str, object], entry["scope"])
        clause = AuthorityClauseV2.build(
            clause_id=old.clause_id,
            successor_id=old.successor_id,
            statement_digest=old.statement_digest,
            source_receipt_digest=old.source_receipt_digest,
            transition_digest=old.transition_digest,
            issuer_class=old.issuer_class,
            grantor_classes=old.grantor_classes,
            scope_digest=old.scope_digest,
            scope_selector_digest=canonical_digest(scope),
            effect_class=cast(str, entry["effect_class"]),
            adapter_id=old.adapter_id,
        )
        entry.update(
            clause_digest=clause.clause_digest,
            statement_digest=clause.statement_digest,
            successor_id=clause.successor_id,
        )
        clauses.append(clause)
        entries.append(entry)
    pack = _pack(
        transition=original.transition_digest,
        clauses=tuple(clauses),
        policies=original.freshness_policies,
    )
    profile = _profile(
        pack=pack,
        authority=tuple(clause.clause_id for clause in clauses),
    )
    artifacts = state.artifacts
    report = inspect_rule_chain_candidate_v2(
        proposal=artifacts.proposal,
        proposal_artifact=artifacts.proposal_artifact,
        proposal_source=artifacts.proposal_source,
        original_owner_question=artifacts.original_owner_question,
        original_owner_reply=artifacts.original_owner_reply,
        normative_source=artifacts.normative_source,
        ratification_manifest=artifacts.ratification_manifest,
        ratification_question=artifacts.ratification_question,
        ratification_reply=artifacts.ratification_reply,
        findings=artifacts.findings,
        acceptance_verifier=state.acceptance_verifier,
        packs=(pack,),
        profile=profile,
        source_verifiers=state.source_verifiers,
        roles=state.roles,
        expected_project_id=state.expected_project_id,
        expected_scope_digest=state.expected_scope_digest,
        now=state.clock(),
    )
    lock = _lock(
        report,
        pack,
        profile,
        state.source_verifiers[pack.pack_id],
        state.current_adapters,
        effect_operations_digest=state.effect_operations.operations_digest,
    )
    selected = replace(
        state,
        packs=(pack,),
        profile=profile,
        lock=lock,
        expected_lock_digest=lock.lock_digest,
    )
    body: dict[str, object] = {
        "schema": "rigor.clause-semantics-set.v2",
        "project_id": profile.project_id,
        "predecessor_acceptance_digest": report.acceptance_digest,
        "previous_semantics_set_digest": None,
        "supersedes_failed_completion": None,
        "rule_projection_digest": lock.rule_projection_digest,
        "successor_clause_digests": list(report.successor_clause_digests),
        "scope_digest": profile.selector_scope_digest,
        "effect_vocabulary_digest": vocabulary.vocabulary_digest,
        "effect_target_table_digest": target_table.table_digest,
        "evaluator_registry_digest": evaluators.registry_digest,
        "resolver_version": "registry-v1-interim",
        "entries": sorted(entries, key=lambda item: cast(str, item["clause_digest"])),
    }
    wire = canonical_journal_json_v2(body)
    digest = ClauseSemanticsSetV2.from_bytes(wire).body_digest
    signed = SignedClauseSemanticsSetV2.from_bytes(
        body_bytes=wire,
        author_signature=_signature(
            "clause-semantics-set-author", digest, "2026-09-23T00:11:00Z"
        ).to_dict(),
        reviewer_signature=_signature(
            "clause-semantics-set", digest, "2026-09-23T00:12:00Z"
        ).to_dict(),
    )
    return selected, signed


def test_scope_bound_signed_pack_profile_lock_and_semantics_share_selection(
    tmp_path: Path,
) -> None:
    """The real selected-host and semantics APIs accept the same four clauses."""
    with _selected(tmp_path) as legacy:
        state, signed = _scope_bound_state(legacy)
        proof = HostSelectedRuleChainVerifierV2(lambda: nullcontext(state)).verify()
        vocabulary = EffectVocabularyV2.build()
        evaluators = ConstraintEvaluatorRegistryV2.build()
        target_table = EffectTargetTableV2.build()
        registry = project_registry(
            groups=(group(_GROUP),),
            projects=(project(state.profile.project_id, _GROUP),),
        )
        binding = bind_clause_semantics_v2(
            signed=signed,
            roles=state.roles,
            now=state.clock(),
            expected_semantics_set_digest=signed.body.body_digest,
            clauses=state.lock.authority_clauses,
            predecessor_acceptance_digest=proof.acceptance_digest,
            rule_projection_digest=proof.rule_projection_digest,
            successor_clause_digests=proof.successor_clause_digests,
            project_id=state.profile.project_id,
            registry=registry,
            expected_registry_sha256=registry.registry_sha256,
            scope_digest=state.profile.selector_scope_digest,
            effect_vocabulary_digest=vocabulary.vocabulary_digest,
            vocabulary=vocabulary,
            effect_target_table_digest=target_table.table_digest,
            target_table=target_table,
            evaluator_registry_digest=evaluators.registry_digest,
            evaluator_registry=evaluators,
            resolver_version="registry-v1-interim",
        )
        assert binding.successor_clause_digests == proof.successor_clause_digests
        assert binding.active_admit_clause_digests == tuple(sorted(proof.successor_clause_digests))
