# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected clause-semantics binding tests
"""Exercise signed clauses through the public selected-chain binding."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_clause_semantics_set_v2 import _body, _entry
from test_owner_confirmation_v2 import _native
from test_project_registry_models import group, project
from test_project_registry_models import registry as project_registry
from test_signed_clause_semantics_set_v2 import _signature
from test_signed_rule_chain_v2 import _roles

from rigor_foundry.clause_semantics_binding_v2 import (
    ClauseSemanticsBindingV2,
    bind_clause_semantics_v2,
)
from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.constraint_evaluator_registry_v2 import ConstraintEvaluatorRegistryV2
from rigor_foundry.effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.models import canonical_digest
from rigor_foundry.owner_confirmation_v2 import OwnerConfirmationRecordV2
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.rule_chain_pack_v2 import AuthorityClauseV2
from rigor_foundry.signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2

_NOW = datetime(2026, 9, 19, tzinfo=UTC)
_GROUP = "AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS"
_FOREIGN_GROUP = "SCPN-REACTOR-SYSTEMS"


def _fixture(
    subjects: tuple[str, ...] = ("admit",),
    effect_class: str = "local-file-write",
) -> tuple[dict[str, object], tuple[AuthorityClauseV2, ...]]:
    """Build distinct real authority clauses and matching signed-body entries."""
    body = _body()
    entries: list[dict[str, object]] = []
    clauses: list[AuthorityClauseV2] = []
    for number, subject in enumerate(subjects, start=1):
        entry = _entry(number, subject)
        entry["effect_class"] = effect_class
        statement = f"authoritative statement {number}\n"
        clause = AuthorityClauseV2.build(
            clause_id=f"clause-{number}",
            successor_id=cast(str, entry["successor_id"]),
            statement_digest=sha256(statement.encode()).hexdigest(),
            source_receipt_digest="7" * 64,
            transition_digest="8" * 64,
            issuer_class="owner",
            grantor_classes=("owner",),
            scope_digest="4" * 64,
            scope_selector_digest=canonical_digest(entry["scope"]),
            effect_class=cast(str, entry["effect_class"]),
            adapter_id="local-adapter",
        )
        entry["clause_digest"] = clause.clause_digest
        entry["statement_digest"] = clause.statement_digest
        entries.append(entry)
        clauses.append(clause)
    entries.sort(key=lambda item: cast(str, item["clause_digest"]))
    body["entries"] = entries
    body["successor_clause_digests"] = [clause.clause_digest for clause in clauses]
    body["effect_vocabulary_digest"] = EffectVocabularyV2.build().vocabulary_digest
    body["evaluator_registry_digest"] = ConstraintEvaluatorRegistryV2.build().registry_digest
    return body, tuple(clauses)


def _signed(body: dict[str, object]) -> SignedClauseSemanticsSetV2:
    """Sign and independently review the exact canonical body with real keys."""
    wire = canonical_journal_json_v2(body)
    digest = ClauseSemanticsSetV2.from_bytes(wire).body_digest
    return SignedClauseSemanticsSetV2.from_bytes(
        body_bytes=wire,
        author_signature=_signature(
            "clause-semantics-set-author", digest, "2026-09-12T00:00:00Z"
        ).to_dict(),
        reviewer_signature=_signature(
            "clause-semantics-set", digest, "2026-09-12T01:00:00Z"
        ).to_dict(),
    )


def _bind(
    body: dict[str, object],
    clauses: tuple[AuthorityClauseV2, ...],
    **changes: object,
) -> ClauseSemanticsBindingV2:
    """Apply the public binder with selected-chain and host pins."""
    signed = _signed(body)
    vocabulary = EffectVocabularyV2.build()
    target_table = EffectTargetTableV2.build()
    evaluator_registry = ConstraintEvaluatorRegistryV2.build()
    registry = project_registry(
        groups=(group(_GROUP), group(_FOREIGN_GROUP)),
        projects=(project("RIGOR-FOUNDRY", _GROUP),),
    )
    arguments: dict[str, object] = {
        "expected_semantics_set_digest": signed.body.body_digest,
        "predecessor_acceptance_digest": "1" * 64,
        "rule_projection_digest": "2" * 64,
        "successor_clause_digests": tuple(clause.clause_digest for clause in clauses),
        "project_id": "RIGOR-FOUNDRY",
        "registry": registry,
        "expected_registry_sha256": registry.registry_sha256,
        "scope_digest": "4" * 64,
        "effect_vocabulary_digest": vocabulary.vocabulary_digest,
        "vocabulary": vocabulary,
        "effect_target_table_digest": target_table.table_digest,
        "target_table": target_table,
        "evaluator_registry_digest": evaluator_registry.registry_digest,
        "evaluator_registry": evaluator_registry,
        "resolver_version": "registry-v1-interim",
        "authority_requirement": None,
        "expected_authority_requirement_digest": None,
        "owner_confirmation": None,
        "expected_owner_confirmation_digest": None,
        "confirmation_manifest": None,
        "confirmation_question": None,
        "confirmation_reply": None,
    }
    arguments.update(changes)
    return bind_clause_semantics_v2(
        signed=signed,
        roles=_roles(),
        now=_NOW,
        expected_semantics_set_digest=cast(str, arguments["expected_semantics_set_digest"]),
        clauses=clauses,
        predecessor_acceptance_digest=cast(str, arguments["predecessor_acceptance_digest"]),
        rule_projection_digest=cast(str, arguments["rule_projection_digest"]),
        successor_clause_digests=cast(tuple[str, ...], arguments["successor_clause_digests"]),
        project_id=cast(str, arguments["project_id"]),
        registry=cast(ProjectRegistry, arguments["registry"]),
        expected_registry_sha256=cast(str, arguments["expected_registry_sha256"]),
        scope_digest=cast(str, arguments["scope_digest"]),
        effect_vocabulary_digest=cast(str, arguments["effect_vocabulary_digest"]),
        vocabulary=cast(EffectVocabularyV2, arguments["vocabulary"]),
        effect_target_table_digest=cast(str, arguments["effect_target_table_digest"]),
        target_table=cast(EffectTargetTableV2, arguments["target_table"]),
        evaluator_registry_digest=cast(str, arguments["evaluator_registry_digest"]),
        evaluator_registry=cast(ConstraintEvaluatorRegistryV2, arguments["evaluator_registry"]),
        resolver_version=cast(str, arguments["resolver_version"]),
        authority_requirement=cast(
            EffectClassAuthorityRequirementV2 | None, arguments["authority_requirement"]
        ),
        expected_authority_requirement_digest=cast(
            str | None, arguments["expected_authority_requirement_digest"]
        ),
        owner_confirmation=cast(OwnerConfirmationRecordV2 | None, arguments["owner_confirmation"]),
        expected_owner_confirmation_digest=cast(
            str | None, arguments["expected_owner_confirmation_digest"]
        ),
        confirmation_manifest=cast(bytes | None, arguments["confirmation_manifest"]),
        confirmation_question=cast(bytes | None, arguments["confirmation_question"]),
        confirmation_reply=cast(bytes | None, arguments["confirmation_reply"]),
    )


def test_exact_signed_clause_binding_returns_only_active_admits() -> None:
    """A signed admit supersedes an older admit while retaining a veto."""
    body, clauses = _fixture(("admit", "admit", "veto"))
    entries = cast(list[dict[str, object]], body["entries"])
    admits = [entry for entry in entries if entry["subject"] == "admit"]
    older, newer = sorted(admits, key=lambda item: cast(str, item["clause_digest"]))
    newer["supersedes"] = [older["clause_digest"]]
    proof = _bind(body, clauses)
    assert proof.guard_admissible is False
    assert proof.active_admit_clause_digests == (newer["clause_digest"],)
    assert proof.successor_clause_digests == tuple(clause.clause_digest for clause in clauses)


@pytest.mark.parametrize(
    "field,value",
    [
        ("predecessor_acceptance_digest", "9" * 64),
        ("rule_projection_digest", "9" * 64),
        ("scope_digest", "9" * 64),
        ("resolver_version", "pcs-k2-v1"),
    ],
)
def test_selected_chain_and_host_pin_mismatch_refuses(field: str, value: object) -> None:
    """A valid signature cannot bind a different selected chain or host pin."""
    body, clauses = _fixture()
    with pytest.raises(PermissionError, match="selected chain or host pins"):
        _bind(body, clauses, **{field: value})


def test_selected_semantics_digest_mismatch_refuses() -> None:
    """The signer cannot choose a different body from the protected selection."""
    body, clauses = _fixture()
    with pytest.raises(PermissionError, match="protected selected digest"):
        _bind(body, clauses, expected_semantics_set_digest="0" * 64)


def test_missing_extra_or_changed_selected_clause_refuses() -> None:
    """Completeness, clause order, and exact clause integrity remain mandatory."""
    body, clauses = _fixture(("admit", "veto"))
    entries = cast(list[dict[str, object]], body["entries"])
    body["entries"] = entries[:1]
    with pytest.raises(PermissionError, match="cover every selected clause"):
        _bind(body, clauses)
    body, clauses = _fixture(("admit", "veto"))
    with pytest.raises(PermissionError, match="selected chain or host pins"):
        _bind(body, clauses[::-1])
    body, clauses = _fixture(("admit", "veto"))
    unknown_successor = "9" * 64
    body["successor_clause_digests"] = [unknown_successor]
    with pytest.raises(PermissionError, match="successor clause is absent"):
        _bind(body, clauses, successor_clause_digests=(unknown_successor,))
    body, clauses = _fixture()
    forged = replace(clauses[0], statement_digest="0" * 64)
    with pytest.raises(ValueError, match="digest"):
        _bind(body, (forged,))
    with pytest.raises(PermissionError, match="authority clause list differs"):
        _bind(
            body,
            clauses + clauses,
            successor_clause_digests=(clauses[0].clause_digest,),
        )


def test_non_successor_authority_clause_requires_semantics_entry() -> None:
    """The four successors do not exempt a fifth selected authority clause."""
    body, clauses = _fixture(("admit", "admit", "admit", "admit", "veto"))
    four = tuple(clause.clause_digest for clause in clauses[:4])
    body["successor_clause_digests"] = list(four)
    proof = _bind(body, clauses, successor_clause_digests=four)
    assert len(proof.active_admit_clause_digests) == 4
    entries = cast(list[dict[str, object]], body["entries"])
    body["entries"] = [
        item for item in entries if item["clause_digest"] != clauses[4].clause_digest
    ]
    with pytest.raises(PermissionError, match="every selected clause"):
        _bind(body, clauses, successor_clause_digests=four)


def test_revoked_signer_refuses_before_chain_comparison() -> None:
    """A signed body with altered cryptographic evidence cannot bind."""
    body, clauses = _fixture()
    signed = _signed(body)
    forged = replace(signed, reviewer=replace(signed.reviewer, signature_hex="0" * 128))
    with pytest.raises(PermissionError, match="signatures no longer verify"):
        bind_clause_semantics_v2(
            signed=forged,
            roles=_roles(),
            now=_NOW,
            expected_semantics_set_digest=signed.body.body_digest,
            clauses=clauses,
            predecessor_acceptance_digest="1" * 64,
            rule_projection_digest="2" * 64,
            successor_clause_digests=tuple(clause.clause_digest for clause in clauses),
            project_id="RIGOR-FOUNDRY",
            registry=project_registry(
                groups=(group(_GROUP), group(_FOREIGN_GROUP)),
                projects=(project("RIGOR-FOUNDRY", _GROUP),),
            ),
            expected_registry_sha256=project_registry(
                groups=(group(_GROUP), group(_FOREIGN_GROUP)),
                projects=(project("RIGOR-FOUNDRY", _GROUP),),
            ).registry_sha256,
            scope_digest="4" * 64,
            effect_vocabulary_digest=EffectVocabularyV2.build().vocabulary_digest,
            vocabulary=EffectVocabularyV2.build(),
            effect_target_table_digest=EffectTargetTableV2.build().table_digest,
            target_table=EffectTargetTableV2.build(),
            evaluator_registry_digest=ConstraintEvaluatorRegistryV2.build().registry_digest,
            evaluator_registry=ConstraintEvaluatorRegistryV2.build(),
            resolver_version="registry-v1-interim",
        )


def test_entry_scope_statement_effect_and_successor_mismatch_refuse() -> None:
    """A separately signed altered field still cannot bind a selected clause."""
    for field, value in (
        ("statement_digest", "9" * 64),
        ("successor_id", "successor-other"),
        ("effect_class", "other-effect"),
        (
            "scope",
            {
                "schema": "rigor.clause-scope-selector.v2",
                "targets": ["path:/tmp/other"],
                "exclusions": [],
            },
        ),
    ):
        body, clauses = _fixture()
        entries = cast(list[dict[str, object]], body["entries"])
        entries[0][field] = value
        with pytest.raises(PermissionError, match="entry differs"):
            _bind(body, clauses)
    body, clauses = _fixture(effect_class="local-write")
    with pytest.raises(PermissionError, match="entry differs"):
        _bind(body, clauses)


def test_forged_or_swapped_vocabulary_refuses() -> None:
    """Host-selected vocabulary bytes and digest must agree exactly."""
    body, clauses = _fixture()
    forged = replace(EffectVocabularyV2.build(), vocabulary_digest="0" * 64)
    with pytest.raises(PermissionError, match="effect vocabulary differs"):
        _bind(body, clauses, vocabulary=forged)
    with pytest.raises(PermissionError, match="effect vocabulary differs"):
        _bind(body, clauses, effect_vocabulary_digest="0" * 64)


def test_target_table_body_and_host_pin_must_match() -> None:
    """A signed semantics body cannot replace the selected target-kind mapping."""
    body, clauses = _fixture()
    forged = replace(EffectTargetTableV2.build(), table_digest="0" * 64)
    with pytest.raises(PermissionError, match="effect target table differs"):
        _bind(body, clauses, target_table=forged)
    with pytest.raises(PermissionError, match="effect target table differs"):
        _bind(body, clauses, effect_target_table_digest="0" * 64)
    body["effect_target_table_digest"] = "0" * 64
    with pytest.raises(PermissionError, match="selected chain or host pins"):
        _bind(body, clauses)


def test_fixed_constraint_registry_is_selected_independently() -> None:
    """A rate entry binds only the four fixed registry IDs."""
    body, clauses = _fixture(("rate",))
    proof = _bind(body, clauses)
    assert proof.active_admit_clause_digests == ()
    registry = ConstraintEvaluatorRegistryV2.build()
    forged = replace(registry, registry_digest="0" * 64)
    with pytest.raises(PermissionError, match="evaluator registry differs"):
        _bind(body, clauses, evaluator_registry=forged)
    with pytest.raises(PermissionError, match="evaluator registry differs"):
        _bind(body, clauses, evaluator_registry_digest="0" * 64)


def test_precondition_requires_native_pinned_owner_confirmation(tmp_path: Path) -> None:
    """A precondition set refuses absent, changed or forged native owner evidence."""
    body, clauses = _fixture(("admit", "precondition"))
    confirmation, requirement, manifest, question, reply = _native(tmp_path)
    selected = {
        "authority_requirement": requirement,
        "expected_authority_requirement_digest": requirement.requirement_digest,
        "owner_confirmation": confirmation,
        "expected_owner_confirmation_digest": confirmation.record_digest,
        "confirmation_manifest": manifest,
        "confirmation_question": question,
        "confirmation_reply": reply,
    }
    with pytest.raises(PermissionError, match="not selected"):
        _bind(body, clauses)
    with pytest.raises(PermissionError, match="not selected"):
        _bind(body, clauses, **{**selected, "owner_confirmation": None})
    with pytest.raises(PermissionError, match="not selected"):
        _bind(body, clauses, **{**selected, "expected_authority_requirement_digest": None})
    with pytest.raises(PermissionError, match="not selected"):
        _bind(body, clauses, **{**selected, "confirmation_manifest": None})
    with pytest.raises(PermissionError, match="selected records"):
        _bind(body, clauses, **{**selected, "expected_authority_requirement_digest": "0" * 64})
    with pytest.raises(PermissionError, match="selected records"):
        _bind(body, clauses, **{**selected, "expected_owner_confirmation_digest": "0" * 64})
    with pytest.raises(PermissionError, match="differs"):
        _bind(
            body,
            clauses,
            **{**selected, "authority_requirement": replace(requirement, body_bytes=b"no")},
        )
    with pytest.raises(PermissionError, match="differs"):
        _bind(
            body,
            clauses,
            **{
                **selected,
                "authority_requirement": replace(requirement, enforced_required=()),
            },
        )
    proof = _bind(body, clauses, **selected)
    assert proof.active_admit_clause_digests
    assert proof.authority_requirement_digest == requirement.requirement_digest
    assert proof.owner_confirmation_digest == confirmation.record_digest


def test_non_precondition_set_does_not_consult_requirement() -> None:
    """A missing K6 list cannot hold a set without preconditions."""
    body, clauses = _fixture(("admit", "rate"))
    proof = _bind(body, clauses)
    assert proof.active_admit_clause_digests
    assert proof.authority_requirement_digest is None
    assert proof.owner_confirmation_digest is None


def test_selected_group_and_foreign_inbox_binding_refuse() -> None:
    """Group aliases cannot pass merely because target syntax is valid."""
    body, clauses = _fixture()
    with pytest.raises(PermissionError, match="protected selected generation"):
        _bind(body, clauses, expected_registry_sha256="0" * 64)
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = [f"group-memory:{_FOREIGN_GROUP}"]
    with pytest.raises(PermissionError, match="group target differs"):
        _bind(body, clauses)
    body, clauses = _fixture(effect_class="exchange-record-create")
    entries = cast(list[dict[str, object]], body["entries"])
    scope = cast(dict[str, object], entries[0]["scope"])
    scope["targets"] = [f"group-exchange-inbox:{_GROUP}"]
    with pytest.raises(PermissionError, match="not a foreign group"):
        _bind(body, clauses)
    scope["targets"] = ["group-exchange-inbox:UNREGISTERED"]
    with pytest.raises(PermissionError, match="not a foreign group"):
        _bind(body, clauses)


def test_unregistered_project_cannot_select_semantics() -> None:
    """The body project must be canonical and active in the selected registry."""
    body, clauses = _fixture()
    other = project_registry(
        groups=(group(_GROUP), group(_FOREIGN_GROUP)),
        projects=(project("OTHER", _GROUP),),
    )
    with pytest.raises(PermissionError, match="project is not active"):
        _bind(
            body,
            clauses,
            registry=other,
            expected_registry_sha256=other.registry_sha256,
        )


def test_supersession_veto_cycle_and_shared_ancestor() -> None:
    """Supersession excludes vetoes and cycles yet accepts a diamond graph."""
    body, clauses = _fixture(("admit", "veto"))
    entries = cast(list[dict[str, object]], body["entries"])
    admit = next(item for item in entries if item["subject"] == "admit")
    veto = next(item for item in entries if item["subject"] == "veto")
    admit["supersedes"] = [veto["clause_digest"]]
    with pytest.raises(PermissionError, match="veto or constraint"):
        _bind(body, clauses)
    body, clauses = _fixture(("admit", "admit"))
    entries = cast(list[dict[str, object]], body["entries"])
    entries[0]["supersedes"] = [entries[1]["clause_digest"]]
    entries[1]["supersedes"] = [entries[0]["clause_digest"]]
    with pytest.raises(PermissionError, match="cycle"):
        _bind(body, clauses)
    body, clauses = _fixture(("admit", "admit", "admit", "admit"))
    entries = cast(list[dict[str, object]], body["entries"])
    digests = [cast(str, item["clause_digest"]) for item in entries]
    entries[0]["supersedes"] = [digests[1], digests[2]]
    entries[1]["supersedes"] = [digests[3]]
    entries[2]["supersedes"] = [digests[3]]
    assert _bind(body, clauses).active_admit_clause_digests == (digests[0],)


def test_layered_shared_ancestors_and_self_cycle() -> None:
    """A deep shared DAG binds without path enumeration; self-supersession refuses."""
    body, clauses = _fixture(("admit",) * 80)
    entries = cast(list[dict[str, object]], body["entries"])
    for layer in range(39):
        children = [item["clause_digest"] for item in entries[2 * layer + 2 : 2 * layer + 4]]
        for entry in entries[2 * layer : 2 * layer + 2]:
            entry["supersedes"] = children
    assert _bind(body, clauses).active_admit_clause_digests == tuple(
        item["clause_digest"] for item in entries[:2]
    )
    body, clauses = _fixture()
    entry = cast(list[dict[str, object]], body["entries"])[0]
    entry["supersedes"] = [entry["clause_digest"]]
    with pytest.raises(PermissionError, match="cycle"):
        _bind(body, clauses)


def test_empty_semantics_and_non_tuple_clause_input() -> None:
    """An empty selected set grants no admit; a mutable clause container refuses."""
    body, clauses = _fixture(())
    proof = _bind(body, clauses)
    assert proof.guard_admissible is False
    assert proof.active_admit_clause_digests == ()
    body, clauses = _fixture()
    with pytest.raises(PermissionError, match="authority clause list differs"):
        _bind(body, cast(tuple[AuthorityClauseV2, ...], list(clauses)))


def test_empty_semantics_cannot_select_a_retired_owning_group() -> None:
    """Active project membership does not activate its retired owning group."""
    body, clauses = _fixture(())
    initial = project_registry(
        groups=(group(_GROUP),), projects=(project("RIGOR-FOUNDRY", _GROUP),)
    )
    retired = ProjectRegistry.build(
        generated_at=initial.generated_at,
        previous_registry_sha256=initial.previous_registry_sha256,
        authority=initial.authority,
        groups=(replace(initial.groups[0], lifecycle_state="retired"),),
        projects=initial.projects,
        consumers=tuple(item for item in initial.consumers if item.kind != "group-view"),
    )
    with pytest.raises(PermissionError, match="owning group is absent"):
        _bind(body, clauses, registry=retired, expected_registry_sha256=retired.registry_sha256)


def test_registered_inactive_project_cannot_select_semantics() -> None:
    """An exact registry pin does not activate a paused registered project."""
    body, clauses = _fixture()
    initial = project_registry(
        groups=(group(_GROUP),), projects=(project("RIGOR-FOUNDRY", _GROUP),)
    )
    inactive = ProjectRegistry.build(
        generated_at=initial.generated_at,
        previous_registry_sha256=initial.previous_registry_sha256,
        authority=initial.authority,
        groups=initial.groups,
        projects=(replace(initial.projects[0], lifecycle_state="paused"),),
        consumers=initial.consumers,
    )
    with pytest.raises(PermissionError, match="project is not active"):
        _bind(body, clauses, registry=inactive, expected_registry_sha256=inactive.registry_sha256)
