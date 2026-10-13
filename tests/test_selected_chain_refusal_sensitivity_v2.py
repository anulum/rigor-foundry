# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected-chain public refusal regressions
"""Distinguish selected-chain refusals from incidental downstream failures."""

from __future__ import annotations

import base64
import json
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_atomic_file_replace_invocation_v2 import _payload
from test_project_registry_models import registry as sample_registry
from test_rule_chain_lock_v2 import _case, _lock
from test_semantic_transition_acceptance_v2 import _body as acceptance_body

from rigor_foundry.adapter_operations_v2 import AdapterOperationsV2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.rule_chain_lock_v2 import EffectiveProfileLockV2, ResolutionStatus
from rigor_foundry.rule_chain_pack_v2 import AuthorityClauseV2
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    HostSelectedRuleChainVerifierV2,
)
from rigor_foundry.semantic_transition_acceptance_v2 import SemanticAcceptanceBodyV2
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2Signature
from rigor_foundry.tier0_builtin.atomic_file_replace_invocation import (
    MAX_REPLACEMENT_CONTENT_BYTES,
    AtomicFileReplaceInvocationV2,
)
from rigor_foundry.tier0_builtin.selected_path_scope_v2 import derive_selected_path_scope_v2


def _projection(lock: EffectiveProfileLockV2) -> dict[str, object]:
    """Exercise public unsigned projection validation with typed record fields."""
    return EffectiveProfileLockV2.body(
        project_id=lock.project_id,
        profile_id=lock.profile_id,
        profile_digest=lock.profile_digest,
        selector_scope_digest=lock.selector_scope_digest,
        acceptance_digest=lock.acceptance_digest,
        acceptance_host_selection_digest=lock.acceptance_host_selection_digest,
        reviewer_policy_digest=lock.reviewer_policy_digest,
        effect_operations_digest=lock.effect_operations_digest,
        pack_digests=lock.pack_digests,
        pack_source_verification_digests=lock.pack_source_verification_digests,
        authority_clauses=lock.authority_clauses,
        successor_clause_digests=lock.successor_clause_digests,
        freshness_policies=lock.freshness_policies,
        local_constraint_digests=lock.local_constraint_digests,
        excluded_clause_ids=lock.excluded_clause_ids,
        adapter_custody=lock.adapter_custody,
        issuer_order=lock.issuer_order,
        resolution_status=lock.resolution_status,
        contradictions=lock.contradictions,
        resolved_at=lock.resolved_at,
        resolver_code_digest=lock.resolver_code_digest,
    )


def _build_with_signature(
    lock: EffectiveProfileLockV2, signature: RuleChainV2Signature
) -> EffectiveProfileLockV2:
    """Supply an independently valid signature envelope to the public builder."""
    return EffectiveProfileLockV2.build(
        project_id=lock.project_id,
        profile_id=lock.profile_id,
        profile_digest=lock.profile_digest,
        selector_scope_digest=lock.selector_scope_digest,
        acceptance_digest=lock.acceptance_digest,
        acceptance_host_selection_digest=lock.acceptance_host_selection_digest,
        reviewer_policy_digest=lock.reviewer_policy_digest,
        effect_operations_digest=lock.effect_operations_digest,
        pack_digests=lock.pack_digests,
        pack_source_verification_digests=lock.pack_source_verification_digests,
        authority_clauses=lock.authority_clauses,
        successor_clause_digests=lock.successor_clause_digests,
        freshness_policies=lock.freshness_policies,
        local_constraint_digests=lock.local_constraint_digests,
        excluded_clause_ids=lock.excluded_clause_ids,
        adapter_custody=lock.adapter_custody,
        issuer_order=lock.issuer_order,
        resolution_status=lock.resolution_status,
        contradictions=lock.contradictions,
        resolved_at=lock.resolved_at,
        resolver_code_digest=lock.resolver_code_digest,
        signature=signature,
    )


@pytest.mark.parametrize("fault", ["empty", "missing-source", "repeated-pack"])
def test_projection_requires_one_source_proof_per_distinct_pack(
    tmp_path: Path, fault: str
) -> None:
    """Incomplete or repeated selected packs cannot form an unsigned projection."""
    with _case(tmp_path) as case:
        lock = case.lock
        if fault == "empty":
            lock = replace(lock, pack_digests=(), pack_source_verification_digests=())
        elif fault == "missing-source":
            lock = replace(lock, pack_source_verification_digests=())
        else:
            lock = replace(
                lock,
                pack_digests=lock.pack_digests * 2,
                pack_source_verification_digests=lock.pack_source_verification_digests * 2,
            )
        with pytest.raises(
            ValueError, match=r"^lock needs one unique source proof per selected pack$"
        ):
            _projection(lock)


@pytest.mark.parametrize(
    "fault",
    [
        "clauses",
        "freshness",
        "repeated-clause",
        "repeated-freshness",
        "repeated-adapter",
        "missing-adapter",
    ],
)
def test_projection_requires_complete_unique_owner_and_adapter_sets(
    tmp_path: Path, fault: str
) -> None:
    """Clause, freshness and adapter membership is checked before derivation."""
    with _case(tmp_path) as case:
        lock = case.lock
        if fault == "clauses":
            lock = replace(lock, authority_clauses=())
        elif fault == "freshness":
            lock = replace(lock, freshness_policies=())
        elif fault == "repeated-clause":
            lock = replace(
                lock, authority_clauses=(*lock.authority_clauses, lock.authority_clauses[0])
            )
        elif fault == "repeated-freshness":
            lock = replace(lock, freshness_policies=lock.freshness_policies * 2)
        elif fault == "repeated-adapter":
            lock = replace(lock, adapter_custody=(*lock.adapter_custody, lock.adapter_custody[0]))
        else:
            lock = replace(lock, adapter_custody=lock.adapter_custody[:1])
        with pytest.raises(
            ValueError, match=r"^lock projection clauses, freshness or adapters differ$"
        ):
            _projection(lock)


def test_projection_binds_every_clause_to_the_same_acceptance(tmp_path: Path) -> None:
    """A valid rebuilt clause cannot borrow an unrelated transition digest."""
    with _case(tmp_path) as case:
        clause = case.lock.authority_clauses[0]
        changed = AuthorityClauseV2.build(
            clause_id=clause.clause_id,
            successor_id=clause.successor_id,
            statement_digest=clause.statement_digest,
            source_receipt_digest=clause.source_receipt_digest,
            transition_digest="0" * 64,
            issuer_class=clause.issuer_class,
            grantor_classes=clause.grantor_classes,
            scope_digest=clause.scope_digest,
            scope_selector_digest=clause.scope_selector_digest,
            effect_class=clause.effect_class,
            adapter_id=clause.adapter_id,
        )
        assert changed.transition_digest != case.lock.acceptance_digest
        clauses = (changed, *case.lock.authority_clauses[1:])
        lock = replace(
            case.lock,
            authority_clauses=clauses,
            successor_clause_digests=tuple(item.clause_digest for item in clauses),
        )
        with pytest.raises(ValueError, match=r"^lock authority clause transition differs$"):
            _projection(lock)


@pytest.mark.parametrize("field", ["local_constraint_digests", "excluded_clause_ids"])
def test_projection_refuses_duplicate_constraints_and_exclusions(
    tmp_path: Path, field: str
) -> None:
    """Repeated local conditions or exclusion identities cannot become signed input."""
    with _case(tmp_path) as case:
        lock = (
            replace(case.lock, local_constraint_digests=("a" * 64,) * 2)
            if field == "local_constraint_digests"
            else replace(case.lock, excluded_clause_ids=("other/clause",) * 2)
        )
        with pytest.raises(ValueError, match=r"^lock constraints and exclusions must be unique$"):
            _projection(lock)


def test_projection_requires_selected_grantor_membership(tmp_path: Path) -> None:
    """A grantor omitted by the issuer policy cannot form a projection."""
    with (
        _case(tmp_path) as case,
        pytest.raises(ValueError, match=r"^lock grantors must belong to selected issuer order$"),
    ):
        _projection(replace(case.lock, issuer_order=("unrelated-issuer",)))


@pytest.mark.parametrize(
    "field",
    [
        "pack_digests",
        "authority_clauses",
        "freshness_policies",
        "adapter_custody",
        "contradictions",
    ],
)
def test_lock_parser_refuses_non_json_array_aliases(tmp_path: Path, field: str) -> None:
    """Iterable tuple aliases cannot bypass the closed array wire contract."""
    with _case(tmp_path) as case:
        wire = case.lock.to_dict()
        wire[field] = tuple(cast(list[object], wire[field]))
        with pytest.raises(ValueError, match=rf"^lock\.{field} must be an array$"):
            EffectiveProfileLockV2.from_dict(wire)


def test_lock_builder_refuses_a_real_signature_for_another_projection(tmp_path: Path) -> None:
    """A second valid signed lock cannot lend its signature to the first body."""
    with _case(tmp_path) as case:
        other = _lock(
            case.report,
            case.pack,
            case.profile,
            case.source,
            case.adapters,
            effect_operations_digest="f" * 64,
        )
        assert other.signature.body_digest != case.lock.signature.body_digest
        assert _build_with_signature(other, other.signature) == other
        with pytest.raises(
            ValueError, match=r"^lock resolver signature does not bind the full projection$"
        ):
            _build_with_signature(case.lock, other.signature)


@pytest.mark.parametrize("field", ["rule_projection_digest", "grantor_classes"])
def test_lock_serialiser_refuses_changed_derived_projection(tmp_path: Path, field: str) -> None:
    """Directly changed derived fields cannot disappear during serialisation."""
    with _case(tmp_path) as case:
        lock = (
            replace(case.lock, rule_projection_digest="0" * 64)
            if field == "rule_projection_digest"
            else replace(case.lock, grantor_classes=("unrelated-issuer",))
        )
        with pytest.raises(
            ValueError, match=r"^lock projection differs from its canonical content$"
        ):
            lock.to_dict()


def test_lock_status_is_refused_by_parser_and_public_projection(tmp_path: Path) -> None:
    """Both entry points refuse status outside the shared effective/held vocabulary."""
    with _case(tmp_path) as case:
        wire = {**case.lock.to_dict(), "resolution_status": "unsupported"}
        with pytest.raises(ValueError, match=r"^lock resolution status is unsupported$"):
            EffectiveProfileLockV2.from_dict(wire)
        with pytest.raises(ValueError, match=r"^lock resolution status is unsupported$"):
            _projection(
                replace(case.lock, resolution_status=cast(ResolutionStatus, "unsupported"))
            )


def test_acceptance_requires_replacement_links_as_a_json_array() -> None:
    """Four otherwise valid tuple links cannot be reinterpreted as a wire array."""
    body = acceptance_body()
    body["replacements"] = tuple(cast(list[object], body["replacements"]))
    with pytest.raises(ValueError, match=r"^semantic acceptance requires four replacement links$"):
        SemanticAcceptanceBodyV2.from_dict(body)


def test_acceptance_requires_statement_hashes_as_a_json_array() -> None:
    """Four valid tuple hashes cannot bypass the exact body array type."""
    body = acceptance_body()
    body["statement_sha256"] = tuple(cast(list[object], body["statement_sha256"]))
    with pytest.raises(ValueError, match=r"^semantic acceptance requires four statement hashes$"):
        SemanticAcceptanceBodyV2.from_dict(body)


def test_acceptance_refuses_coherent_duplicate_statement_mapping() -> None:
    """Matching link hashes cannot conceal four duplicated statements."""
    body = acceptance_body()
    body["statement_sha256"] = ["1" * 64] * 4
    links = cast(list[dict[str, object]], body["replacements"])
    body["replacements"] = [{**item, "statement_sha256": "1" * 64} for item in links]
    with pytest.raises(ValueError, match=r"^semantic acceptance statement hashes must be unique$"):
        SemanticAcceptanceBodyV2.from_dict(body)


@pytest.mark.parametrize("body", [None, "{}", bytearray(b"{}")])
def test_selected_scope_requires_actual_registry_bytes(tmp_path: Path, body: object) -> None:
    """Missing or aliased source bodies refuse before invoking registry parsing."""
    registry = sample_registry()
    with pytest.raises(
        PermissionError, match=r"^selected path scope registry body is unavailable$"
    ):
        derive_selected_path_scope_v2(
            registry_bytes=cast(bytes, body),
            monorepo_root=str(tmp_path),
            selected_project_id="PROJECT-A",
            registry_generation_id=registry.generation_id,
            registry_sha256=registry.registry_sha256,
        )


@pytest.mark.parametrize("project_id", [None, "", 0])
def test_selected_scope_requires_a_project_identity(tmp_path: Path, project_id: object) -> None:
    """Unavailable identity is distinct from a named inactive or unknown project."""
    registry = sample_registry()
    with pytest.raises(ValueError, match=r"^selected path scope project id is unavailable$"):
        derive_selected_path_scope_v2(
            registry_bytes=registry.to_bytes(),
            monorepo_root=str(tmp_path),
            selected_project_id=cast(str, project_id),
            registry_generation_id=registry.generation_id,
            registry_sha256=registry.registry_sha256,
        )


def test_empty_catalogue_cannot_select_a_nonempty_reviewed_registry() -> None:
    """An empty catalogue cannot silently adopt the valid first-operation extractors."""
    with pytest.raises(
        ValueError, match=r"^adapter operations extractor registry is not reviewed$"
    ):
        AdapterOperationsV2.empty(
            vocabulary=EffectVocabularyV2.build(),
            target_table=EffectTargetTableV2.build(),
            extractors=ExtractorRegistryV2.first_atomic_candidate(),
        )


@pytest.mark.parametrize("extra_bytes", [-1, 0, 1, 2])
def test_atomic_parser_checks_decoded_content_bound_inside_base64_rounding(
    extra_bytes: int,
) -> None:
    """Equal encoded lengths still distinguish admitted bytes from decoded overflow."""
    content = b"x" * (MAX_REPLACEMENT_CONTENT_BYTES + extra_bytes)
    body = json.loads(_payload())
    body["content_b64"] = base64.b64encode(content).decode("ascii")
    body["declared"]["byte_count"] = 0
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if extra_bytes > 0:
        with pytest.raises(ValueError, match=r"^atomic replacement content exceeds 16 MiB$"):
            AtomicFileReplaceInvocationV2.from_bytes(payload)
    else:
        assert AtomicFileReplaceInvocationV2.from_bytes(payload).content == content


def test_atomic_parser_refuses_encoded_overflow_before_base64_decoding() -> None:
    """The encoded byte budget precedes parsing even malformed oversized data."""
    body = json.loads(_payload())
    maximum_encoded_length = 4 * ((MAX_REPLACEMENT_CONTENT_BYTES + 2) // 3)
    body["content_b64"] = "!" * (maximum_encoded_length + 1)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(ValueError, match=r"^atomic replacement content exceeds 16 MiB$"):
        AtomicFileReplaceInvocationV2.from_bytes(payload)


def test_verified_lease_keeps_the_same_public_type_refusal_as_verify() -> None:
    """The inner verify type check also protects the lease's redundant early check."""
    malformed = cast(HostSelectedRuleChainStateV2, object())
    verifier = HostSelectedRuleChainVerifierV2(lambda: nullcontext(malformed))
    with pytest.raises(
        PermissionError, match=r"^selected v2 rule-chain host state is unavailable$"
    ):
        verifier.verify()
    with (
        pytest.raises(
            PermissionError, match=r"^selected v2 rule-chain host state is unavailable$"
        ),
        verifier.verified_lease(),
    ):
        pytest.fail("malformed selected state reached the consumer")
