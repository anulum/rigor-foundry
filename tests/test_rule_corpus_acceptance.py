# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual dual-signed corpus envelope tests
"""Exercise full document preimages and actual independent-domain TEST Ed25519 signatures."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_rule_chain_trust_v3 import selected_roles
from test_rule_corpus_native import changed_ratification, corpus_budget, corpus_native_selection
from test_rule_source_document import source_document
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.rule_chain_trust_v3 import RuleObjectKindV3, rule_chain_v3_signature_boundary
from rigor_foundry.rule_corpus_acceptance import (
    RuleCorpusAcceptance1,
    rule_corpus_acceptance_body,
    rule_corpus_document_digests,
)
from rigor_foundry.rule_corpus_ratification import RuleCorpusRatification1
from rigor_foundry.rule_source_document import RuleSourceDocument1
from rigor_foundry.signed_rule_chain_v3 import RuleChainV3Signature, rule_chain_v3_payload_digest
from rigor_foundry.typed_object_reference import TypedObjectRef1


def corpus_signature(
    kind: RuleObjectKindV3,
    body_digest: str,
    *,
    budget: PolicyReadBudget1,
    fault: bool = False,
    signed_at: str = "2026-10-20T00:00:00Z",
) -> RuleChainV3Signature:
    """Sign the actual common acceptance body with its exact selected TEST semantic role."""
    _, version, _, domain = rule_chain_v3_signature_boundary(kind)
    key = selected_roles().policy_for(kind).keys[0].key.key_id
    payload = rule_chain_v3_payload_digest(
        object_kind=kind, body_schema_version=version, body_digest=body_digest, signed_at=signed_at
    )
    return RuleChainV3Signature.build(
        object_kind=kind,
        body_schema_version=version,
        key_id=key,
        body_digest=body_digest,
        signed_at=signed_at,
        signature_hex=sign_message("unrelated-test-key" if fault else key, domain, payload),
        budget=budget,
    )


def signed_corpus_acceptance(
    document: RuleSourceDocument1,
    ratification: RuleCorpusRatification1,
    *,
    budget: PolicyReadBudget1,
    changes: dict[str, object] | None = None,
    bad_author: bool = False,
    bad_reviewer: bool = False,
    signed_at: str = "2026-10-20T00:00:00Z",
) -> RuleCorpusAcceptance1:
    """Create an actual signed full-body candidate, including deliberately coordinated identity attacks."""
    body = {
        **rule_corpus_acceptance_body(document, ratification, budget=budget),
        **(changes or {}),
    }
    digest = canonical_digest(body)
    return RuleCorpusAcceptance1.build(
        corpus_id=cast(str, body["corpus_id"]),
        document_digest=cast(str, body["document_digest"]),
        universe_digest=cast(str, body["universe_digest"]),
        decision_set_digest=cast(str, body["decision_set_digest"]),
        component_set_digest=cast(str, body["component_set_digest"]),
        compiler_contract_digest=cast(str, body["compiler_contract_digest"]),
        native_ratification=TypedObjectRef1.from_dict(body["native_ratification"]),
        author_signature=corpus_signature(
            "rule-corpus-author", digest, budget=budget, fault=bad_author, signed_at=signed_at
        ),
        reviewer_signature=corpus_signature(
            "rule-corpus-acceptance",
            digest,
            budget=budget,
            fault=bad_reviewer,
            signed_at=signed_at,
        ),
        budget=budget,
    )


def test_full_array_preimages_common_body_real_signatures_and_exact_envelope(
    tmp_path: Path,
) -> None:
    """Both real signatures bind the exact same complete nine-field body and native identity."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        body = rule_corpus_acceptance_body(document, selected.ratification, budget=limits)
        assert len(body) == 9
        wire = document.to_dict(budget=limits)
        assert body["universe_digest"] == canonical_digest(wire["universe"])
        assert body["decision_set_digest"] == canonical_digest(wire["decisions"])
        assert body["component_set_digest"] == canonical_digest(
            {
                name: wire[name]
                for name in (
                    "qualitative_controls",
                    "review_policies",
                    "legacy_control_bindings",
                    "authority_bindings",
                    "freshness_policies",
                )
            }
        )
        acceptance = signed_corpus_acceptance(document, selected.ratification, budget=limits)
        envelope = acceptance.to_dict(budget=limits)
        assert len(envelope) == 12
        assert RuleCorpusAcceptance1.from_dict(envelope, budget=limits) == acceptance
        assert acceptance.unsigned_body(budget=limits) == body
        assert acceptance.reference(budget=limits).object_digest == acceptance.acceptance_digest
        assert acceptance.reference(budget=limits).object_id == document.corpus_id
        roles = selected_roles()
        for signature, kind in [
            (acceptance.author_signature, "rule-corpus-author"),
            (acceptance.reviewer_signature, "rule-corpus-acceptance"),
        ]:
            assert signature.body_digest == canonical_digest(body)
            assert signature.verify(
                object_kind=cast(RuleObjectKindV3, kind),
                body_schema_version="1.0",
                body_digest=canonical_digest(body),
                roles=roles,
                trust_roles_digest=roles.trust_roles_digest,
                now=datetime(2026, 10, 28, tzinfo=UTC),
                budget=limits,
            )
        assert (
            acceptance.author_signature.signature_hex
            != acceptance.reviewer_signature.signature_hex
        )
        assert not {"accepted", "host", "lock_digest", "pack_digest"}.intersection(envelope)


@pytest.mark.parametrize(
    "field", ["corpus_id", "document_digest", "universe_digest", "decision_set_digest"]
)
def test_actual_document_binding_refuses_rehashed_native_subset_or_other_subject(
    tmp_path: Path, field: str
) -> None:
    """A valid new native metadata digest cannot change one exact complete document identity."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        changed = changed_ratification(
            selected.ratification,
            budget=limits,
            **{field: "different" if field == "corpus_id" else "d" * 64},
        )
        with pytest.raises(ValueError, match="actual complete corpus"):
            rule_corpus_acceptance_body(document, changed, budget=limits)


def test_body_derivation_requires_actual_new_records(tmp_path: Path) -> None:
    """Caller dictionaries cannot stand in for the complete source or new native record."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits):
        with pytest.raises(ValueError):
            rule_corpus_document_digests(
                cast(RuleSourceDocument1, "caller-document"), budget=limits
            )
        with pytest.raises(ValueError):
            rule_corpus_acceptance_body(
                document, cast(RuleCorpusRatification1, "caller-ratification"), budget=limits
            )


@pytest.mark.parametrize(
    "fault",
    [
        "body",
        "author-kind",
        "reviewer-kind",
        "signature-type",
        "native-format",
        "native-identity",
        "final-digest",
    ],
)
def test_direct_envelopes_cannot_omit_common_body_kind_or_original_reference_checks(
    tmp_path: Path, fault: str
) -> None:
    """Direct records receive the same complete identity checks as decoded exact wire."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        acceptance = signed_corpus_acceptance(document, selected.ratification, budget=limits)
        if fault == "body":
            changed = replace(acceptance, component_set_digest="b" * 64)
        elif fault == "author-kind":
            changed = replace(acceptance, author_signature=acceptance.reviewer_signature)
        elif fault == "reviewer-kind":
            changed = replace(acceptance, reviewer_signature=acceptance.author_signature)
        elif fault == "signature-type":
            changed = replace(
                acceptance, author_signature=cast(RuleChainV3Signature, "caller-signature")
            )
        elif fault == "native-format":
            changed = replace(acceptance, native_ratification=reference())
        elif fault == "native-identity":
            changed = replace(acceptance, corpus_id="other")
        else:
            changed = replace(acceptance, acceptance_digest="c" * 64)
        with pytest.raises(ValueError):
            changed.to_dict(budget=limits)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "rule-corpus-author"),
        ("acceptance_digest", "b" * 64),
        ("compiler_contract_digest", "c" * 64),
    ],
)
def test_closed_envelope_version_and_integrity_fields_refuse(
    tmp_path: Path, field: str, value: str
) -> None:
    """Wire versions and complete body digests cannot be changed under valid signatures."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        wire = signed_corpus_acceptance(document, selected.ratification, budget=limits).to_dict(
            budget=limits
        )
        wire[field] = value
        with pytest.raises(ValueError):
            RuleCorpusAcceptance1.from_dict(wire, budget=limits)


def test_whole_envelope_budgets_and_missing_extra_fields_refuse(tmp_path: Path) -> None:
    """Both signature envelopes and native reference remain inside one bounded exact body."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        acceptance = signed_corpus_acceptance(document, selected.ratification, budget=limits)
        wire = acceptance.to_dict(budget=limits)
        for bad in [
            {**wire, "selected": True},
            {k: v for k, v in wire.items() if k != "native_ratification"},
        ]:
            with pytest.raises(ValueError):
                RuleCorpusAcceptance1.from_dict(bad, budget=limits)
        for budget in [corpus_budget(references=2), corpus_budget(size=10)]:
            with pytest.raises(ValueError):
                acceptance.to_dict(budget=budget)
            with pytest.raises(ValueError):
                RuleCorpusAcceptance1.from_dict(wire, budget=budget)
