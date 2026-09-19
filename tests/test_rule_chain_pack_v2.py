# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed rule-chain pack tests
"""Exercise exact v2 pack wire and source-bound real Ed25519 verification."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import pytest
from signing_fixtures import public_key_hex, sign_message
from test_semantic_transition import _evidence

from rigor_foundry.models import canonical_digest
from rigor_foundry.pack_source_host import (
    HostPackSourceSelection,
    HostPackSourceState,
    HostPackSourceVerifier,
)
from rigor_foundry.rule_chain_pack_v2 import (
    AuthorityClauseV2,
    FreshnessMode,
    FreshnessPolicyV2,
    StandardPackV2,
)
from rigor_foundry.signed_rule_chain_v2 import (
    RuleChainV2Signature,
    RuleChainV2TrustRoles,
    rule_chain_v2_payload_digest,
)
from rigor_foundry.standard_pack import StandardPack
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_SOURCE_BYTES = b"retained core standard source\n"
_SOURCE = sha256(_SOURCE_BYTES).hexdigest()
_TRANSITION = "2" * 64
_RECEIPT = "3" * 64
_KEY = "v2-pack-issuer"
_SIGNED_AT = "2026-09-12T00:00:00Z"
_NOW = datetime(2026, 9, 19, tzinfo=UTC)


def _roles() -> RuleChainV2TrustRoles:
    def policy(key_id: str) -> OfflineTrustPolicy:
        return OfflineTrustPolicy.build(
            (
                VerificationKeyPolicy.build(
                    key=TrustedPublicKey.build(
                        key_id=key_id, public_key_hex=public_key_hex(key_id)
                    ),
                    valid_from="2026-09-01T00:00:00Z",
                    valid_until="2026-10-01T00:00:00Z",
                ),
            )
        )

    return RuleChainV2TrustRoles.build(
        pack_issuers=policy(_KEY),
        project_selectors=policy("v2-project-selector"),
        lock_resolvers=policy("v2-lock-resolver"),
        semantic_reviewers=policy("v2-semantic-reviewer"),
    )


def _clause(
    *,
    clause_id: str = "core/authority",
    successor_id: str = "new-1",
    statement_digest: str = "4" * 64,
    source_receipt_digest: str = _RECEIPT,
    transition_digest: str = _TRANSITION,
    grantor_classes: tuple[str, ...] = ("owner",),
    scope_selector_digest: str = "6" * 64,
) -> AuthorityClauseV2:
    return AuthorityClauseV2.build(
        clause_id=clause_id,
        successor_id=successor_id,
        statement_digest=statement_digest,
        source_receipt_digest=source_receipt_digest,
        transition_digest=transition_digest,
        issuer_class="owner",
        grantor_classes=grantor_classes,
        scope_digest="5" * 64,
        scope_selector_digest=scope_selector_digest,
        effect_class="local-write",
        adapter_id="fs-adapter",
    )


def _freshness(*, policy_id: str = "core/freshness") -> FreshnessPolicyV2:
    return FreshnessPolicyV2.build(
        policy_id=policy_id,
        claim_type="file-state",
        subject_class="repository",
        mode="mutable-state",
        risk_class="high",
        invalidator_ids=("git-head", "grant-revocation"),
        proof_adapter_id="git-adapter",
    )


def _pack(
    *,
    pack_id: str = "core",
    source: str = _SOURCE,
    transition: str = _TRANSITION,
    clauses: tuple[AuthorityClauseV2, ...] | None = None,
    policies: tuple[FreshnessPolicyV2, ...] | None = None,
) -> StandardPackV2:
    clauses = (_clause(),) if clauses is None else clauses
    policies = (_freshness(),) if policies is None else policies
    body_digest = canonical_digest(
        StandardPackV2.body(
            pack_id=pack_id,
            version="2.0.0",
            source_uri=f"https://standards.example/{pack_id}/v2",
            source_digest=source,
            transition_digest=transition,
            licence="MIT",
            controls=(),
            authority_clauses=clauses,
            freshness_policies=policies,
        )
    )
    payload = rule_chain_v2_payload_digest(
        object_kind="standard-pack", body_digest=body_digest, signed_at=_SIGNED_AT
    )
    signature = RuleChainV2Signature.build(
        object_kind="standard-pack",
        key_id=_KEY,
        body_digest=body_digest,
        signed_at=_SIGNED_AT,
        signature_hex=sign_message(_KEY, "rigor-foundry.standard-pack.v2", payload),
    )
    return StandardPackV2.build(
        pack_id=pack_id,
        version="2.0.0",
        source_uri=f"https://standards.example/{pack_id}/v2",
        source_digest=source,
        transition_digest=transition,
        licence="MIT",
        controls=(),
        authority_clauses=clauses,
        freshness_policies=policies,
        signature=signature,
    )


def _verify(
    pack: StandardPackV2,
    *,
    source_bytes: bytes = _SOURCE_BYTES,
    source_uri: str = "https://standards.example/core/v2",
) -> bool:
    with _host_source(source_bytes=source_bytes, source_uri=source_uri) as source_verifier:
        return pack.verify_structural_source_signature(
            roles=_roles(),
            source_verifier=source_verifier,
            now=_NOW,
        )


@contextmanager
def _host_source(
    *,
    pack_id: str = "core",
    source_bytes: bytes = _SOURCE_BYTES,
    source_uri: str = "https://standards.example/core/v2",
) -> Iterator[HostPackSourceVerifier]:
    """Hold a real retained object and one host selection for a public verification."""
    with TemporaryDirectory() as directory:
        path = Path(directory) / "retained-source"
        path.write_bytes(source_bytes)
        selection = HostPackSourceSelection.build(
            pack_id=pack_id,
            source_uri=source_uri,
            source_digest=sha256(source_bytes).hexdigest(),
            retained_path=path,
        )

        @contextmanager
        def state() -> Iterator[HostPackSourceState]:
            yield HostPackSourceState(selection, selection.selection_digest, frozenset())

        yield HostPackSourceVerifier(state)


def test_pack_round_trip_and_exact_external_source_dependencies() -> None:
    pack = _pack()
    assert StandardPackV2.from_dict(pack.to_dict()) == pack
    assert AuthorityClauseV2.from_dict(_clause().to_dict()) == _clause()
    assert FreshnessPolicyV2.from_dict(_freshness().to_dict()) == _freshness()
    assert _verify(pack)
    assert not _verify(pack, source_bytes=b"another retained source\n")
    assert not hasattr(pack, "verify_source_bound_signature")


@pytest.mark.parametrize(
    ("component", "field", "replacement"),
    [
        ("authority_clauses", "successor_id", "different-successor"),
        ("authority_clauses", "statement_digest", "6" * 64),
        ("authority_clauses", "source_receipt_digest", "7" * 64),
        ("authority_clauses", "scope_selector_digest", "7" * 64),
        ("authority_clauses", "grantor_classes", "vendor"),
        ("authority_clauses", "clause_digest", "8" * 64),
        ("freshness_policies", "mode", "duration"),
        ("freshness_policies", "policy_digest", "9" * 64),
    ],
)
def test_nested_tamper_is_rejected(component: str, field: str, replacement: str) -> None:
    wire = deepcopy(_pack().to_dict())
    entries = cast(list[dict[str, object]], wire[component])
    entries[0][field] = replacement
    with pytest.raises(ValueError):
        StandardPackV2.from_dict(wire)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "1.1"),
        ("object_kind", "project-profile"),
        ("source_digest", "6" * 64),
        ("transition_digest", "7" * 64),
        ("pack_digest", "8" * 64),
    ],
)
def test_pack_tamper_and_downgrade_are_rejected(field: str, replacement: str) -> None:
    wire = _pack().to_dict()
    wire[field] = replacement
    with pytest.raises(ValueError):
        StandardPackV2.from_dict(wire)


def test_v2_refuses_numeric_ttl_extra_fields_and_v1_parser() -> None:
    wire = _pack().to_dict()
    policies = cast(list[dict[str, object]], wire["freshness_policies"])
    policies[0]["freshness_seconds"] = 3600
    with pytest.raises(ValueError):
        StandardPackV2.from_dict(wire)
    wire = _pack().to_dict()
    wire["legacy_default"] = True
    with pytest.raises(ValueError):
        StandardPackV2.from_dict(wire)
    with pytest.raises(ValueError):
        StandardPack.from_dict(_pack().to_dict())


def test_component_wire_requires_v2_schema_and_typed_arrays() -> None:
    clause = _clause().to_dict()
    clause["schema_version"] = "1.0"
    with pytest.raises(ValueError, match="authority-clause schema"):
        AuthorityClauseV2.from_dict(clause)
    policy = _freshness().to_dict()
    policy["schema_version"] = "1.0"
    with pytest.raises(ValueError, match="freshness-policy schema"):
        FreshnessPolicyV2.from_dict(policy)
    policy = _freshness().to_dict()
    policy["invalidator_ids"] = "git-head"
    with pytest.raises(ValueError, match="must be an array"):
        FreshnessPolicyV2.from_dict(policy)
    wire = _pack().to_dict()
    wire["authority_clauses"] = {"core/authority": _clause().to_dict()}
    with pytest.raises(ValueError, match="must be arrays"):
        StandardPackV2.from_dict(wire)
    wire = _pack().to_dict()
    wire["source_uri"] = "https://standards.example/has space"
    with pytest.raises(ValueError, match="whitespace"):
        StandardPackV2.from_dict(wire)


def test_unsigned_source_claim_or_structural_signature_cannot_admit_pack() -> None:
    replacement = b"another retained source\n"
    pack = _pack(source=sha256(replacement).hexdigest())
    assert not _verify(pack)
    assert _verify(pack, source_bytes=replacement)
    forged = replace(pack, signature=replace(pack.signature, signature_hex="0" * 128))
    assert not _verify(forged)
    assert not _verify(replace(pack, pack_digest="0" * 64))


def test_same_source_bytes_at_another_uri_do_not_borrow_admission() -> None:
    """A matching digest cannot transfer source admission across URI identity."""
    pack = _pack()
    assert not _verify(
        pack,
        source_uri="https://other.example/core/v2",
    )


def test_missing_retained_object_refuses_at_signed_pack_boundary() -> None:
    pack = _pack()
    with _host_source() as source_verifier:
        with source_verifier.state() as current:
            current.selected.retained_path.unlink()
        assert not pack.verify_structural_source_signature(
            roles=_roles(),
            source_verifier=source_verifier,
            now=_NOW,
        )
        assert not pack.verify_structural_source_signature(
            roles=_roles(),
            source_verifier=cast(HostPackSourceVerifier, object()),
            now=_NOW,
        )


def test_suppressing_host_lease_cannot_admit_signed_pack() -> None:
    """A swallowed source failure must not become pack admission."""
    pack = _pack()
    with TemporaryDirectory() as directory:
        path = Path(directory) / "retained-source"
        path.write_bytes(b"changed source\n")
        selection = HostPackSourceSelection.build(
            pack_id=pack.pack_id,
            source_uri=pack.source_uri,
            source_digest=pack.source_digest,
            retained_path=path,
        )

        @contextmanager
        def suppressing_state() -> Iterator[HostPackSourceState]:
            with suppress(ValueError):
                yield HostPackSourceState(selection, selection.selection_digest, frozenset())

        assert not pack.verify_structural_source_signature(
            roles=_roles(),
            source_verifier=HostPackSourceVerifier(suppressing_state),
            now=_NOW,
        )


def test_component_identity_and_semantic_transition_are_exact() -> None:
    with pytest.raises(ValueError, match="semantic transition"):
        _pack(clauses=(_clause(transition_digest="9" * 64),))
    with pytest.raises(ValueError, match="namespace"):
        _pack(clauses=(_clause(clause_id="foreign/authority"),))
    with pytest.raises(ValueError, match="distinct"):
        _pack(clauses=(_clause(clause_id="core/freshness"),))
    with pytest.raises(ValueError, match="needs authority"):
        _pack(clauses=())


def test_grantor_and_scope_selector_are_signed_but_not_grants() -> None:
    """A clause pins its grantor class and selector without issuing an effect."""
    clause = _clause()
    assert clause.successor_id == "new-1"
    assert clause.grantor_classes == ("owner",)
    assert clause.scope_selector_digest == "6" * 64
    with pytest.raises(ValueError, match="at least 1"):
        _clause(grantor_classes=())
    with pytest.raises(ValueError, match="unique"):
        _clause(grantor_classes=("owner", "owner"))
    with pytest.raises(ValueError, match="digest"):
        _clause(scope_selector_digest="unreviewed")
    with pytest.raises(ValueError, match="successor_id"):
        _clause(successor_id="")


def test_clause_links_exact_successor_statement_and_receipt(tmp_path: Path) -> None:
    """A signed clause must still match the proposal's precise source span."""
    proposal, _, _, _, _ = _evidence(tmp_path)
    first, second = proposal.replacements[:2]
    linked = _clause(
        successor_id=first.successor_id,
        statement_digest=first.statement_digest,
        source_receipt_digest=proposal.source_receipt_digest,
    )
    assert linked.matches_proposal_source(proposal)
    assert not _clause(
        successor_id=second.successor_id,
        statement_digest=first.statement_digest,
        source_receipt_digest=proposal.source_receipt_digest,
    ).matches_proposal_source(proposal)
    assert not _clause(
        successor_id=first.successor_id,
        statement_digest=second.statement_digest,
        source_receipt_digest=proposal.source_receipt_digest,
    ).matches_proposal_source(proposal)
    assert not _clause(
        successor_id=first.successor_id,
        statement_digest=first.statement_digest,
        source_receipt_digest="0" * 64,
    ).matches_proposal_source(proposal)
    assert not replace(linked, successor_id="forged").matches_proposal_source(proposal)


def test_immutable_and_mutable_policy_modes_are_explicit() -> None:
    immutable = FreshnessPolicyV2.build(
        policy_id="core/immutable",
        claim_type="content-digest",
        subject_class="object",
        mode="immutable-object",
        risk_class="low",
        invalidator_ids=("source-revocation",),
        proof_adapter_id="object-adapter",
    )
    assert FreshnessPolicyV2.from_dict(immutable.to_dict()) == immutable
    with pytest.raises(ValueError, match="unsupported"):
        FreshnessPolicyV2.build(
            policy_id="core/bad",
            claim_type="file-state",
            subject_class="repository",
            mode=cast("FreshnessMode", "one-hour"),
            risk_class="high",
            invalidator_ids=("git-head",),
            proof_adapter_id="git-adapter",
        )
