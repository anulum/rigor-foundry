# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed rule-chain profile tests
"""Exercise exact signed v2 profile selection against real signed packs."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_rule_chain_pack_v2 import _clause, _freshness, _host_source, _pack, _roles

from rigor_foundry.models import canonical_digest
from rigor_foundry.pack_source_host import HostPackSourceVerifier
from rigor_foundry.project_profile import ProjectProfile
from rigor_foundry.rule_chain_pack_v2 import StandardPackV2
from rigor_foundry.rule_chain_profile_v2 import ProjectProfileV2, SelectedPackV2
from rigor_foundry.signed_rule_chain_v2 import (
    RuleChainV2Signature,
    rule_chain_v2_payload_digest,
)

_SIGNED_AT = "2026-09-12T00:00:00Z"
_NOW = datetime(2026, 9, 19, tzinfo=UTC)
_SCOPE = "a" * 64


def _profile(
    *,
    pack: StandardPackV2 | None = None,
    extra_selections: tuple[SelectedPackV2, ...] = (),
    authority: tuple[str, ...] = ("core/authority",),
    freshness: tuple[str, ...] = ("core/freshness",),
    excluded: tuple[str, ...] = (),
) -> ProjectProfileV2:
    """Sign one exact project selection with its distinct owner test key."""
    selected = _pack() if pack is None else pack
    selection = SelectedPackV2.build(
        pack_id=selected.pack_id,
        pack_digest=selected.pack_digest,
        source_digest=selected.source_digest,
        transition_digest=selected.transition_digest,
        pack_signer_key_id=selected.signature.key_id,
    )
    selections = (selection, *extra_selections)
    body_digest = canonical_digest(
        ProjectProfileV2.body(
            project_id="RIGOR-FOUNDRY",
            profile_id="rigor-production",
            selector_scope_digest=_SCOPE,
            selected_packs=selections,
            authority_clause_ids=authority,
            freshness_policy_ids=freshness,
            local_constraint_digests=("b" * 64,),
            excluded_clause_ids=excluded,
        )
    )
    payload = rule_chain_v2_payload_digest(
        object_kind="project-profile", body_digest=body_digest, signed_at=_SIGNED_AT
    )
    signature = RuleChainV2Signature.build(
        object_kind="project-profile",
        key_id="v2-project-selector",
        body_digest=body_digest,
        signed_at=_SIGNED_AT,
        signature_hex=sign_message(
            "v2-project-selector", "rigor-foundry.project-profile-selection.v2", payload
        ),
    )
    return ProjectProfileV2.build(
        project_id="RIGOR-FOUNDRY",
        profile_id="rigor-production",
        selector_scope_digest=_SCOPE,
        selected_packs=selections,
        authority_clause_ids=authority,
        freshness_policy_ids=freshness,
        local_constraint_digests=("b" * 64,),
        excluded_clause_ids=excluded,
        signature=signature,
    )


def _verify(profile: ProjectProfileV2, *, packs: tuple[StandardPackV2, ...] | None = None) -> bool:
    """Verify the complete candidate relation, not just the detached signature."""
    with _host_source() as source_verifier:
        return profile.verify_structural_selection(
            packs=(_pack(),) if packs is None else packs,
            roles=_roles(),
            source_verifiers={"core": source_verifier},
            expected_project_id="RIGOR-FOUNDRY",
            expected_scope_digest=_SCOPE,
            now=_NOW,
        )


def test_signed_profile_round_trips_and_authenticates_selected_pack() -> None:
    """Typed profile and pack signatures bind one exact project choice."""
    profile = _profile()
    assert ProjectProfileV2.from_dict(profile.to_dict()) == profile
    assert (
        SelectedPackV2.from_dict(profile.selected_packs[0].to_dict())
        == (profile.selected_packs[0])
    )
    assert _verify(profile)
    assert not hasattr(profile, "verify_selection")
    with pytest.raises(ValueError):
        ProjectProfile.from_dict(profile.to_dict())


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "1.0"),
        ("object_kind", "standard-pack"),
        ("project_id", "OTHER"),
        ("selector_scope_digest", "c" * 64),
        ("profile_digest", "d" * 64),
    ],
)
def test_profile_field_tamper_refuses_exact_parse(field: str, replacement: str) -> None:
    """Unsigned project, scope and profile-digest changes cannot be read."""
    wire = _profile().to_dict()
    wire[field] = replacement
    with pytest.raises(ValueError):
        ProjectProfileV2.from_dict(wire)


def test_unknown_and_missing_fields_or_scalar_arrays_refuse() -> None:
    """A v1-style omission or scalar shortcut cannot default into v2."""
    wire = _profile().to_dict()
    wire["overlay_grant"] = True
    with pytest.raises(ValueError):
        ProjectProfileV2.from_dict(wire)
    wire = _profile().to_dict()
    del wire["authority_clause_ids"]
    with pytest.raises(ValueError):
        ProjectProfileV2.from_dict(wire)
    for field in (
        "selected_packs",
        "authority_clause_ids",
        "freshness_policy_ids",
        "local_constraint_digests",
        "excluded_clause_ids",
    ):
        wire = _profile().to_dict()
        wire[field] = "scalar"
        with pytest.raises(ValueError):
            ProjectProfileV2.from_dict(wire)


def test_pack_selection_and_signer_identity_are_exact() -> None:
    """Digest, source, transition and signing key are all selected explicitly."""
    profile = _profile()
    for field in (
        "pack_digest",
        "source_digest",
        "transition_digest",
        "pack_signer_key_id",
        "selection_digest",
    ):
        wire = deepcopy(profile.to_dict())
        selected = cast(list[dict[str, object]], wire["selected_packs"])
        selected[0][field] = "e" * 64 if field != "pack_signer_key_id" else "other-key"
        with pytest.raises(ValueError):
            ProjectProfileV2.from_dict(wire)
    selected_wire = profile.selected_packs[0].to_dict()
    selected_wire["schema_version"] = "1.0"
    with pytest.raises(ValueError, match="selected-pack schema"):
        SelectedPackV2.from_dict(selected_wire)


def test_wrong_project_pack_or_signature_refuses_verification() -> None:
    """The profile cannot borrow a different scope, pack or selector key."""
    profile = _profile()
    with _host_source() as source_verifier:
        assert not profile.verify_structural_selection(
            packs=(_pack(),),
            roles=_roles(),
            source_verifiers={"core": source_verifier},
            expected_project_id="OTHER",
            expected_scope_digest=_SCOPE,
            now=_NOW,
        )
        assert not profile.verify_structural_selection(
            packs=(_pack(),),
            roles=_roles(),
            source_verifiers={"core": source_verifier},
            expected_project_id="RIGOR-FOUNDRY",
            expected_scope_digest="f" * 64,
            now=_NOW,
        )
    assert not _verify(profile, packs=())
    assert not _verify(profile, packs=(_pack(source="6" * 64),))
    assert not _verify(profile, packs=(_pack(), _pack()))
    signed_pack = _pack()
    forged_pack = replace(
        signed_pack,
        signature=replace(signed_pack.signature, signature_hex="0" * 128),
    )
    assert not _verify(profile, packs=(forged_pack,))
    assert not _verify(
        replace(profile, signature=replace(profile.signature, signature_hex="0" * 128))
    )


def test_unknown_selected_clause_or_policy_refuses_verification() -> None:
    """A signed profile cannot activate a clause absent from its exact pack."""
    assert not _verify(_profile(authority=("core/unknown",)))
    assert not _verify(_profile(freshness=("core/unknown",)))
    assert not _verify(_profile(excluded=("core/unknown",)))
    with pytest.raises(ValueError, match="select and exclude"):
        _profile(excluded=("core/authority",))


def test_profile_has_no_implicit_pack_or_clause_selection() -> None:
    """Missing selections and duplicate pack references fail before signing."""
    profile = _profile()
    with pytest.raises(ValueError, match="needs packs"):
        ProjectProfileV2.body(
            project_id=profile.project_id,
            profile_id=profile.profile_id,
            selector_scope_digest=profile.selector_scope_digest,
            selected_packs=(),
            authority_clause_ids=profile.authority_clause_ids,
            freshness_policy_ids=profile.freshness_policy_ids,
            local_constraint_digests=profile.local_constraint_digests,
            excluded_clause_ids=profile.excluded_clause_ids,
        )
    with pytest.raises(ValueError, match="twice"):
        ProjectProfileV2.body(
            project_id=profile.project_id,
            profile_id=profile.profile_id,
            selector_scope_digest=profile.selector_scope_digest,
            selected_packs=(profile.selected_packs[0], profile.selected_packs[0]),
            authority_clause_ids=profile.authority_clause_ids,
            freshness_policy_ids=profile.freshness_policy_ids,
            local_constraint_digests=profile.local_constraint_digests,
            excluded_clause_ids=profile.excluded_clause_ids,
        )


def test_duplicate_supplied_pack_cannot_satisfy_two_selections() -> None:
    """The verifier refuses a repeated pack object for a distinct selection."""
    second = SelectedPackV2.build(
        pack_id="aux",
        pack_digest="6" * 64,
        source_digest="7" * 64,
        transition_digest="8" * 64,
        pack_signer_key_id="aux-issuer",
    )
    profile = _profile(extra_selections=(second,))
    same_pack = _pack()
    assert not _verify(profile, packs=(same_pack, same_pack))


def test_each_selected_pack_requires_its_own_host_source() -> None:
    """Two signed packs verify only with their matching retained-source leases."""
    core = _pack()
    aux = _pack(
        pack_id="aux",
        clauses=(_clause(clause_id="aux/authority"),),
        policies=(_freshness(policy_id="aux/freshness"),),
    )
    selected_aux = SelectedPackV2.build(
        pack_id=aux.pack_id,
        pack_digest=aux.pack_digest,
        source_digest=aux.source_digest,
        transition_digest=aux.transition_digest,
        pack_signer_key_id=aux.signature.key_id,
    )
    profile = _profile(pack=core, extra_selections=(selected_aux,))
    with (
        _host_source() as core_source,
        _host_source(pack_id="aux", source_uri=aux.source_uri) as aux_source,
    ):

        def verify(sources: dict[str, HostPackSourceVerifier]) -> bool:
            return profile.verify_structural_selection(
                packs=(core, aux),
                roles=_roles(),
                source_verifiers=sources,
                expected_project_id="RIGOR-FOUNDRY",
                expected_scope_digest=_SCOPE,
                now=_NOW,
            )

        assert verify({"core": core_source, "aux": aux_source})
        assert not verify({"core": core_source})
        assert not verify({"core": aux_source, "aux": core_source})
