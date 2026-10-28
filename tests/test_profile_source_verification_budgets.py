# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — whole selected source body allocation tests
"""Verify aggregate allocation through actual signed complete source and profile owners."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_component_source_resolution import original_pack
from test_context_owner_implementation import implementation_budget
from test_profile_source_verification import (
    enter_profile,
    profile_world,
    signed_pack,
    signed_profile,
)

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.component_source_resolution import StandardPackSource2
from rigor_foundry.policy_model_inputs import policy_wire_size
from rigor_foundry.rule_chain_pack_v2 import StandardPackV2
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2Signature, rule_chain_v2_payload_digest


def expanded_original_pack() -> StandardPackV2:
    """Sign a real original evidence contract with a distinct identity and many required proof types."""
    original = original_pack()
    body = original.to_dict()
    body.pop("pack_digest")
    body.pop("signature")
    controls = cast(list[dict[str, object]], body["controls"])
    evidence = cast(dict[str, object], controls[0]["evidence"])
    evidence["contract_id"] = "evidence/expanded-source-proofs"
    evidence["evidence_types"] = [f"retained-source-proof-{index}" for index in range(2000)]
    evidence.pop("contract_digest")
    evidence["contract_digest"] = canonical_digest(evidence)
    controls[0].pop("control_digest")
    controls[0]["control_digest"] = canonical_digest(controls[0])
    digest, instant = canonical_digest(body), original.signature.signed_at
    payload = rule_chain_v2_payload_digest(
        object_kind="standard-pack", body_digest=digest, signed_at=instant
    )
    body["signature"] = RuleChainV2Signature.build(
        object_kind="standard-pack",
        key_id=original.signature.key_id,
        body_digest=digest,
        signed_at=instant,
        signature_hex=sign_message(
            original.signature.key_id, "rigor-foundry.standard-pack.v2", payload
        ),
    ).to_dict()
    return StandardPackV2.from_dict({**body, "pack_digest": canonical_digest(body)})


@pytest.mark.parametrize("references", [False, True])
def test_individually_valid_signed_bodies_cannot_exceed_complete_selected_pack_cohort_bounds(
    tmp_path: Path,
    references: bool,
) -> None:
    """Actual full corpus and each real pack fit; their combined metadata must still refuse."""
    original = expanded_original_pack() if references else original_pack()
    with profile_world(tmp_path, original_override=original if references else None) as world:
        packs, profile = world.packs, world.profile
        if references:
            limits = implementation_budget(max_references=2000)
            while True:
                try:
                    StandardPackSource2(original, limits)
                    break
                except ValueError:
                    limits = implementation_budget(max_references=limits.max_references + 1)
            reason = "aggregate component reference budget"
        else:
            quality = signed_pack(
                world.corpus,
                source_uri="opaque:" + "retained-source-locator." * 3000,
            )
            packs = (original, quality)
            profile = signed_profile(world.corpus, packs)
            size = policy_wire_size(
                quality.to_dict(budget=world.corpus.selected.budget),
                budget=world.corpus.selected.budget,
            )
            limits = implementation_budget(max_document_bytes=size + 2)
            reason = "aggregate body byte budget"
        corpus = replace(world.verifier.corpus_verifier, budget=limits)
        verifier = replace(
            world.verifier, corpus_verifier=corpus, expected_profile_digest=profile.profile_digest
        )
        assert StandardPackSource2(original, limits).record == original
        with corpus.verified_context(
            world.corpus.acceptance,
            world.corpus.document,
            world.corpus.native.ratification,
            targets=world.corpus.targets,
        ) as accepted:
            assert accepted == world.corpus.acceptance
        with pytest.raises(ValueError, match=reason), ExitStack() as stack:
            enter_profile(stack, world, profile=profile, packs=packs, verifier=verifier)


def test_actual_original_pack_payloads_have_a_complete_source_byte_limit(tmp_path: Path) -> None:
    """Real old-pack source reads remain bounded independently of signed component metadata."""
    with profile_world(tmp_path) as world:
        limits = implementation_budget(max_total_source_bytes=1)
        corpus = replace(world.verifier.corpus_verifier, budget=limits)
        verifier = replace(world.verifier, corpus_verifier=corpus)
        with pytest.raises(ValueError, match="complete source byte budget"), ExitStack() as stack:
            enter_profile(stack, world, verifier=verifier)
