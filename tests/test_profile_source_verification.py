# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real complete selected profile source tests
"""Compose actual source/native/crypto owners and original retained packs under one held context."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_component_source_resolution import original_pack
from test_rule_chain_trust_v3 import role_policy, selected_roles
from test_rule_corpus_acceptance import corpus_signature, signed_corpus_acceptance
from test_rule_corpus_native import corpus_native_selection
from test_rule_corpus_verification import CorpusWorld, corpus_world

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.component_source_resolution import StandardPackSource2
from rigor_foundry.legacy_control_binding import LegacyControlBinding1
from rigor_foundry.pack_source_host import HostPackSourceSelection, HostPackSourceState
from rigor_foundry.profile_source_verification import ProfileSourceVerifierV3
from rigor_foundry.rule_chain_pack_v2 import StandardPackV2
from rigor_foundry.rule_chain_pack_v3 import StandardPackV3
from rigor_foundry.rule_chain_profile_v3 import (
    PackSelectionV3,
    ProfileRuleDisposition1,
    ProjectProfileV3,
)
from rigor_foundry.rule_chain_trust_v3 import TrustRolesV3
from rigor_foundry.rule_corpus_native import RuleCorpusNativeOwner
from rigor_foundry.rule_corpus_verification import RuleCorpusVerifier
from rigor_foundry.rule_source_document import RuleSourceDocument1
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2Signature, rule_chain_v2_payload_digest
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.verification_policy import OfflineTrustPolicy


@dataclass(frozen=True)
class ProfileWorld:
    """Real held corpus plus original pack-source states and full signed mixed-format selection."""

    corpus: CorpusWorld
    verifier: ProfileSourceVerifierV3
    profile: ProjectProfileV3
    packs: tuple[StandardPackV2 | StandardPackV3, ...]
    original_source: HostPackSourceState
    original_path: Path


def signed_pack(
    world: CorpusWorld, *, bad_crypto: bool = False, **changes: object
) -> StandardPackV3:
    """Sign actual new complete source components, with controlled valid structural mutations."""
    limits, document = world.selected.budget, world.document
    original = original_pack()
    body = StandardPackV3.body(
        pack_id="complete-quality",
        version="1.0.0",
        source_uri="opaque:canonical-source-document",
        source_digest=document.document_digest,
        corpus_acceptance_digest=world.acceptance.acceptance_digest,
        licence="Apache-2.0",
        controls=document.qualitative_controls,
        authority_clauses=(),
        freshness_policies=tuple(
            row for row in document.freshness_policies if row not in original.freshness_policies
        ),
        budget=limits,
    )
    body.update(changes)
    body["signature"] = corpus_signature(
        "standard-pack", canonical_digest(body), budget=limits, fault=bad_crypto
    ).to_dict(budget=limits)
    return StandardPackV3.from_dict({**body, "pack_digest": canonical_digest(body)}, budget=limits)


def signed_profile(
    world: CorpusWorld,
    packs: tuple[StandardPackV2 | StandardPackV3, ...],
    bad_crypto: bool = False,
    **changes: object,
) -> ProjectProfileV3:
    """Sign actual selected pack identities and complete source rules with the selector TEST key."""
    limits = world.selected.budget
    selections = tuple(
        PackSelectionV3.build(
            pack_id=pack.pack_id,
            pack_format="2.0" if type(pack) is StandardPackV2 else "3.0",
            pack_digest=pack.pack_digest,
            source_digest=pack.source_digest,
            transition_digest=pack.transition_digest if type(pack) is StandardPackV2 else None,
            corpus_acceptance_digest=pack.corpus_acceptance_digest
            if type(pack) is StandardPackV3
            else None,
            pack_signer_key_id=pack.signature.key_id,
            budget=limits,
        )
        for pack in packs
    )
    body = ProjectProfileV3.body(
        project_id="example",
        profile_id="source-bound",
        selector_scope_digest="9" * 64,
        selected_packs=selections,
        corpus_acceptance_digest=world.acceptance.acceptance_digest,
        mandatory_rule_ids=tuple(
            row.rule_id for row in world.document.rules if row.mandatory_floor
        ),
        rule_dispositions=tuple(
            ProfileRuleDisposition1.build(
                rule_id=row.rule_id,
                disposition="included",
                decision_id="adopt-original",
                budget=limits,
            )
            for row in world.document.rules
        ),
        target_maturity="production",
        legacy_fact_context_digest=canonical_digest(
            {"declared-test-context": "source binding does not authenticate current facts"}
        )
        if any(
            control.condition is not None
            for pack in packs
            if type(pack) is StandardPackV2
            for control in pack.controls
        )
        else None,
        local_constraint_digests=(),
        budget=limits,
    )
    body.update(changes)
    body["signature"] = corpus_signature(
        "project-profile", canonical_digest(body), budget=limits, fault=bad_crypto
    ).to_dict(budget=limits)
    return ProjectProfileV3.from_dict(
        {**body, "profile_digest": canonical_digest(body)}, budget=limits
    )


@contextmanager
def profile_world(
    root: Path, *, source_variant: str = "default", original_override: StandardPackV2 | None = None
) -> Iterator[ProfileWorld]:
    """Hold actual original filesystem/source/native owners; no request installs a provider."""
    original = (
        original_override
        if original_override is not None
        else original_pack(controls=())
        if source_variant == "authority-only"
        else original_pack()
    )
    corpus_root = root / "corpus"
    corpus_root.mkdir()
    with corpus_world(corpus_root) as base_world, ExitStack() as held:
        world = base_world
        if source_variant != "default" or original_override is not None:
            limits = world.selected.budget
            wire = world.document.to_dict(budget=limits)
            rules = cast(list[dict[str, object]], wire["rules"])
            if source_variant != "default":
                rules[0]["mandatory_floor"] = False
            pack_ref = StandardPackSource2(original, limits).reference()
            source_rule = world.document.rules[0]
            bindings = tuple(
                LegacyControlBinding1.build(
                    rule_id=source_rule.rule_id,
                    pack=pack_ref,
                    control=PolicyComponent1(control, limits).reference(),
                    source_decision_ids=("adopt-original",),
                    budget=limits,
                )
                for control in original.controls
            )
            refs = [
                ref
                for ref in source_rule.component_refs
                if (ref.kind, ref.format_version) != ("control-definition", "1.0")
            ]
            refs.extend(binding.control for binding in bindings)
            rules[0]["component_refs"] = [
                ref.to_dict()
                for ref in sorted(
                    refs, key=lambda ref: (ref.kind, ref.format_version, ref.object_id)
                )
            ]
            wire["legacy_control_bindings"] = [
                binding.to_dict(budget=limits) for binding in bindings
            ]
            targets = (
                (pack_ref, original.to_dict()),
                *((ref, body) for ref, body in world.targets if ref.kind != "standard-pack"),
            )
            if source_variant == "exclusion":
                decisions = cast(list[dict[str, object]], wire["decisions"])
                decisions[0]["relation"] = "exclusion"
                decisions[0].pop("decision_digest")
                decisions[0]["decision_digest"] = canonical_digest(decisions[0])
            rules[0].pop("rule_digest")
            rules[0]["rule_digest"] = canonical_digest(rules[0])
            wire.pop("document_digest")
            wire["document_digest"] = canonical_digest(wire)
            document = RuleSourceDocument1.from_dict(wire, budget=limits)
            native = held.enter_context(
                corpus_native_selection(root / "variant-approval", document, budget=limits)
            )
            native_owner = held.enter_context(RuleCorpusNativeOwner(**native.arguments))
            acceptance = signed_corpus_acceptance(document, native.ratification, budget=limits)
            world = replace(
                world,
                document=document,
                targets=targets,
                native=native,
                native_owner=native_owner,
                acceptance=acceptance,
                verifier=replace(world.verifier, native_owner=native_owner),
            )
        world.clock[0] = datetime(2026, 10, 28, 13, tzinfo=UTC)
        base = selected_roles()
        roles = TrustRolesV3.build(
            pack_issuers=OfflineTrustPolicy.build(
                (*base.pack_issuers.keys, *role_policy("common-policy-legacy-pack").keys)
            ),
            project_selectors=base.project_selectors,
            lock_resolvers=base.lock_resolvers,
            semantic_authors=base.semantic_authors,
            semantic_reviewers=base.semantic_reviewers,
        )
        corpus = replace(world.verifier, roles=roles, trust_roles_digest=roles.trust_roles_digest)
        path = root / "original-source.txt"
        path.write_bytes(b"Retain every selected architecture control.\n")
        selected = HostPackSourceSelection.build(
            pack_id=original.pack_id,
            source_uri=original.source_uri,
            source_digest=original.source_digest,
            retained_path=path,
        )
        state = HostPackSourceState(selected, selected.selection_digest, frozenset())
        packs: tuple[StandardPackV2 | StandardPackV3, ...] = (original, signed_pack(world))
        profile = signed_profile(world, packs)
        verifier = ProfileSourceVerifierV3(
            corpus,
            (state,),
            profile.profile_digest,
            profile.project_id,
            profile.selector_scope_digest,
        )
        yield ProfileWorld(world, verifier, profile, packs, state, path)


def enter_profile(
    stack: ExitStack,
    world: ProfileWorld,
    *,
    profile: ProjectProfileV3 | None = None,
    packs: tuple[StandardPackV2 | StandardPackV3, ...] | None = None,
    verifier: ProfileSourceVerifierV3 | None = None,
) -> None:
    """Enter only the actual public source-owning composition with complete retained bodies."""
    corpus = world.corpus
    stack.enter_context(
        (verifier or world.verifier).verified_context(
            profile if profile is not None else world.profile,
            packs if packs is not None else world.packs,
            corpus.document,
            corpus.acceptance,
            corpus.native.ratification,
            targets=corpus.targets,
        )
    )


def test_actual_complete_mixed_pack_sources_and_original_controls_remain_held(
    tmp_path: Path,
) -> None:
    """Original numeric controls and new quality components all survive the complete source join."""
    with profile_world(tmp_path) as world:
        corpus = world.corpus
        with world.verifier.verified_context(
            world.profile,
            world.packs,
            corpus.document,
            corpus.acceptance,
            corpus.native.ratification,
            targets=corpus.targets,
        ) as proof:
            assert proof.profile_digest == world.profile.profile_digest
            assert proof.selected_pack_digests == tuple(row.pack_digest for row in world.packs)
            assert len(proof.pack_source_verification_digests) == 2
            assert len(proof.legacy_controls) == 2
            assert proof.qualitative_controls == tuple(
                row.reference(budget=corpus.selected.budget)
                for row in corpus.document.qualitative_controls
            )
            assert proof.rule_ids == ("review-rule",)
            assert not hasattr(proof, "lock_digest")


def test_actual_protected_selection_and_child_identity_are_not_caller_choices(
    tmp_path: Path,
) -> None:
    """Fresh valid signatures and mutable tuples cannot replace protected project or complete bodies."""
    with profile_world(tmp_path) as world:
        limits = world.corpus.selected.budget
        altered_selection = world.profile.selected_packs[1].to_dict(budget=limits)
        altered_selection.pop("selection_digest")
        altered_selection["pack_signer_key_id"] = "other-issuer"
        altered_selection["selection_digest"] = canonical_digest(altered_selection)
        changed = signed_profile(
            world.corpus,
            world.packs,
            selected_packs=[
                world.profile.selected_packs[0].to_dict(budget=limits),
                altered_selection,
            ],
        )
        for profile, packs, verifier in (
            (world.profile, world.packs, replace(world.verifier, expected_project_id="other")),
            (world.profile, (), world.verifier),
            (world.profile, tuple(reversed(world.packs)), world.verifier),
            (
                changed,
                world.packs,
                replace(world.verifier, expected_profile_digest=changed.profile_digest),
            ),
        ):
            with pytest.raises((ValueError, PermissionError)), ExitStack() as stack:
                enter_profile(stack, world, profile=profile, packs=packs, verifier=verifier)


def test_real_freshly_signed_omissions_do_not_replace_complete_accepted_component_cohort(
    tmp_path: Path,
) -> None:
    """The source owner independently derives every control, authority and freshness component."""
    with profile_world(tmp_path) as world:
        original, quality = world.packs
        assert type(original) is StandardPackV2 and type(quality) is StandardPackV3
        for replacement in (
            signed_pack(world.corpus, controls=[]),
            original_pack(controls=original.controls[:1]),
            signed_pack(
                world.corpus,
                authority_clauses=[row.to_dict() for row in original.authority_clauses],
            ),
        ):
            packs = (
                (replacement, quality)
                if type(replacement) is StandardPackV2
                else (original, replacement)
            )
            selected = signed_profile(world.corpus, packs)
            verifier = replace(world.verifier, expected_profile_digest=selected.profile_digest)
            with (
                pytest.raises(PermissionError, match="complete source components"),
                ExitStack() as stack,
            ):
                enter_profile(stack, world, profile=selected, packs=packs, verifier=verifier)


def test_actual_rule_dispositions_and_floor_come_from_complete_accepted_source(
    tmp_path: Path,
) -> None:
    """A signed profile cannot omit source floors, omit rules or appoint an unrelated decision."""
    with profile_world(tmp_path) as world:
        limits = world.corpus.selected.budget
        unrelated = ProfileRuleDisposition1.build(
            rule_id="review-rule", disposition="included", decision_id="unrelated", budget=limits
        )
        for changes, reason in (
            ({"mandatory_rule_ids": []}, "mandatory identities"),
            ({"mandatory_rule_ids": [], "rule_dispositions": []}, "complete source rule cohort"),
            ({"rule_dispositions": [unrelated.to_dict(budget=limits)]}, "absent or unrelated"),
        ):
            selected = signed_profile(world.corpus, world.packs, **changes)
            verifier = replace(world.verifier, expected_profile_digest=selected.profile_digest)
            with pytest.raises(PermissionError, match=reason), ExitStack() as stack:
                enter_profile(stack, world, profile=selected, verifier=verifier)


def test_original_source_revocation_and_current_policy_fail_before_yield(tmp_path: Path) -> None:
    """Current original retained bytes and original signature policy remain actual required owners."""
    with profile_world(tmp_path) as world:
        revoked = replace(
            world.original_source,
            revoked_selection_digests=frozenset({world.original_source.expected_selection_digest}),
        )
        verifier = replace(world.verifier, original_sources=(revoked,))
        with pytest.raises(PermissionError, match="original pack source"), ExitStack() as stack:
            enter_profile(stack, world, verifier=verifier)
        world.original_path.write_bytes(b"changed actual retained source\n")
        with pytest.raises(PermissionError, match="original pack source"), ExitStack() as stack:
            enter_profile(stack, world)


def test_closing_original_source_generation_change_refuses_after_valid_consumer_use(
    tmp_path: Path,
) -> None:
    """A fully valid replacement retained source selection still changes the held proof generation."""
    with (
        profile_world(tmp_path) as world,
        pytest.raises(PermissionError, match="generation changed"),
        ExitStack() as stack,
    ):
        enter_profile(stack, world)
        duplicate = tmp_path / "different-original-source.txt"
        duplicate.write_bytes(world.original_path.read_bytes())
        changed = HostPackSourceSelection.build(
            pack_id=world.original_source.selected.pack_id,
            source_uri=world.original_source.selected.source_uri,
            source_digest=world.original_source.selected.source_digest,
            retained_path=duplicate,
        )
        object.__setattr__(world.original_source, "selected", changed)
        object.__setattr__(
            world.original_source, "expected_selection_digest", changed.selection_digest
        )


def test_consumer_failure_and_closing_clock_mutation_are_not_suppressed(
    tmp_path: Path,
) -> None:
    """The outer actual corpus stays held through exceptions and initial/closing source checks."""
    with profile_world(tmp_path) as world:
        with pytest.raises(RuntimeError, match="consumer failed"), ExitStack() as stack:
            enter_profile(stack, world)
            raise RuntimeError("consumer failed")
        with pytest.raises(PermissionError, match="signature"), ExitStack() as stack:
            enter_profile(stack, world)
            world.corpus.clock[0] = datetime(2027, 1, 1, tzinfo=UTC)


def test_fixed_owner_composition_refuses_unheld_or_duplicate_original_source_states(
    tmp_path: Path,
) -> None:
    """No untrusted callback, foreign owner or mutable source cohort becomes an installed host."""
    with profile_world(tmp_path) as world:
        for changes in (
            {"corpus_verifier": cast(RuleCorpusVerifier, "caller-owner")},
            {"original_sources": cast(tuple[HostPackSourceState, ...], [])},
            {"original_sources": cast(tuple[HostPackSourceState, ...], ("caller-state",))},
            {"original_sources": (world.original_source, world.original_source)},
            {
                "original_sources": (world.original_source,)
                * (world.corpus.selected.budget.max_sources + 1)
            },
        ):
            with pytest.raises(ValueError):
                replace(world.verifier, **changes)


def test_actual_new_parent_crypto_and_source_relations_are_checked_separately(
    tmp_path: Path,
) -> None:
    """Fresh valid metadata cannot authenticate another real key or another source document."""
    with profile_world(tmp_path) as world:
        bad_profile = signed_profile(world.corpus, world.packs, bad_crypto=True)
        with (
            pytest.raises(PermissionError, match="profile3 current selected signature"),
            ExitStack() as stack,
        ):
            enter_profile(
                stack,
                world,
                profile=bad_profile,
                verifier=replace(
                    world.verifier, expected_profile_digest=bad_profile.profile_digest
                ),
            )
        for pack in (
            signed_pack(world.corpus, bad_crypto=True),
            signed_pack(world.corpus, source_digest="0" * 64),
        ):
            packs = (world.packs[0], pack)
            selected = signed_profile(world.corpus, packs)
            with pytest.raises(PermissionError, match="pack3 source"), ExitStack() as stack:
                enter_profile(
                    stack,
                    world,
                    profile=selected,
                    packs=packs,
                    verifier=replace(
                        world.verifier, expected_profile_digest=selected.profile_digest
                    ),
                )


def test_actual_original_transition_and_full_pack_identity_are_not_interchangeable(
    tmp_path: Path,
) -> None:
    """Original source and valid current crypto do not repair mismatched transition or pack bindings."""
    with profile_world(tmp_path) as world:
        limits = world.corpus.selected.budget
        selection = world.profile.selected_packs[0].to_dict(budget=limits)
        selection.pop("selection_digest")
        selection["transition_digest"] = "0" * 64
        selection["selection_digest"] = canonical_digest(selection)
        selected = signed_profile(
            world.corpus,
            world.packs,
            selected_packs=[selection, world.profile.selected_packs[1].to_dict(budget=limits)],
        )
        with pytest.raises(PermissionError, match="transition selection"), ExitStack() as stack:
            enter_profile(
                stack,
                world,
                profile=selected,
                verifier=replace(world.verifier, expected_profile_digest=selected.profile_digest),
            )
        original = world.packs[0]
        assert type(original) is StandardPackV2
        body = original.to_dict()
        body.pop("pack_digest")
        body.pop("signature")
        body["licence"] = "Apache-2.0"
        digest = canonical_digest(body)
        signed_at = original.signature.signed_at
        payload = rule_chain_v2_payload_digest(
            object_kind="standard-pack", body_digest=digest, signed_at=signed_at
        )
        body["signature"] = RuleChainV2Signature.build(
            object_kind="standard-pack",
            key_id=original.signature.key_id,
            body_digest=digest,
            signed_at=signed_at,
            signature_hex=sign_message(
                original.signature.key_id, "rigor-foundry.standard-pack.v2", payload
            ),
        ).to_dict()
        different = StandardPackV2.from_dict({**body, "pack_digest": canonical_digest(body)})
        packs = (different, world.packs[1])
        selected = signed_profile(world.corpus, packs)
        with (
            pytest.raises(PermissionError, match="different original pack cohort"),
            ExitStack() as stack,
        ):
            enter_profile(
                stack,
                world,
                profile=selected,
                packs=packs,
                verifier=replace(world.verifier, expected_profile_digest=selected.profile_digest),
            )


def test_only_actual_complete_original_states_and_profile_owners_can_enter(tmp_path: Path) -> None:
    """Actual outer corpus approval does not make foreign profile objects or absent old sources valid."""
    with profile_world(tmp_path) as world:
        with (
            pytest.raises(ValueError, match="actual complete project profile3"),
            ExitStack() as stack,
        ):
            enter_profile(stack, world, profile=cast(ProjectProfileV3, {}))
        with pytest.raises(PermissionError, match="old-pack cohort"), ExitStack() as stack:
            enter_profile(stack, world, verifier=replace(world.verifier, original_sources=()))


def test_conditional_original_controls_require_the_legacy_context_declaration(
    tmp_path: Path,
) -> None:
    """Source metadata cannot omit the declared fact dependency needed by actual old conditions."""
    with profile_world(tmp_path) as world:
        selected = signed_profile(world.corpus, world.packs, legacy_fact_context_digest=None)
        with (
            pytest.raises(PermissionError, match="legacy fact-context declaration"),
            ExitStack() as stack,
        ):
            enter_profile(
                stack,
                world,
                profile=selected,
                verifier=replace(world.verifier, expected_profile_digest=selected.profile_digest),
            )


def test_original_authority_pack_without_numeric_controls_preserves_complete_source_coverage(
    tmp_path: Path,
) -> None:
    """An unchanged authority-only original pack needs no fabricated numeric-control binding."""
    with profile_world(tmp_path, source_variant="authority-only") as world, ExitStack() as stack:
        enter_profile(stack, world)
        original = world.packs[0]
        assert type(original) is StandardPackV2 and original.controls == ()
        assert not world.corpus.document.legacy_control_bindings


@pytest.mark.parametrize("source_variant", ["nonmandatory", "exclusion"])
def test_dispositions_retain_exact_source_decisions_without_claiming_competent_exclusion_authority(
    tmp_path: Path,
    source_variant: str,
) -> None:
    """Source-bound declarations remain distinct from semantic approval and effective-lock admission."""
    with profile_world(tmp_path, source_variant=source_variant) as world:
        limits = world.corpus.selected.budget
        excluded = ProfileRuleDisposition1.build(
            rule_id="review-rule",
            disposition="excluded",
            decision_id="adopt-original",
            budget=limits,
        )
        selected = signed_profile(
            world.corpus, world.packs, rule_dispositions=[excluded.to_dict(budget=limits)]
        )
        verifier = replace(world.verifier, expected_profile_digest=selected.profile_digest)
        if source_variant == "nonmandatory":
            with (
                pytest.raises(PermissionError, match="source exclusion declaration"),
                ExitStack() as stack,
            ):
                enter_profile(stack, world, profile=selected, verifier=verifier)
        else:
            with ExitStack() as stack:
                enter_profile(stack, world, profile=selected, verifier=verifier)
        included = ProfileRuleDisposition1.build(
            rule_id="review-rule", disposition="included", decision_id=None, budget=limits
        )
        selected = signed_profile(
            world.corpus, world.packs, rule_dispositions=[included.to_dict(budget=limits)]
        )
        with ExitStack() as stack:
            enter_profile(
                stack,
                world,
                profile=selected,
                verifier=replace(world.verifier, expected_profile_digest=selected.profile_digest),
            )
