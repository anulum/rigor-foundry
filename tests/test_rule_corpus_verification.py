# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real held corpus verification tests
"""Exercise actual source/compiler/native/crypto owners through retained context closure."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from test_rule_chain_trust_v3 import selected_roles
from test_rule_corpus_acceptance import signed_corpus_acceptance
from test_rule_corpus_native import CorpusNativeSelection, corpus_native_selection
from test_rule_source_compiler import Targets, compiled_document
from test_source_universe_owner import UniverseSelection, owner, universe_selection

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.native_source_host import HostNativeSourceState, HostNativeSourceVerifier
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_regions import RegionDisposition, SourceRegion1
from rigor_foundry.rule_chain_trust_v3 import TrustRolesV3
from rigor_foundry.rule_corpus_acceptance import RuleCorpusAcceptance1
from rigor_foundry.rule_corpus_native import RuleCorpusNativeOwner
from rigor_foundry.rule_corpus_ratification import RuleCorpusRatification1
from rigor_foundry.rule_corpus_verification import RuleCorpusVerifier
from rigor_foundry.rule_source_compiler import (
    compile_rule_source_document,
    rule_source_compiler_contract_digest,
    verify_rule_source_document,
)
from rigor_foundry.rule_source_document import RuleSourceDocument1
from rigor_foundry.source_universe_owner import SourceUniverseOwner

NOW = datetime(2026, 10, 28, tzinfo=UTC)


@dataclass(frozen=True)
class CorpusWorld:
    """Actual complete source/corpus/native/signature selections held for public tests."""

    selected: UniverseSelection
    source: SourceUniverseOwner
    native: CorpusNativeSelection
    native_owner: RuleCorpusNativeOwner
    document: RuleSourceDocument1
    targets: Targets
    acceptance: RuleCorpusAcceptance1
    verifier: RuleCorpusVerifier
    clock: list[datetime]
    provider_entries: list[int]


@contextmanager
def corpus_world(
    root: Path, *, kind: str = "capture", held: bool = False
) -> Iterator[CorpusWorld]:
    """Compose actual original sources, separate native approval and real TEST signatures."""
    with ExitStack() as stack:
        selected = stack.enter_context(
            universe_selection(root / "source", kind, state="protected" if held else "verified")
        )
        entries = [0]
        if kind == "native":
            original_verifier = selected.sources[0].native_verifier
            assert original_verifier is not None

            @contextmanager
            def installed_native_state() -> Iterator[HostNativeSourceState]:
                """Count actual host-provider acquisition while retaining its original context."""
                entries[0] += 1
                with original_verifier.state() as state:
                    yield state

            original_state = stack.enter_context(installed_native_state())
            borrowed = HostNativeSourceVerifier(lambda: nullcontext(original_state))
            sources = tuple(replace(item, native_verifier=borrowed) for item in selected.sources)
            arguments = {**selected.arguments, "sources": sources}
            selected = UniverseSelection(arguments, sources, selected.actual, selected.budget)
        actual = stack.enter_context(owner(selected))
        if held:
            document = compile_rule_source_document(
                corpus_id="held-corpus",
                source_owner=actual,
                regions=(),
                rules=(),
                decisions=(),
                qualitative_controls=(),
                review_policies=(),
                legacy_control_bindings=(),
                authority_bindings=(),
                freshness_policies=(),
                targets=(),
                budget=selected.budget,
            )
            targets: Targets = ()
        else:
            document, targets = compiled_document(selected, actual)
        native = stack.enter_context(
            corpus_native_selection(root / "approval", document, budget=selected.budget)
        )
        native_owner = stack.enter_context(RuleCorpusNativeOwner(**native.arguments))
        acceptance = signed_corpus_acceptance(
            document, native.ratification, budget=selected.budget
        )
        roles = selected_roles()
        clock = [NOW]
        verifier = RuleCorpusVerifier(
            actual,
            native_owner,
            roles,
            roles.trust_roles_digest,
            lambda: clock[0],
            selected.budget,
        )
        yield CorpusWorld(
            selected,
            actual,
            native,
            native_owner,
            document,
            targets,
            acceptance,
            verifier,
            clock,
            entries,
        )


@pytest.mark.parametrize("kind", ["capture", "native", "discovery"])
def test_complete_actual_owners_verify_with_separate_noncyclic_approval_and_same_held_state(
    tmp_path: Path, kind: str
) -> None:
    """Full actual corpus, original targets and actual native approval close within one held generation."""
    with corpus_world(tmp_path, kind=kind) as world:
        assert world.document.compiler_contract_digest == rule_source_compiler_contract_digest()
        assert world.native.pin.file_digest not in {
            entry.byte_digest for entry in world.document.universe
        }
        assert world.native.ratification.native_capture not in {
            entry.existing_source for entry in world.document.universe
        }
        with world.verifier.verified_context(
            world.acceptance, world.document, world.native.ratification, targets=world.targets
        ) as checked:
            assert checked == world.acceptance
            assert checked.native_ratification == world.native.ratification.reference(
                budget=world.selected.budget
            )
            world.source.verify(world.document.universe)
        assert world.provider_entries == [1 if kind == "native" else 0]


def test_valid_signatures_do_not_authenticate_partial_body_or_bad_current_crypto(
    tmp_path: Path,
) -> None:
    """Real newly signed identities still must equal the entire actual source/native body."""
    with corpus_world(tmp_path) as world:
        for field in [
            "document_digest",
            "universe_digest",
            "decision_set_digest",
            "component_set_digest",
            "compiler_contract_digest",
        ]:
            changed = signed_corpus_acceptance(
                world.document,
                world.native.ratification,
                budget=world.selected.budget,
                changes={field: "b" * 64},
            )
            with (
                pytest.raises(ValueError, match="entire actual document"),
                ExitStack() as attempted,
            ):
                attempted.enter_context(
                    world.verifier.verified_context(
                        changed, world.document, world.native.ratification, targets=world.targets
                    )
                )
        for bad_author, bad_reviewer in [(True, False), (False, True)]:
            changed = signed_corpus_acceptance(
                world.document,
                world.native.ratification,
                budget=world.selected.budget,
                bad_author=bad_author,
                bad_reviewer=bad_reviewer,
            )
            with (
                pytest.raises(PermissionError, match="signature"),
                ExitStack() as attempted,
            ):
                attempted.enter_context(
                    world.verifier.verified_context(
                        changed, world.document, world.native.ratification, targets=world.targets
                    )
                )
        wrong_selection = replace(world.verifier, trust_roles_digest="c" * 64)
        with (
            pytest.raises(PermissionError),
            ExitStack() as attempted,
        ):
            attempted.enter_context(
                wrong_selection.verified_context(
                    world.acceptance,
                    world.document,
                    world.native.ratification,
                    targets=world.targets,
                )
            )


def test_real_included_protected_source_prevents_acceptance_readiness(tmp_path: Path) -> None:
    """Native approval and valid signatures never replace missing actual included source bytes."""
    with (
        corpus_world(tmp_path, held=True) as world,
        pytest.raises(PermissionError, match="included unread or protected"),
        ExitStack() as attempted,
    ):
        attempted.enter_context(
            world.verifier.verified_context(
                world.acceptance, world.document, world.native.ratification, targets=world.targets
            )
        )


def test_complete_source_compiler_and_original_target_custody_are_mandatory(
    tmp_path: Path,
) -> None:
    """A byte-valid native acceptance cannot replace actual whole original component verification."""
    with (
        corpus_world(tmp_path) as world,
        pytest.raises(ValueError),
        ExitStack() as attempted,
    ):
        attempted.enter_context(
            world.verifier.verified_context(
                world.acceptance,
                world.document,
                world.native.ratification,
                targets=world.targets[1:],
            )
        )


def test_actual_verifier_configuration_and_exact_metadata_classes_are_closed(
    tmp_path: Path,
) -> None:
    """Caller strings and substitute implementations cannot appoint a source/native/trust owner."""
    with corpus_world(tmp_path) as world:
        invalid_configs: tuple[Callable[[], RuleCorpusVerifier], ...] = (
            lambda: replace(world.verifier, source_owner=cast(SourceUniverseOwner, "source")),
            lambda: replace(world.verifier, native_owner=cast(RuleCorpusNativeOwner, "native")),
            lambda: replace(world.verifier, roles=cast(TrustRolesV3, "roles")),
            lambda: replace(world.verifier, clock=cast(Callable[[], datetime], None)),
            lambda: replace(world.verifier, trust_roles_digest="invalid"),
            lambda: replace(world.verifier, budget=cast(PolicyReadBudget1, "budget")),
        )
        for invalid in invalid_configs:
            with pytest.raises(ValueError):
                invalid()
        with (
            pytest.raises(ValueError, match="actual complete corpus acceptance"),
            ExitStack() as attempted,
        ):
            attempted.enter_context(
                world.verifier.verified_context(
                    cast(RuleCorpusAcceptance1, "metadata"),
                    world.document,
                    world.native.ratification,
                    targets=world.targets,
                )
            )


def test_held_current_signature_lifecycle_and_generation_are_rechecked(tmp_path: Path) -> None:
    """Clock expiry and an actual valid resigning cannot swap a checked generation while held."""
    with corpus_world(tmp_path) as world:
        with (
            pytest.raises(PermissionError, match="signature"),
            world.verifier.verified_context(
                world.acceptance, world.document, world.native.ratification, targets=world.targets
            ),
        ):
            world.clock[0] = datetime(2026, 12, 1, tzinfo=UTC)
        assert world.clock[0] == datetime(2026, 12, 1, tzinfo=UTC)
        world.clock[0] = NOW
        replacement = signed_corpus_acceptance(
            world.document,
            world.native.ratification,
            budget=world.selected.budget,
            signed_at="2026-10-21T00:00:00Z",
        )
        with (
            pytest.raises(PermissionError, match="generation changed"),
            world.verifier.verified_context(
                world.acceptance, world.document, world.native.ratification, targets=world.targets
            ),
        ):
            for name in ["author_signature", "reviewer_signature", "acceptance_digest"]:
                object.__setattr__(world.acceptance, name, getattr(replacement, name))


def test_consumer_failure_is_not_suppressed_by_final_verification(tmp_path: Path) -> None:
    """The same held real owners recheck without swallowing an actual consumer exception."""
    with (
        corpus_world(tmp_path) as world,
        pytest.raises(RuntimeError, match="consumer failure"),
        world.verifier.verified_context(
            world.acceptance, world.document, world.native.ratification, targets=world.targets
        ),
    ):
        raise RuntimeError("consumer failure")


@pytest.mark.parametrize("fault", ["native-bytes", "original-source", "revocation"])
def test_suppressed_inner_read_failure_does_not_hide_changed_original_custody(
    tmp_path: Path, fault: str
) -> None:
    """Real mutation after initial success is refused again by complete closing checks."""
    entered = False
    with (
        pytest.raises((ValueError, PermissionError)),
        corpus_world(tmp_path) as world,
        world.verifier.verified_context(
            world.acceptance, world.document, world.native.ratification, targets=world.targets
        ),
    ):
        entered = True
        if fault == "native-bytes":
            world.native.path.write_bytes(world.native.path.read_bytes() + b"changed")
        elif fault == "original-source":
            source = world.selected.sources[0].payload
            assert source is not None
            source.path.write_bytes(source.path.read_bytes() + b"changed")
        else:
            object.__setattr__(
                world.native.arguments["state"],
                "revoked_pin_digests",
                frozenset({world.native.pin.pin_digest}),
            )
        with pytest.raises((ValueError, PermissionError)):
            if fault == "original-source":
                world.source.verify(world.document.universe)
            else:
                world.native_owner.verify(world.document, world.native.ratification)
    assert entered


@pytest.mark.parametrize("phase", ["initial", "closing"])
def test_unresolved_required_source_regions_hold_even_with_actual_complete_native_and_dual_signatures(
    tmp_path: Path, phase: str
) -> None:
    """Exact approval/signatures preserve an unresolved required region's hold through context use."""
    with corpus_world(tmp_path) as world:
        with world.verifier.verified_context(
            world.acceptance, world.document, world.native.ratification, targets=world.targets
        ) as control:
            assert control == world.acceptance
        source = world.selected.sources[0].payload
        assert source is not None
        payload = source.read()
        original = world.document.regions[0]
        middle = len(payload) // 2
        ranges: tuple[tuple[int, int, RegionDisposition], ...] = (
            (0, middle, "normative"),
            (middle, len(payload), "unresolved"),
        )
        regions = tuple(
            SourceRegion1.build(
                source_id=original.source_id,
                start_byte=start,
                end_byte=end,
                payload=payload,
                disposition=disposition,
                rule_ids=original.rule_ids,
                decision_ids=original.decision_ids,
                reason_code="unresolved-required-meaning"
                if disposition == "unresolved"
                else "declared-normative",
            )
            for start, end, disposition in ranges
        )
        wire = world.document.to_dict(budget=world.selected.budget)
        wire["regions"] = [region.to_dict() for region in regions]
        wire.pop("document_digest")
        changed = RuleSourceDocument1.from_dict(
            {**wire, "document_digest": canonical_digest(wire)}, budget=world.selected.budget
        )
        assert verify_rule_source_document(
            changed, source_owner=world.source, targets=world.targets, budget=world.selected.budget
        ) == ("review-rule",)
        with (
            corpus_native_selection(
                tmp_path / "unresolved-approval", changed, budget=world.selected.budget
            ) as native,
            RuleCorpusNativeOwner(**native.arguments) as native_owner,
        ):
            accepted = signed_corpus_acceptance(
                changed, native.ratification, budget=world.selected.budget
            )
            assert (
                RuleCorpusAcceptance1.from_dict(
                    accepted.to_dict(budget=world.selected.budget), budget=world.selected.budget
                )
                == accepted
            )
            assert native_owner.verify(changed, native.ratification) == native.pin
            if phase == "initial":
                verifier = replace(world.verifier, native_owner=native_owner)
                with (
                    pytest.raises(PermissionError, match="unresolved source regions"),
                    ExitStack() as attempted,
                ):
                    attempted.enter_context(
                        verifier.verified_context(
                            accepted, changed, native.ratification, targets=world.targets
                        )
                    )
            else:
                replacements: tuple[
                    tuple[
                        object,
                        RuleSourceDocument1 | RuleCorpusRatification1 | RuleCorpusAcceptance1,
                    ],
                    ...,
                ] = (
                    (world.document, changed),
                    (world.native.ratification, native.ratification),
                    (world.acceptance, accepted),
                )
                with (
                    pytest.raises(PermissionError, match="unresolved source regions"),
                    world.verifier.verified_context(
                        world.acceptance,
                        world.document,
                        world.native.ratification,
                        targets=world.targets,
                    ),
                ):
                    for current, replacement in replacements:
                        for field in fields(replacement):
                            object.__setattr__(
                                current, field.name, getattr(replacement, field.name)
                            )
                    object.__setattr__(world.verifier, "native_owner", native_owner)
