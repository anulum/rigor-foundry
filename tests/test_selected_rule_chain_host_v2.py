# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected v2 rule-chain host tests
"""Exercise selected-lock reinspection through real signed and retained files."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import fields, replace
from pathlib import Path
from typing import cast

import pytest
from test_rule_chain_candidate_v2 import _chain
from test_rule_chain_lock_v2 import (
    _HOST_SELECTION,
    _ISSUERS,
    _NOW,
    _RESOLVER_DIGEST,
    _adapter,
    _lock,
)
from test_rule_chain_pack_v2 import _host_source
from test_semantic_acceptance_host_v2 import _host as acceptance_host

from rigor_foundry.adapter_operations_v2 import AdapterOperationsV2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.rule_chain_candidate_v2 import inspect_rule_chain_candidate_v2
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    HostSelectedRuleChainVerifierV2,
    SelectedRuleChainArtifactsV2,
)


@contextmanager
def _selected(
    root: Path, *, nested: bool = False, first_atomic: bool = False
) -> Iterator[HostSelectedRuleChainStateV2]:
    """Select one synthetic four-successor chain with real source files."""
    proposal, acceptance_state, inputs, pack, profile, roles = _chain(root, nested=nested)
    with _host_source() as source:
        verifier = acceptance_host(acceptance_state)
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
            acceptance_verifier=verifier,
            packs=(pack,),
            profile=profile,
            source_verifiers={pack.pack_id: source},
            roles=roles,
            expected_project_id=profile.project_id,
            expected_scope_digest=profile.selector_scope_digest,
            now=_NOW,
        )
        adapters = (_adapter("fs-adapter"), _adapter("git-adapter"))
        vocabulary = EffectVocabularyV2.build()
        table = EffectTargetTableV2.build()
        registry = (
            ExtractorRegistryV2.first_atomic_candidate()
            if first_atomic
            else ExtractorRegistryV2.empty()
        )
        operations = (
            AdapterOperationsV2.first_atomic_candidate(
                vocabulary=vocabulary, target_table=table, extractors=registry
            )
            if first_atomic
            else AdapterOperationsV2.empty(
                vocabulary=vocabulary, target_table=table, extractors=registry
            )
        )
        lock = _lock(
            report,
            pack,
            profile,
            source,
            adapters,
            effect_operations_digest=operations.operations_digest,
        )
        yield HostSelectedRuleChainStateV2(
            artifacts=SelectedRuleChainArtifactsV2(
                proposal,
                cast(bytes, inputs["proposal_artifact"]),
                cast(bytes, inputs["proposal_source"]),
                cast(bytes, inputs["original_owner_question"]),
                cast(bytes, inputs["original_owner_reply"]),
                cast(bytes, inputs["normative_source"]),
                cast(bytes, inputs["ratification_manifest"]),
                cast(bytes, inputs["ratification_question"]),
                cast(bytes, inputs["ratification_reply"]),
                cast(bytes, inputs["findings"]),
            ),
            acceptance_verifier=verifier,
            packs=(pack,),
            profile=profile,
            source_verifiers={pack.pack_id: source},
            roles=roles,
            current_adapters=adapters,
            effect_vocabulary=vocabulary,
            effect_target_table=table,
            extractor_registry=registry,
            effect_operations=operations,
            lock=lock,
            expected_lock_digest=lock.lock_digest,
            expected_project_id=profile.project_id,
            expected_scope_digest=profile.selector_scope_digest,
            expected_acceptance_host_selection_digest=_HOST_SELECTION,
            expected_effect_vocabulary_digest=vocabulary.vocabulary_digest,
            expected_effect_target_table_digest=table.table_digest,
            expected_extractor_registry_digest=registry.registry_digest,
            expected_effect_operations_digest=operations.operations_digest,
            expected_resolver_code_digest=_RESOLVER_DIGEST,
            expected_issuer_order=_ISSUERS,
            clock=lambda: _NOW,
            revalidate=lambda: None,
        )


def test_selected_host_rebuilds_four_successors_and_exact_lock(tmp_path: Path) -> None:
    """The host recomputes a signed CLEAR, pack, profile and resolver lock."""
    with _selected(tmp_path) as state:
        proof = HostSelectedRuleChainVerifierV2(lambda: nullcontext(state)).verify()
        assert proof.lock_digest == state.lock.lock_digest
        assert proof.rule_projection_digest == state.lock.rule_projection_digest
        assert proof.acceptance_digest == state.lock.acceptance_digest
        assert proof.successor_clause_digests == state.lock.successor_clause_digests


def test_selected_host_verified_lease_pins_same_state_through_consumer(tmp_path: Path) -> None:
    """The four-successor check and consumer run before host lease release."""
    events: list[str] = []
    with _selected(tmp_path) as state:

        @contextmanager
        def host_state() -> Iterator[HostSelectedRuleChainStateV2]:
            """Record the protected selection's lifetime."""
            events.append("enter")
            try:
                yield replace(state, revalidate=lambda: events.append("revalidate"))
            finally:
                events.append("exit")

        with HostSelectedRuleChainVerifierV2(host_state).verified_lease() as (selected, proof):
            assert selected.lock.lock_digest == proof.lock_digest
            events.append("consumer")
            assert events == ["enter", "revalidate", "consumer"]
    assert events == [
        "enter",
        "revalidate",
        "consumer",
        "revalidate",
        "revalidate",
        "exit",
    ]


def test_selected_host_verified_lease_refuses_suppressed_consumer_failure(
    tmp_path: Path,
) -> None:
    """A faulty host provider cannot turn a refused effect into success."""
    with _selected(tmp_path) as state:

        @contextmanager
        def swallowing() -> Iterator[HostSelectedRuleChainStateV2]:
            """Model a provider that suppresses a consumer refusal."""
            with suppress(PermissionError):
                yield state

        with (
            pytest.raises(RuntimeError, match="suppressed a failure"),
            HostSelectedRuleChainVerifierV2(swallowing).verified_lease(),
        ):
            raise PermissionError("consumer refused")


def test_selected_host_verified_lease_refuses_source_change_after_consumer(
    tmp_path: Path,
) -> None:
    """The final lease check rereads retained bytes after the consumer runs."""
    with _selected(tmp_path) as state:
        pack = state.packs[0]
        with state.source_verifiers[pack.pack_id].state() as source_state:
            retained_path = source_state.selected.retained_path
        verifier = HostSelectedRuleChainVerifierV2(lambda: nullcontext(state))
        with (
            pytest.raises((PermissionError, ValueError)),
            verifier.verified_lease() as (_, proof),
        ):
            assert proof.lock_digest == state.lock.lock_digest
            retained_path.write_bytes(b"changed retained source during consumer\n")


def test_selected_host_verified_lease_refuses_valid_selection_swap(tmp_path: Path) -> None:
    """A newly valid selection cannot replace the one pinned before consumption."""
    nested_root = tmp_path / "nested"
    nested_root.mkdir()
    with _selected(tmp_path) as first, _selected(nested_root, nested=True) as second:
        assert first.lock.lock_digest != second.lock.lock_digest
        verifier = HostSelectedRuleChainVerifierV2(lambda: nullcontext(first))
        with (
            pytest.raises(PermissionError, match="changed during lease"),
            verifier.verified_lease() as (_, proof),
        ):
            assert proof.lock_digest == first.lock.lock_digest
            for field in fields(HostSelectedRuleChainStateV2):
                object.__setattr__(first, field.name, getattr(second, field.name))


def test_selected_host_verified_lease_refuses_operations_pin_swap(tmp_path: Path) -> None:
    """The final recheck catches a changed protected effect catalogue pin."""
    with _selected(tmp_path) as state:
        verifier = HostSelectedRuleChainVerifierV2(lambda: nullcontext(state))
        with (
            pytest.raises(PermissionError, match="effect-operation body differs"),
            verifier.verified_lease(),
        ):
            object.__setattr__(state, "expected_effect_operations_digest", "0" * 64)


@pytest.mark.parametrize(
    "fault",
    [
        "lock",
        "resolver",
        "source",
        "adapter",
        "vocabulary-pin",
        "table-pin",
        "registry-pin",
        "operations-pin",
        "operations-body",
    ],
)
def test_selected_host_refuses_changed_choice_or_live_dependency(
    tmp_path: Path, fault: str
) -> None:
    """A protected choice cannot be replaced by stale inspected artifacts."""
    with _selected(tmp_path) as state:
        if fault == "lock":
            changed = replace(state, expected_lock_digest="0" * 64)
        elif fault == "resolver":
            changed = replace(state, expected_resolver_code_digest="0" * 64)
        elif fault == "source":
            changed = replace(
                state,
                artifacts=replace(state.artifacts, normative_source=b"changed source\n"),
            )
        elif fault == "adapter":
            changed = replace(state, current_adapters=(_adapter("other-adapter"),))
        elif fault == "vocabulary-pin":
            changed = replace(state, expected_effect_vocabulary_digest="0" * 64)
        elif fault == "table-pin":
            changed = replace(state, expected_effect_target_table_digest="0" * 64)
        elif fault == "registry-pin":
            changed = replace(state, expected_extractor_registry_digest="0" * 64)
        elif fault == "operations-pin":
            changed = replace(state, expected_effect_operations_digest="0" * 64)
        elif fault == "operations-body":
            changed = replace(
                state,
                effect_operations=replace(state.effect_operations, operations_digest="0" * 64),
            )
        else:
            raise AssertionError(f"unknown fixture fault: {fault}")
        with pytest.raises((PermissionError, ValueError)):
            HostSelectedRuleChainVerifierV2(lambda: nullcontext(changed)).verify()


@pytest.mark.parametrize("failure", ["changed", "missing"])
def test_selected_host_refuses_real_selection_revocation(tmp_path: Path, failure: str) -> None:
    """Recheck the actual selected-lock file before and after consumption."""
    selection = tmp_path / "selected-lock.txt"
    with _selected(tmp_path) as state:
        selection.write_text(state.lock.lock_digest, encoding="ascii")

        def revalidate() -> None:
            """Read the current fixture selection and refuse a changed lock."""
            if selection.read_text(encoding="ascii") != state.lock.lock_digest:
                raise PermissionError("selected v2 selection was revoked")

        selected = replace(state, revalidate=revalidate)
        verifier = HostSelectedRuleChainVerifierV2(lambda: nullcontext(selected))
        assert verifier.verify().lock_digest == state.lock.lock_digest
        with verifier.verified_lease() as (_, proof):
            assert proof.lock_digest == state.lock.lock_digest

        error = PermissionError if failure == "changed" else FileNotFoundError
        with pytest.raises(error) as refusal, verifier.verified_lease() as (_, proof):
            assert proof.lock_digest == state.lock.lock_digest
            if failure == "changed":
                selection.write_text("0" * 64, encoding="ascii")
            else:
                selection.unlink()
        if failure == "missing":
            assert isinstance(refusal.value, FileNotFoundError)
            assert refusal.value.filename == str(selection)
        else:
            assert str(refusal.value) == "selected v2 selection was revoked"


def test_selected_host_refuses_suppressed_lease_failure(tmp_path: Path) -> None:
    """A state provider that swallows verification failure cannot return proof."""
    with _selected(tmp_path) as state:

        @contextmanager
        def swallowing() -> Iterator[HostSelectedRuleChainStateV2]:
            """Model a faulty context manager suppressing an exception."""
            with suppress(PermissionError):
                yield replace(state, expected_lock_digest="0" * 64)

        with pytest.raises(RuntimeError, match="suppressed a failure"):
            HostSelectedRuleChainVerifierV2(swallowing).verify()


def test_selected_host_refuses_wrong_state_type() -> None:
    """A malformed host provider cannot produce a selected-chain proof."""
    malformed = cast(HostSelectedRuleChainStateV2, object())
    with pytest.raises(PermissionError, match="host state is unavailable"):
        HostSelectedRuleChainVerifierV2(lambda: nullcontext(malformed)).verify()
    with (
        pytest.raises(PermissionError, match="host state is unavailable"),
        HostSelectedRuleChainVerifierV2(lambda: nullcontext(malformed)).verified_lease(),
    ):
        pytest.fail("malformed host state reached consumer")
