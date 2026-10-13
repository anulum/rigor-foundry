# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected clause-semantics host tests
"""Exercise exact signatures and native owner custody inside a selected lease."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_clause_semantics_ratification_v2 import _SESSION
from test_project_registry_models import group, project
from test_project_registry_models import registry as project_registry
from test_scope_bound_selected_chain_v2 import _scope_bound_state
from test_selected_rule_chain_host_v2 import _selected
from test_semantic_ratification_source import _line

from rigor_foundry.clause_semantics_ratification_v2 import render_clause_semantics_question_v2
from rigor_foundry.constraint_evaluator_registry_v2 import ConstraintEvaluatorRegistryV2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    HostSelectedClauseSemanticsVerifierV2,
)
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainVerifierV2,
)
from rigor_foundry.signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2
from rigor_foundry.tier0_builtin.selected_path_scope_v2 import derive_selected_path_scope_v2

_GROUP = "AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS"


def _native_ratification(
    root: Path, signed: SignedClauseSemanticsSetV2
) -> tuple[bytes, bytes, bytes, Path]:
    """Retain an exact rendered question and later native owner line."""
    question = render_clause_semantics_question_v2(signed.body)
    reply = f"SCHVAĽUJEM clause-semantics-set {signed.body.body_digest}\n".encode()
    transcript = root / f"{_SESSION}.jsonl"
    question_at = "2026-09-23T00:13:00.000Z"
    reply_at = "2026-09-23T00:14:00.000Z"
    lines = [
        _line({"type": "mode"}),
        _line(
            {
                "type": "assistant",
                "uuid": "question-1",
                "timestamp": question_at,
                "sessionId": _SESSION,
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": question[:-1].decode()}],
                },
            }
        ),
        _line({"type": "system", "uuid": "system-1", "parentUuid": "question-1"}),
        _line(
            {
                "type": "user",
                "origin": {"kind": "human"},
                "uuid": "reply-1",
                "timestamp": reply_at,
                "sessionId": _SESSION,
                "parentUuid": "system-1",
                "message": {"role": "user", "content": reply[:-1].decode()},
            }
        ),
    ]
    transcript.write_bytes(b"".join(lines))
    captures: dict[str, object] = {}
    for name, number, role, timestamp, capture in (
        ("CEO_QUESTION_FULL_TEXT.txt", 2, "assistant", question_at, question),
        ("OWNER_REPLY.txt", 4, "user", reply_at, reply),
    ):
        captures[name] = {
            "jsonl_line": number,
            "uuid": "question-1" if number == 2 else "reply-1",
            "timestamp": timestamp,
            "type": role,
            "text_bytes": len(capture),
            "text_sha256": sha256(capture).hexdigest(),
            "native_line_sha256": sha256(lines[number - 1]).hexdigest(),
        }
    manifest = json.dumps(
        {"transcript": str(transcript), "session": _SESSION, "captures": captures},
        separators=(",", ":"),
    ).encode()
    return manifest, question, reply, transcript


@contextmanager
def _state(
    root: Path,
    *,
    first_atomic: bool = False,
    entry_mutator: Callable[[int, dict[str, object]], None] | None = None,
) -> Iterator[HostSelectedClauseSemanticsStateV2]:
    """Select one real signed fixture chain and native owner ratification."""
    with _selected(root, first_atomic=first_atomic) as legacy:
        chain_state, signed = _scope_bound_state(legacy, entry_mutator=entry_mutator)
        manifest, question, reply, transcript = _native_ratification(root, signed)
        registry: ProjectRegistry = project_registry(
            groups=(group(_GROUP),),
            projects=(project(chain_state.profile.project_id, _GROUP),),
        )
        if first_atomic:
            path_scope = derive_selected_path_scope_v2(
                registry_bytes=registry.to_bytes(),
                monorepo_root=str(root),
                selected_project_id=chain_state.profile.project_id,
                registry_generation_id=registry.generation_id,
                registry_sha256=registry.registry_sha256,
            )
            chain_state = replace(chain_state, path_scope=path_scope)
        vocabulary = EffectVocabularyV2.build()
        target_table = EffectTargetTableV2.build()
        evaluators = ConstraintEvaluatorRegistryV2.build()
        yield HostSelectedClauseSemanticsStateV2(
            chain=HostSelectedRuleChainVerifierV2(lambda: nullcontext(chain_state)),
            signed=signed,
            registry=registry,
            vocabulary=vocabulary,
            target_table=target_table,
            evaluator_registry=evaluators,
            monorepo_root=root,
            expected_semantics_set_digest=signed.body.body_digest,
            expected_registry_sha256=registry.registry_sha256,
            expected_effect_vocabulary_digest=vocabulary.vocabulary_digest,
            expected_effect_target_table_digest=target_table.table_digest,
            expected_evaluator_registry_digest=evaluators.registry_digest,
            expected_resolver_version="registry-v1-interim",
            ratification_manifest=manifest,
            ratification_question=question,
            ratification_reply=reply,
            ratification_transcript_path=transcript,
            expected_ratification_manifest_sha256=sha256(manifest).hexdigest(),
            expected_ratification_question_sha256=sha256(question).hexdigest(),
            expected_ratification_reply_sha256=sha256(reply).hexdigest(),
            authority_requirement=None,
            expected_authority_requirement_digest=None,
            owner_confirmation=None,
            expected_owner_confirmation_digest=None,
            confirmation_manifest=None,
            confirmation_question=None,
            confirmation_reply=None,
            revalidate=lambda: None,
        )


def test_selected_host_checks_chain_semantics_and_native_ratification(tmp_path: Path) -> None:
    """A single selected lease binds the exact pack, signed set and owner line."""
    with _state(tmp_path) as selected:
        proof = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected)).verify()
        assert proof.chain.lock_digest == selected.chain.verify().lock_digest
        assert proof.binding.semantics_set_digest == selected.signed.body.body_digest
        assert len(proof.binding.active_admit_clause_digests) == 4
        assert len(proof.ratification_proof_digest) == 64
        assert len(proof.scope_expansion_digest) == 64
        assert proof.registry_generation_id == selected.registry.generation_id
        assert proof.registry_sha256 == selected.registry.registry_sha256


def test_coherent_selection_tamper_with_valid_signatures_refuses_closing_proof(
    tmp_path: Path,
) -> None:
    """Two separately valid selections cannot be swapped through yielded state memory."""
    original_root = tmp_path / "original"
    variant_root = tmp_path / "variant"
    original_root.mkdir()
    variant_root.mkdir()
    with _state(original_root) as selected:
        with selected.chain.state() as chain_state:
            predecessor = chain_state.lock.authority_clauses[0].clause_digest

            def supersede_first(number: int, entry: dict[str, object]) -> None:
                """Make a genuine second semantics graph over the same signed chain."""
                if number == 2:
                    entry["supersedes"] = [predecessor]

            rebuilt, signed = _scope_bound_state(chain_state, entry_mutator=supersede_first)
            assert rebuilt.lock == chain_state.lock
        manifest, question, reply, transcript = _native_ratification(variant_root, signed)
        successor = replace(
            selected,
            signed=signed,
            expected_semantics_set_digest=signed.body.body_digest,
            ratification_manifest=manifest,
            ratification_question=question,
            ratification_reply=reply,
            ratification_transcript_path=transcript,
            expected_ratification_manifest_sha256=sha256(manifest).hexdigest(),
            expected_ratification_question_sha256=sha256(question).hexdigest(),
            expected_ratification_reply_sha256=sha256(reply).hexdigest(),
        )
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        original_proof = verifier.verify()
        successor_proof = HostSelectedClauseSemanticsVerifierV2(
            lambda: nullcontext(successor)
        ).verify()
        assert original_proof != successor_proof
        assert len(original_proof.binding.active_admit_clause_digests) == 4
        assert len(successor_proof.binding.active_admit_clause_digests) == 3
        with (
            pytest.raises(PermissionError, match="changed during lease"),
            verifier.verified_lease() as (held, proof),
        ):
            assert held is selected and proof == original_proof
            # Model a provider/caller that violates snapshot pinning. Frozen
            # assignment does not prevent ordinary instance-dictionary tamper.
            # Both input sets have real signatures and physical native captures.
            vars(held).update(vars(successor))


@pytest.mark.parametrize(
    "fault",
    ["semantics-pin", "registry-pin", "target-table-pin", "target-table-body", "ratification-pin"],
)
def test_changed_protected_choice_refuses(tmp_path: Path, fault: str) -> None:
    """A matching signature cannot override a changed selected digest."""
    with _state(tmp_path) as selected:
        if fault == "semantics-pin":
            selected = replace(selected, expected_semantics_set_digest="0" * 64)
        elif fault == "registry-pin":
            selected = replace(selected, expected_registry_sha256="0" * 64)
        elif fault == "target-table-pin":
            selected = replace(selected, expected_effect_target_table_digest="0" * 64)
        elif fault == "target-table-body":
            selected = replace(
                selected,
                target_table=replace(selected.target_table, table_digest="0" * 64),
            )
        else:
            selected = replace(selected, expected_ratification_reply_sha256="0" * 64)
        with pytest.raises((PermissionError, ValueError)):
            HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected)).verify()


def test_native_owner_custody_change_during_lease_refuses(tmp_path: Path) -> None:
    """The final recheck detects a changed native line after initial proof."""
    with _state(tmp_path) as selected:
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with (
            pytest.raises((PermissionError, ValueError)),
            verifier.verified_lease() as (_, proof),
        ):
            assert proof.binding.semantics_set_digest == selected.signed.body.body_digest
            selected.ratification_transcript_path.write_bytes(b"replaced transcript\n")


def test_registry_generation_change_during_lease_refuses(tmp_path: Path) -> None:
    """An atomic registry generation change invalidates the selected lease."""
    with _state(tmp_path) as selected:
        registry_path = tmp_path / "active-registry.json"
        registry_path.write_bytes(selected.registry.to_bytes())
        next_registry = project_registry(
            groups=selected.registry.groups,
            projects=selected.registry.projects,
            generated_at="2026-09-04T12:01:00.000000Z",
            previous=selected.registry.registry_sha256,
        )
        assert next_registry.generation_id != selected.registry.generation_id

        def revalidate_registry() -> None:
            """Check the real registry file against the pinned generation."""
            current = ProjectRegistry.from_bytes(registry_path.read_bytes())
            if current.generation_id != selected.registry.generation_id:
                raise PermissionError("registry generation changed during lease")

        verifier = HostSelectedClauseSemanticsVerifierV2(
            lambda: nullcontext(replace(selected, revalidate=revalidate_registry))
        )
        with (
            pytest.raises(PermissionError, match="registry generation changed during lease"),
            verifier.verified_lease() as (_, proof),
        ):
            assert proof.registry_generation_id == selected.registry.generation_id
            candidate = tmp_path / "next-registry.json"
            candidate.write_bytes(next_registry.to_bytes())
            candidate.replace(registry_path)
        assert ProjectRegistry.from_bytes(registry_path.read_bytes()) == next_registry


def test_swallowing_provider_and_malformed_state_refuse(tmp_path: Path) -> None:
    """A faulty state context cannot suppress a failed selection."""
    malformed = cast(HostSelectedClauseSemanticsStateV2, object())
    with pytest.raises(PermissionError, match="host state is unavailable"):
        HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(malformed)).verify()
    with _state(tmp_path) as selected:

        @contextmanager
        def swallowing() -> Iterator[HostSelectedClauseSemanticsStateV2]:
            """Model a provider that swallows a protected pin failure."""
            with suppress(PermissionError):
                yield replace(selected, expected_semantics_set_digest="0" * 64)

        with pytest.raises(RuntimeError, match="suppressed a failure"):
            HostSelectedClauseSemanticsVerifierV2(swallowing).verify()
