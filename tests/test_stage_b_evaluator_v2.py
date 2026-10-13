# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected Stage B composition tests
"""Exercise B1/B2/B4 through a verified fixture lease and exact body changes."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_scope_bound_selected_chain_v2 import _signature
from test_selected_clause_semantics_host_v2 import _native_ratification, _state

from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.constraint_evaluators_v2 import RateContextV2, RateIntentV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    HostSelectedClauseSemanticsVerifierV2,
    SelectedClauseSemanticsProofV2,
)
from rigor_foundry.signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2
from rigor_foundry.stage_b_evaluator_v2 import evaluate_stage_b_part_v2

_TARGET = {"form": "path", "value": "/tmp/rigor/child"}


def _context_never(_digest: str, _subject: str) -> RateContextV2:
    """Refuse context lookup from an actual signed all-admit fixture."""
    raise AssertionError("an all-admit set must not request constraint context")


def _signed_selected_body(
    selected: HostSelectedClauseSemanticsStateV2,
    body: dict[str, object],
    label: str,
) -> tuple[HostSelectedClauseSemanticsStateV2, SelectedClauseSemanticsProofV2]:
    """Sign and ratify a changed fixture body through the real selected host."""
    wire = canonical_journal_json_v2(body)
    parsed = ClauseSemanticsSetV2.from_bytes(wire)
    signed = SignedClauseSemanticsSetV2.from_bytes(
        body_bytes=wire,
        author_signature=_signature(
            "clause-semantics-set-author", parsed.body_digest, "2026-09-23T00:11:00Z"
        ).to_dict(),
        reviewer_signature=_signature(
            "clause-semantics-set", parsed.body_digest, "2026-09-23T00:12:00Z"
        ).to_dict(),
    )
    ratification_dir = selected.monorepo_root / label
    ratification_dir.mkdir()
    manifest, question, reply, transcript = _native_ratification(ratification_dir, signed)
    selected = replace(
        selected,
        signed=signed,
        expected_semantics_set_digest=parsed.body_digest,
        ratification_manifest=manifest,
        ratification_question=question,
        ratification_reply=reply,
        ratification_transcript_path=transcript,
        expected_ratification_manifest_sha256=sha256(manifest).hexdigest(),
        expected_ratification_question_sha256=sha256(question).hexdigest(),
        expected_ratification_reply_sha256=sha256(reply).hexdigest(),
    )
    proof = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected)).verify()
    return selected, proof


def _changed_body(
    selected: HostSelectedClauseSemanticsStateV2,
    *,
    subject: str,
    second_subject: str | None = None,
) -> tuple[HostSelectedClauseSemanticsStateV2, SelectedClauseSemanticsProofV2]:
    """Change a clause subject in a newly signed selected set."""
    body = selected.signed.body.to_dict()
    entries = cast(list[dict[str, object]], body["entries"])
    first = entries[0]
    first["subject"] = subject
    del first["supersedes"]
    if subject == "rate":
        first["evaluator"] = {"id": "builtin.rate.v2"}
        first["params"] = {"limit": 1, "window_seconds": 60, "count_basis": "operation-intent"}
    elif subject == "admit":
        first["supersedes"] = []
    if second_subject == "rate":
        second = entries[1]
        second["subject"] = "rate"
        del second["supersedes"]
        second["evaluator"] = {"id": "builtin.rate.v2"}
        second["params"] = {"limit": 1, "window_seconds": 60, "count_basis": "operation-intent"}
    return _signed_selected_body(selected, body, "changed-semantics")


def test_selected_lease_admits_all_four_covering_clauses(tmp_path: Path) -> None:
    """The leased result binds all active admits and the verified scope digest."""
    with _state(tmp_path) as selected:
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with verifier.verified_lease() as (state, proof):
            result = evaluate_stage_b_part_v2(
                selected=state,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )
            body = result.to_dict()
            assert body["admitting_clause_digests"] == list(
                proof.binding.active_admit_clause_digests
            )
            assert body["constraint_results"] == []
            assert body["scope_expansion_digest"] == proof.scope_expansion_digest


def test_superseded_covering_admit_is_not_reported(tmp_path: Path) -> None:
    """A ratified supersedes edge removes the covered predecessor admit."""
    with _state(tmp_path) as selected:
        body = selected.signed.body.to_dict()
        entries = cast(list[dict[str, object]], body["entries"])
        superseded = cast(str, entries[0]["clause_digest"])
        cast(list[str], entries[1]["supersedes"]).append(superseded)
        changed, _proof = _signed_selected_body(selected, body, "superseding-semantics")
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(changed))
        with verifier.verified_lease() as (leased, proof):
            assert superseded not in proof.binding.active_admit_clause_digests
            result = evaluate_stage_b_part_v2(
                selected=leased,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )
            assert result.to_dict()["admitting_clause_digests"] == list(
                proof.binding.active_admit_clause_digests
            )


def test_no_covering_admit_and_bad_target_triple_refuse(tmp_path: Path) -> None:
    """Outside targets, changed target kinds and uncovered classes refuse."""
    with _state(tmp_path) as selected:
        proof = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected)).verify()
        with pytest.raises(PermissionError, match="no active covering admit"):
            evaluate_stage_b_part_v2(
                selected=selected,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref={"form": "path", "value": "/tmp/outside"},
                context_for=_context_never,
            )
        with pytest.raises(PermissionError, match="target triple differs"):
            evaluate_stage_b_part_v2(
                selected=selected,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="send-channel",
                target_ref=_TARGET,
                context_for=_context_never,
            )
        with pytest.raises(PermissionError, match="no active covering admit"):
            evaluate_stage_b_part_v2(
                selected=selected,
                proof=proof,
                part_index=0,
                effect_class="read",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )


def test_excluded_admit_and_changed_selection_refuse_or_narrow(tmp_path: Path) -> None:
    """Scope exclusions narrow admits; changed selections and indices refuse."""

    def excluded_admit(number: int, entry: dict[str, object]) -> None:
        """Bind a covering exclusion into the selected clause and semantics."""
        if number == 1:
            cast(dict[str, object], entry["scope"])["exclusions"] = ["path:/tmp/rigor"]

    with _state(tmp_path, entry_mutator=excluded_admit) as selected:
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with verifier.verified_lease() as (leased, proof):
            result = evaluate_stage_b_part_v2(
                selected=leased,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )
            assert len(cast(list[str], result.to_dict()["admitting_clause_digests"])) == 3
            with pytest.raises(PermissionError, match="semantics or registry differs"):
                evaluate_stage_b_part_v2(
                    selected=replace(leased, expected_semantics_set_digest="0" * 64),
                    proof=proof,
                    part_index=0,
                    effect_class="local-file-write",
                    target_kind="filesystem-path",
                    target_ref=_TARGET,
                    context_for=_context_never,
                )
        with pytest.raises(ValueError, match="part index differs"):
            evaluate_stage_b_part_v2(
                selected=selected,
                proof=proof,
                part_index=-1,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )


def test_covering_veto_refuses_even_with_other_admits(tmp_path: Path) -> None:
    """A covering veto prevents admission despite the remaining admit clauses."""
    with _state(tmp_path) as selected:
        changed, changed_proof = _changed_body(selected, subject="veto")
        with pytest.raises(PermissionError, match="covering veto"):
            evaluate_stage_b_part_v2(
                selected=changed,
                proof=changed_proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )


def test_covering_veto_excluded_from_target_does_not_refuse(tmp_path: Path) -> None:
    """A selected veto's own exclusion removes its coverage at this layer."""

    def narrowed_veto(number: int, entry: dict[str, object]) -> None:
        """Bind the veto exclusion into both signed clause and semantics."""
        if number == 1:
            entry["subject"] = "veto"
            del entry["supersedes"]
            cast(dict[str, object], entry["scope"])["exclusions"] = ["path:/tmp/rigor/child"]

    with _state(tmp_path, entry_mutator=narrowed_veto) as selected:
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with verifier.verified_lease() as (leased, proof):
            result = evaluate_stage_b_part_v2(
                selected=leased,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )
            assert result.to_dict()["outcome"] == "admit"


def test_covering_veto_refuses_before_constraint_context(tmp_path: Path) -> None:
    """A covering veto prevents a later constraint from reading context."""
    with _state(tmp_path) as selected:
        changed, proof = _changed_body(selected, subject="veto", second_subject="rate")
        requested: list[tuple[str, str]] = []

        def context_for(digest: str, subject: str) -> RateContextV2:
            """Record a lookup that the covering veto must prevent."""
            requested.append((digest, subject))
            raise AssertionError("veto must win first")

        with pytest.raises(PermissionError, match="covering veto"):
            evaluate_stage_b_part_v2(
                selected=changed,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=context_for,
            )
        assert requested == []


def test_rate_constraint_pass_and_refusal_use_host_context(tmp_path: Path) -> None:
    """A matching prior intent reaches the rate cap through the real evaluator."""
    with _state(tmp_path) as selected:
        changed, changed_proof = _changed_body(selected, subject="rate")
        now = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)
        context = RateContextV2(now, "local-file-write", "/tmp/rigor/child", (), True)
        result = evaluate_stage_b_part_v2(
            selected=changed,
            proof=changed_proof,
            part_index=0,
            effect_class="local-file-write",
            target_kind="filesystem-path",
            target_ref=_TARGET,
            context_for=lambda _digest, _subject: context,
        )
        rows = cast(list[dict[str, object]], result.to_dict()["constraint_results"])
        assert len(rows) == 1 and rows[0]["evaluator_id"] == "builtin.rate.v2"
        limited = replace(
            context, intents=(RateIntentV2("local-file-write", "/tmp/rigor/child", now),)
        )
        with pytest.raises(PermissionError, match="constraint refuses"):
            evaluate_stage_b_part_v2(
                selected=changed,
                proof=changed_proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=lambda _digest, _subject: limited,
            )


def test_malformed_host_constraint_context_yields_no_result(tmp_path: Path) -> None:
    """A malformed host context cannot produce an admitted Stage B part."""
    with _state(tmp_path) as selected:
        changed, _proof = _changed_body(selected, subject="rate")
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(changed))
        with (
            verifier.verified_lease() as (leased, proof),
            pytest.raises(PermissionError, match="constraint refuses"),
        ):
            evaluate_stage_b_part_v2(
                selected=leased,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=lambda _digest, _subject: RateContextV2(
                    cast(datetime, None),
                    "local-file-write",
                    "/tmp/rigor/child",
                    (),
                    True,
                ),
            )


def test_other_class_constraint_does_not_request_context(tmp_path: Path) -> None:
    """A constraint for read cannot evaluate a local write part."""

    def read_constraint(number: int, entry: dict[str, object]) -> None:
        """Bind one read constraint into the selected signed clause chain."""
        if number == 1:
            entry["subject"] = "rate"
            entry["effect_class"] = "read"
            del entry["supersedes"]
            entry["evaluator"] = {"id": "builtin.rate.v2"}
            entry["params"] = {
                "limit": 1,
                "window_seconds": 60,
                "count_basis": "operation-intent",
            }

    with _state(tmp_path, entry_mutator=read_constraint) as selected:
        requested: list[tuple[str, str]] = []

        def context_for(digest: str, subject: str) -> RateContextV2:
            """Record a lookup that an inapplicable effect-class constraint must prevent."""
            requested.append((digest, subject))
            raise AssertionError("other-class context must not be requested")

        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with verifier.verified_lease() as (leased, proof):
            result = evaluate_stage_b_part_v2(
                selected=leased,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=context_for,
            )
            assert result.to_dict()["outcome"] == "admit"
        assert requested == []


def test_changed_scope_proof_refuses(tmp_path: Path) -> None:
    """A changed scope identity cannot authorise the extracted part."""
    with _state(tmp_path) as selected:
        proof = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected)).verify()
        with pytest.raises(PermissionError, match="scope expansion differs"):
            evaluate_stage_b_part_v2(
                selected=selected,
                proof=replace(proof, scope_expansion_digest="0" * 64),
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=_context_never,
            )


@pytest.mark.parametrize("failure", ["missing", "malformed"])
def test_real_context_source_failure_refuses(tmp_path: Path, failure: str) -> None:
    """Missing or malformed clock bytes refuse after a real positive control."""
    clock_path = tmp_path / "host-clock.txt"
    clock_path.write_text(datetime(2026, 9, 23, tzinfo=UTC).isoformat())

    def read_context(_digest: str, _subject: str) -> RateContextV2:
        """Read the fixture clock through real filesystem and timestamp parsing."""
        return RateContextV2(
            datetime.fromisoformat(clock_path.read_text()),
            "local-file-write",
            "/tmp/rigor/child",
            (),
            True,
        )

    with _state(tmp_path) as selected:
        changed, _proof = _changed_body(selected, subject="rate")
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(changed))
        with verifier.verified_lease() as (leased, proof):
            result = evaluate_stage_b_part_v2(
                selected=leased,
                proof=proof,
                part_index=0,
                effect_class="local-file-write",
                target_kind="filesystem-path",
                target_ref=_TARGET,
                context_for=read_context,
            )
            assert result.to_dict()["outcome"] == "admit"
            constraint_results = result.to_dict()["constraint_results"]
            assert isinstance(constraint_results, list)
            assert len(constraint_results) == 1
            if failure == "missing":
                clock_path.unlink()
            else:
                clock_path.write_text("not an ISO timestamp\n")
            with pytest.raises(PermissionError, match="context is unavailable") as caught:
                evaluate_stage_b_part_v2(
                    selected=leased,
                    proof=proof,
                    part_index=0,
                    effect_class="local-file-write",
                    target_kind="filesystem-path",
                    target_ref=_TARGET,
                    context_for=read_context,
                )
            if failure == "missing":
                assert isinstance(caught.value.__cause__, FileNotFoundError)
                assert caught.value.__cause__.filename == str(clock_path)
            else:
                assert isinstance(caught.value.__cause__, ValueError)
