# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual effect-journal rate context tests
"""Exercise actual journal reads through public selected applicability consumers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest
from selected_applicability_support import (
    ApplicabilityFixture,
    applicability_fixture,
    evaluate_applicability,
)
from test_effect_journal_state_v2 import _intent

from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.constraint_evaluators_v2 import (
    EvaluatorContextV2,
    RateContextV2,
    WindowContextV2,
    evaluate_rate_v2,
)
from rigor_foundry.effect_journal_rate_v2 import EffectJournalRateSourceV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.effect_journal_v2 import EffectJournalLeaseV2, EffectJournalStoreV2
from rigor_foundry.selected_dispatch_extraction_v2 import (
    ExtractedDispatchPartV2,
    extract_selected_dispatch_request_v2,
)
from rigor_foundry.selected_rule_chain_host_v2 import HostSelectedRuleChainStateV2

_NOW = datetime.now(UTC)
_FIRST = "123e4567-e89b-12d3-a456-426614174000"
_SECOND = "123e4567-e89b-12d3-a456-426614174001"
_DIGEST = "a" * 64
_PARAMS: dict[str, object] = {"limit": 1, "window_seconds": 60, "count_basis": "operation-intent"}


def _other(_digest: str, _subject: str) -> EvaluatorContextV2:
    """Provide a separately installed ordinary clock for non-rate subjects."""
    return WindowContextV2(datetime.now(UTC))


@contextmanager
def _selected(root: Path) -> Iterator[tuple[ApplicabilityFixture, ExtractedDispatchPartV2, str]]:
    """Retain actual signed sources and extract the original immutable invocation."""
    available = RateContextV2(_NOW, "local-file-write", "fixture-context", (), True)
    with applicability_fixture(
        root, subject="rate", context_for=lambda _d, _s: available
    ) as fixture:
        selected = fixture
        extracted = extract_selected_dispatch_request_v2(
            fixture.request,
            selected_chain=selected.chain,
            chain_proof=selected.chain_proof,
            selected_semantics=selected.semantics,
            semantics_proof=selected.semantics_proof,
            observed_lock_digest=selected.chain_proof.lock_digest,
            observed_projection_digest=selected.chain_proof.rule_projection_digest,
        )
        entries = cast(
            list[dict[str, object]], selected.semantics.signed.body.to_dict()["entries"]
        )
        digest = next(
            cast(str, entry["clause_digest"]) for entry in entries if entry["subject"] == "rate"
        )
        yield fixture, extracted.parts[0], digest


@contextmanager
def _journal(root: Path) -> Iterator[tuple[EffectJournalStoreV2, EffectJournalLeaseV2]]:
    """Retain one real owner-only journal lock through all source reads."""
    parent = root / "rate-journal"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    genesis = store.initialize()
    with store.locked(selected_head_digest=genesis, max_bytes=1000000) as lease:
        yield store, lease


def _source(
    lease: EffectJournalLeaseV2, fixture: ApplicabilityFixture
) -> EffectJournalRateSourceV2:
    """Install an explicit complete-history origin and fixture host clock."""

    def catalogue_for(digest: str) -> HostSelectedRuleChainStateV2:
        """Retain the actual fixture catalogue only for its exact original digest."""
        chain = fixture.chain
        if digest != chain.effect_operations.operations_digest:
            raise PermissionError("original catalogue unavailable")
        return chain

    return EffectJournalRateSourceV2(
        lease, _NOW - timedelta(days=1), lambda: _NOW, frozenset(), _other, catalogue_for
    )


def _append(
    lease: EffectJournalLeaseV2,
    part: ExtractedDispatchPartV2,
    fixture: ApplicabilityFixture,
    *,
    age: int = 0,
) -> None:
    """Fsync a real operation-intent with exact independently extracted target fields."""
    body = _intent(_FIRST, part.target_ref)
    body.update(
        adapter_operations_digest=fixture.chain.effect_operations.operations_digest,
        operation_key=part.operation_id,
    )
    cast(list[dict[str, object]], body["parts"])[0]["operation_variant"] = part.operation_variant
    lease.append_from_host(
        kind="operation-intent",
        body=body,
        host_time=(_NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z"),
    )


@pytest.mark.parametrize("age, admitted", [(61, True), (60, False), (0, False)])
def test_real_journal_window_decides_selected_applicability(
    tmp_path: Path, age: int, admitted: bool
) -> None:
    """The common producer counts actual intents at the inclusive signed window boundary."""
    with _selected(tmp_path) as (fixture, part, _digest), _journal(tmp_path) as (store, lease):
        before = fixture.target.read_bytes()
        _append(lease, part, fixture, age=age)
        source = _source(lease, fixture)
        if admitted:
            result = evaluate_applicability(fixture, context_for=source)
            assert result.guard_admissible is False
            assert result.results[0].to_dict()["constraint_results"]
        else:
            with pytest.raises(PermissionError, match="applicable constraint refuses"):
                evaluate_applicability(fixture, context_for=source)
        assert fixture.target.read_bytes() == before
        assert len(lease.snapshot.records) == 1
        assert store.path.read_bytes().endswith(lease.snapshot.records[0].frame)


def test_fresh_append_after_first_read_is_counted_and_selection_prefix_does_not_hide_it(
    tmp_path: Path,
) -> None:
    """A retained source rescans newly appended intents beyond the earlier selected prefix."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        source = _source(lease, fixture)
        context_for = source.for_part(fixture.semantics, part)
        first = context_for(digest, "rate")
        assert isinstance(first, RateContextV2)
        assert first.intents == () and first.window_start_reached
        _append(lease, part, fixture)
        assert lease.snapshot.selected_record_count == 0
        with pytest.raises(PermissionError, match="applicable constraint refuses"):
            evaluate_applicability(fixture, context_for=source)
        second = context_for(digest, "rate")
        assert isinstance(second, RateContextV2) and len(second.intents) == 1


@pytest.mark.parametrize("change", ["target", "class"])
def test_other_target_is_separate_and_false_recorded_class_refuses(
    tmp_path: Path, change: str
) -> None:
    """Other targets do not spend the pair; a class conflicting with its registry refuses."""
    with _selected(tmp_path) as (fixture, part, _digest), _journal(tmp_path) as (_store, lease):
        body = _intent(
            _FIRST,
            part.target_ref
            if change == "class"
            else {"form": "path", "value": str(tmp_path / "other")},
        )
        body.update(
            adapter_operations_digest=fixture.chain.effect_operations.operations_digest,
            operation_key=part.operation_id,
        )
        cast(list[dict[str, object]], body["parts"])[0]["operation_variant"] = (
            part.operation_variant
        )
        if change == "class":
            cast(list[dict[str, object]], body["parts"])[0]["effect_class"] = "read"
        lease.append_from_host(
            kind="operation-intent", body=body, host_time=_NOW.isoformat().replace("+00:00", "Z")
        )
        if change == "class":
            with pytest.raises(PermissionError, match="context is unavailable"):
                evaluate_applicability(fixture, context_for=_source(lease, fixture))
        else:
            result = evaluate_applicability(fixture, context_for=_source(lease, fixture))
            assert result.guard_admissible is False
            assert result.results[0].to_dict()["constraint_results"]


def test_closed_operation_still_counts_its_original_intent(tmp_path: Path) -> None:
    """An independently selected complete closure cannot erase historical rate consumption."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (store, lease):
        _append(lease, part, fixture)
        stamp = _NOW.isoformat().replace("+00:00", "Z")
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
            host_time=stamp,
        )
        lease.append_from_host(
            kind="effect-complete",
            body={"permit_id": _FIRST, "part_index": 0, "post_state_digest": _DIGEST},
            host_time=stamp,
        )
        closure = lease.append_from_host(
            kind="operation-complete",
            body={"permit_id": _FIRST, "parts_result_digest": _DIGEST},
            host_time=stamp,
        )
    with store.locked(selected_head_digest=closure.record_head, max_bytes=1000000) as current:
        source = replace(
            _source(current, fixture), honoured_closure_digests=frozenset({closure.record_digest})
        )
        ctx = source.for_part(fixture.semantics, part)(digest, "rate")
        assert isinstance(ctx, RateContextV2) and len(ctx.intents) == 1
        assert evaluate_rate_v2(ctx, _PARAMS).reason == "rate-limit"


def test_new_journal_and_first_record_do_not_prove_window_coverage(tmp_path: Path) -> None:
    """A recent independent history origin refuses even an empty verified journal."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        source = replace(_source(lease, fixture), history_started_at=_NOW - timedelta(seconds=59))
        ctx = source.for_part(fixture.semantics, part)(digest, "rate")
        assert isinstance(ctx, RateContextV2) and not ctx.window_start_reached
        with pytest.raises(PermissionError, match="applicable constraint refuses"):
            evaluate_applicability(fixture, context_for=source)


@pytest.mark.parametrize(
    "case", ["naive-clock", "offset-clock", "naive-origin", "before-origin", "future-record"]
)
def test_unusable_clock_and_history_times_refuse_actual_reader(tmp_path: Path, case: str) -> None:
    """Invalid host UTC and records outside the independent history boundary cannot pass."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        source = _source(lease, fixture)
        if case == "naive-clock":
            source = replace(source, clock=lambda: _NOW.replace(tzinfo=None))
        elif case == "offset-clock":
            source = replace(source, clock=lambda: _NOW.astimezone(timezone(timedelta(hours=1))))
        elif case == "naive-origin":
            source = replace(source, history_started_at=_NOW.replace(tzinfo=None))
        elif case == "before-origin":
            _append(lease, part, fixture)
            source = replace(source, history_started_at=_NOW + timedelta(seconds=1))
        else:
            _append(lease, part, fixture, age=-1)
        with pytest.raises(PermissionError, match=r"not UTC|outside retained history"):
            source.for_part(fixture.semantics, part)(digest, "rate")


def test_unbound_or_different_selected_clause_refuses_and_other_subject_delegates(
    tmp_path: Path,
) -> None:
    """The callable requires actual part binding and never accepts an arbitrary rate clause."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        source = _source(lease, fixture)
        with pytest.raises(PermissionError, match="extracted part"):
            source(digest, "rate")
        assert isinstance(source(digest, "window"), WindowContextV2)
        bound = source.for_part(fixture.semantics, part)
        assert isinstance(bound(digest, "window"), WindowContextV2)
        with pytest.raises(PermissionError, match="clause differs"):
            bound("b" * 64, "rate")
        with pytest.raises(PermissionError, match="clause differs"):
            source.for_part(fixture.semantics, replace(part, effect_class="read"))(digest, "rate")


@pytest.mark.parametrize("seconds", [True, 0, 604801])
def test_forged_in_memory_rate_window_cannot_select_a_journal_read(
    tmp_path: Path, seconds: object
) -> None:
    """The public reader refuses invalid windows in an unverified in-memory semantics carrier."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        selected = fixture.semantics
        body = selected.signed.body.to_dict()
        entries = cast(list[dict[str, object]], body["entries"])
        entry = next(entry for entry in entries if entry["subject"] == "rate")
        cast(dict[str, object], entry["params"])["window_seconds"] = seconds
        forged = replace(
            selected,
            signed=replace(
                selected.signed,
                body=ClauseSemanticsSetV2(
                    canonical_journal_json_v2(body), selected.signed.body.body_digest
                ),
            ),
        )
        with pytest.raises(PermissionError, match="window is invalid"):
            _source(lease, fixture).for_part(forged, part)(digest, "rate")


def test_invalid_operation_history_and_missing_actual_journal_refuse(tmp_path: Path) -> None:
    """Complete semantic replay and actual descriptors are required before rate can pass."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        _append(lease, part, fixture)
        duplicate = _intent(_SECOND, part.target_ref)
        lease.append_from_host(
            kind="operation-intent",
            body=duplicate,
            host_time=_NOW.isoformat().replace("+00:00", "Z"),
        )
        with pytest.raises(PermissionError, match="targets overlap"):
            _source(lease, fixture).for_part(fixture.semantics, part)(digest, "rate")
        closed_source = _source(lease, fixture)
    with pytest.raises(OSError):
        closed_source.for_part(fixture.semantics, part)(digest, "rate")


def test_same_length_changed_bytes_refuse_without_repair(tmp_path: Path) -> None:
    """A lock-ignoring same-size write is detected by the actual retained descriptor rescan."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (store, lease):
        _append(lease, part, fixture)
        original = store.path.read_bytes()
        changed = original[:-1] + bytes([original[-1] ^ 1])
        with store.path.open("r+b") as writer:
            writer.write(changed)
            writer.flush()
            os.fsync(writer.fileno())
        with pytest.raises(PermissionError, match="record head differs"):
            _source(lease, fixture).for_part(fixture.semantics, part)(digest, "rate")
        assert store.path.read_bytes() == changed


@pytest.mark.parametrize(
    "case",
    [
        "missing-catalogue",
        "operation",
        "atomicity",
        "part-count",
        "target-form",
        "variant",
        "catalogue-carrier",
    ],
)
def test_actual_intent_must_match_its_complete_original_catalogue(
    tmp_path: Path, case: str
) -> None:
    """Even out-of-window intent metadata cannot replace the original operation declaration."""
    with _selected(tmp_path) as (fixture, part, digest), _journal(tmp_path) as (_store, lease):
        body = _intent(_FIRST, part.target_ref)
        body.update(
            adapter_operations_digest=fixture.chain.effect_operations.operations_digest,
            operation_key=part.operation_id,
        )
        parts = cast(list[dict[str, object]], body["parts"])
        parts[0]["operation_variant"] = part.operation_variant
        source = _source(lease, fixture)
        if case == "missing-catalogue":
            body["adapter_operations_digest"] = "b" * 64
        elif case == "operation":
            body["operation_key"] = "unregistered-operation"
        elif case == "atomicity":
            body["atomicity"] = "partial-allowed"
        elif case == "part-count":
            parts.append(
                {
                    **parts[0],
                    "index": 1,
                    "target_ref": {"form": "path", "value": str(tmp_path / "other")},
                }
            )
        elif case == "target-form":
            parts[0]["target_ref"] = {"form": "remote", "value": "https://example.com/data"}
        elif case == "variant":
            parts[0]["operation_variant"] = "default"
        else:
            chain = fixture.chain
            forged = replace(
                chain,
                effect_operations=replace(chain.effect_operations, operations_digest="b" * 64),
            )
            source = replace(source, catalogue_for=lambda _digest: forged)
        lease.append_from_host(
            kind="operation-intent",
            body=body,
            host_time=(_NOW - timedelta(seconds=61)).isoformat().replace("+00:00", "Z"),
        )
        with pytest.raises(PermissionError, match=r"catalogue|original operation"):
            source.for_part(fixture.semantics, part)(digest, "rate")
