# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual journal issuance and token lifetime tests
"""Exercise process-local intent tokens through actual owner-only journal files."""

from __future__ import annotations

import os
import sys
from copy import copy, deepcopy
from pathlib import Path
from types import FrameType
from typing import cast
from uuid import uuid4

import pytest

from rigor_foundry.effect_intent_token_v2 import EffectIntentBindingV2, EffectIntentTokenV2
from rigor_foundry.effect_journal_v2 import EffectJournalLeaseV2, EffectJournalStoreV2

_TIME = "2026-10-01T17:45:00Z"


def _store(path: Path) -> tuple[EffectJournalStoreV2, str]:
    """Initialize real cooperative fixture custody, without protected qualification."""
    path.mkdir(mode=0o700)
    store = EffectJournalStoreV2(path / "effect.journal")
    return store, store.initialize()


def _issue(
    lease: EffectJournalLeaseV2, permit: str, part: int = 0
) -> tuple[EffectIntentTokenV2, EffectIntentBindingV2]:
    """Obtain issuance and independently retain its actual journal-frame binding."""
    token = lease.append_effect_intent_from_host(
        body={"permit_id": permit, "part_index": part, "pre_state_digest": None},
        host_time=_TIME,
    )
    binding = EffectIntentBindingV2(permit, part, lease.snapshot.records[-1].record_digest)
    return token, binding


def test_actual_fsync_returns_before_issuance_and_frame_binding_is_immutable(
    tmp_path: Path,
) -> None:
    """A genuine flush precedes the token; mutable record bodies do not change its binding."""
    store, head = _store(tmp_path / "custody")
    permit = str(uuid4())
    observed: list[str] = []

    def observe(frame: FrameType, event: str, arg: object) -> None:
        """Record only actual journal fsync returns without replacing any call."""
        if event == "c_return" and arg is os.fsync:
            observed.append(frame.f_code.co_name)

    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        sys.setprofile(observe)
        try:
            token, binding = _issue(lease, permit)
        finally:
            sys.setprofile(None)
        assert observed == ["append_from_host"]
        record = lease.snapshot.records[-1]
        assert store.path.read_bytes().endswith(record.frame)
        assert token.binding == binding
        token.require_current(binding)
        record.body["permit_id"] = str(uuid4())
        assert token.binding == binding
    token.require_current(binding)
    assert (
        store.snapshot(selected_head_digest=head, max_bytes=100000).records[-1].body["permit_id"]
        == permit
    )


@pytest.mark.parametrize("field", ["permit", "part", "digest"])
def test_actual_issued_token_requires_exact_current_handler_binding(
    tmp_path: Path, field: str
) -> None:
    """Another valid permit, part or intent digest refuses despite genuine issuance."""
    store, head = _store(tmp_path / "custody")
    permit = str(uuid4())
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token, binding = _issue(lease, permit)
    wrong = EffectIntentBindingV2(
        str(uuid4()) if field == "permit" else permit,
        1 if field == "part" else 0,
        "a" * 64 if field == "digest" else binding.effect_intent_record_digest,
    )
    with pytest.raises(PermissionError, match="current handler part"):
        token.require_current(wrong)
    with pytest.raises(PermissionError, match="current handler part"):
        token.require_current(cast(EffectIntentBindingV2, None))


def test_no_public_constructor_or_structural_copy_supplies_journal_issuance(
    tmp_path: Path,
) -> None:
    """Actual opaque identities cannot be reconstructed from a valid binding."""
    with pytest.raises(PermissionError, match="journal issuance"):
        EffectIntentTokenV2()
    store, head = _store(tmp_path / "custody")
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token, binding = _issue(lease, str(uuid4()))
        for copier in (copy, deepcopy):
            with pytest.raises(PermissionError, match="journal issuance"):
                copier(token)
        token.require_current(binding)
    with pytest.raises(PermissionError, match="issued by the journal"):
        EffectIntentTokenV2.require_current(cast(EffectIntentTokenV2, None), binding)


@pytest.mark.parametrize("part", [-1, True])
def test_binding_rejects_invalid_part_index(part: int) -> None:
    """Boolean and negative part indexes never identify the current handler part."""
    with pytest.raises(ValueError, match="nonnegative integer"):
        EffectIntentBindingV2(str(uuid4()), part, "a" * 64)


def test_binding_rejects_invalid_permit_and_digest() -> None:
    """Malformed context identifiers refuse at the public binding constructor."""
    with pytest.raises(ValueError):
        EffectIntentBindingV2("invalid", 0, "a" * 64)
    with pytest.raises(ValueError):
        EffectIntentBindingV2(str(uuid4()), 0, "invalid")


@pytest.mark.parametrize("kind", ["effect-complete", "effect-failed"])
def test_actual_outcome_on_later_lease_invalidates_only_same_journal_part(
    tmp_path: Path, kind: str
) -> None:
    """Outcome invalidation survives lock release and distinguishes other live intents."""
    store, head = _store(tmp_path / "custody")
    other, other_head = _store(tmp_path / "other-custody")
    permit = str(uuid4())
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token, current = _issue(lease, permit)
        part_token, part_binding = _issue(lease, permit, 1)
        foreign_token, foreign_binding = _issue(lease, str(uuid4()))
    with other.locked(selected_head_digest=other_head, max_bytes=100000) as other_lease:
        other_token, other_binding = _issue(other_lease, permit)
    body: dict[str, object] = {"permit_id": permit, "part_index": 0, "post_state_digest": None}
    if kind == "effect-failed":
        body["failure_code"] = "cancelled"
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        lease.append_from_host(kind=kind, body=body, host_time=_TIME)
    for unlink in (False, True):
        with pytest.raises(PermissionError, match="invalidated"):
            token.require_current(current, unlink=unlink)
    assert token.binding == current
    for active, binding in (
        (part_token, part_binding),
        (foreign_token, foreign_binding),
        (other_token, other_binding),
    ):
        active.require_current(binding)


def test_failure_preparation_allows_only_unlink_until_actual_failed_write(tmp_path: Path) -> None:
    """Preparation is monotone and a foreign journal cannot change a token's phase."""
    store, head = _store(tmp_path / "custody")
    other, other_head = _store(tmp_path / "other-custody")
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token, current = _issue(lease, str(uuid4()))
        with (
            other.locked(selected_head_digest=other_head, max_bytes=100000) as other_lease,
            pytest.raises(PermissionError, match="another journal"),
        ):
            other_lease.prepare_effect_failure(token, current=current)
        token.require_current(current)
        lease.prepare_effect_failure(token, current=current)
        token.require_current(current, unlink=True)
        with pytest.raises(PermissionError, match="invalidated"):
            token.require_current(current)
        with pytest.raises(PermissionError, match="invalidated"):
            lease.prepare_effect_failure(token, current=current)
        lease.append_from_host(
            kind="effect-failed",
            body={
                "permit_id": current.permit_id,
                "part_index": 0,
                "post_state_digest": None,
                "failure_code": "cancelled",
            },
            host_time=_TIME,
        )
        with pytest.raises(PermissionError, match="invalidated"):
            token.require_current(current, unlink=True)


def test_journal_budget_refusal_returns_no_token(tmp_path: Path) -> None:
    """Actual selected budget refusal leaves the real journal unchanged."""
    store, head = _store(tmp_path / "custody")
    original = store.path.read_bytes()
    with (
        store.locked(selected_head_digest=head, max_bytes=len(original)) as lease,
        pytest.raises(PermissionError, match="byte budget"),
    ):
        _issue(lease, str(uuid4()))
    assert store.path.read_bytes() == original


def test_inherited_token_is_refused_in_actual_forked_process(tmp_path: Path) -> None:
    """Fork inheritance cannot serve as journal issuance to a handler child."""
    store, head = _store(tmp_path / "custody")
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token, current = _issue(lease, str(uuid4()))
    child = os.fork()
    if child == 0:
        try:
            token.require_current(current)
        except PermissionError:
            os._exit(0)
        os._exit(1)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    token.require_current(current)


@pytest.mark.parametrize("kind", ["effect-intent", "effect-complete"])
def test_real_fsync_descriptor_failure_never_opens_or_restores_barrier(
    tmp_path: Path, kind: str
) -> None:
    """An actual EBADF flush keeps the written tail and mutation authority closed."""
    store, head = _store(tmp_path / "custody")
    permit = str(uuid4())
    issued: EffectIntentTokenV2 | None = None
    current: EffectIntentBindingV2 | None = None
    exceptions: list[str] = []
    with (
        pytest.raises(PermissionError, match="changed during locked operation"),
        store.locked(selected_head_digest=head, max_bytes=100000) as lease,
    ):
        if kind == "effect-complete":
            issued, current = _issue(lease, permit)
        saved = os.dup(lease.descriptor)
        armed = True

        def close_before_flush(frame: FrameType, event: str, arg: object) -> None:
            """Close the real FD once; the unchanged fsync executes and raises EBADF."""
            nonlocal armed
            if frame.f_code.co_name == "append_from_host" and arg is os.fsync:
                if event == "c_call" and armed:
                    armed = False
                    os.close(lease.descriptor)
                elif event == "c_exception":
                    exceptions.append("actual-fsync-exception")

        sys.setprofile(close_before_flush)
        try:
            with pytest.raises(OSError) as error:
                if kind == "effect-intent":
                    issued, current = _issue(lease, permit)
                else:
                    lease.append_from_host(
                        kind=kind,
                        body={"permit_id": permit, "part_index": 0, "post_state_digest": None},
                        host_time=_TIME,
                    )
            assert error.value.errno == 9
        finally:
            sys.setprofile(None)
            os.dup2(saved, lease.descriptor, inheritable=False)
            os.close(saved)
        assert exceptions == ["actual-fsync-exception"]
        if kind == "effect-intent":
            assert issued is None and current is None
        else:
            assert issued is not None and current is not None
            with pytest.raises(PermissionError, match="invalidated"):
                issued.require_current(current)
    snapshot = store.snapshot(selected_head_digest=head, max_bytes=100000)
    assert snapshot.records[-1].kind == kind
    assert store.path.read_bytes().endswith(snapshot.records[-1].frame)
