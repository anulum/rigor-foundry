# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — composed semantic-source host tests
"""Exercise two real file readers under one selected source lease."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_discovery_receipt_host import _host_evidence, _host_verifier
from test_semantic_transition import _HOST_QUESTION, _HOST_REPLY, _HOST_SOURCE

from rigor_foundry.discovery_receipt_host import HostDiscoveryReceiptState
from rigor_foundry.native_message_pair import NativeMessageSelector, NativeReadLimits
from rigor_foundry.native_source_host import HostNativeSourceState, HostNativeSourceVerifier
from rigor_foundry.native_source_pin import NativeSourcePin
from rigor_foundry.semantic_source_host import (
    HostSemanticSourceSelection,
    HostSemanticSourceState,
    HostSemanticSourceVerifier,
)
from rigor_foundry.semantic_transition import SemanticTransitionProposal

_SESSION = "synthetic-owner-session"
_TIMESTAMP = "2026-09-12T13:12:23Z"


def _line(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _native_verifier(root: Path) -> tuple[HostNativeSourceVerifier, NativeSourcePin, Path]:
    """Create a bounded native session whose selected text equals our captures."""
    question = _line(
        {
            "type": "response_item",
            "timestamp": _TIMESTAMP,
            "payload": {
                "type": "message",
                "role": "assistant",
                "id": "msg_question",
                "content": [{"type": "output_text", "text": _HOST_QUESTION.decode()[:-1]}],
            },
        }
    )
    reply = _line(
        {
            "type": "response_item",
            "timestamp": _TIMESTAMP,
            "payload": {
                "type": "message",
                "role": "user",
                "id": "msg_reply",
                "content": [{"type": "input_text", "text": _HOST_REPLY.decode()[:-1]}],
            },
        }
    )
    payload = b"".join(
        (_line({"type": "session_meta", "payload": {"id": _SESSION}}), question, reply)
    )
    path = root / f"{_SESSION}.jsonl"
    path.write_bytes(payload)
    pin = NativeSourcePin.build(
        source_id="owner-decision-fixture",
        root=root,
        filename=path.name,
        session_id=_SESSION,
        file_digest=sha256(payload).hexdigest(),
        question=NativeMessageSelector.build(
            line_number=2,
            message_id="msg_question",
            timestamp=_TIMESTAMP,
            line_digest=sha256(question).hexdigest(),
            capture_digest=sha256(_HOST_QUESTION).hexdigest(),
        ),
        reply=NativeMessageSelector.build(
            line_number=3,
            message_id="msg_reply",
            timestamp=_TIMESTAMP,
            line_digest=sha256(reply).hexdigest(),
            capture_digest=sha256(_HOST_REPLY).hexdigest(),
        ),
        limits=NativeReadLimits(8192, 4096, 1),
    )

    @contextmanager
    def state() -> Iterator[HostNativeSourceState]:
        yield HostNativeSourceState(pin, pin.pin_digest, frozenset())

    return HostNativeSourceVerifier(state), pin, path


def _fixture(
    root: Path,
) -> tuple[SemanticTransitionProposal, HostSemanticSourceState, Path]:
    proposal, discovery_selection = _host_evidence(root)
    discovery = _host_verifier(
        HostDiscoveryReceiptState(
            discovery_selection, discovery_selection.selection_digest, frozenset()
        )
    )
    native, pin, path = _native_verifier(root)
    selected = HostSemanticSourceSelection.build(
        proposal_digest=proposal.proposal_digest,
        discovery_selection_digest=discovery_selection.selection_digest,
        native_pin_digest=pin.pin_digest,
    )
    state = HostSemanticSourceState(
        selected, selected.selection_digest, frozenset(), discovery, native
    )
    return proposal, state, path


def _verifier(state: HostSemanticSourceState) -> HostSemanticSourceVerifier:
    @contextmanager
    def lease() -> Iterator[HostSemanticSourceState]:
        yield state

    return HostSemanticSourceVerifier(lease)


def _verify(
    verifier: HostSemanticSourceVerifier,
    proposal: SemanticTransitionProposal,
    *,
    source: bytes = _HOST_SOURCE,
    question: bytes = _HOST_QUESTION,
    reply: bytes = _HOST_REPLY,
) -> dict[str, object]:
    return verifier.verify(
        proposal,
        proposal_source=source,
        owner_question=question,
        owner_reply=reply,
    )


def test_composed_host_source_verifies_both_real_readers(tmp_path: Path) -> None:
    """The combined proof binds one selected proposal, replay and native pin."""
    proposal, state, _ = _fixture(tmp_path)
    proof = _verify(_verifier(state), proposal)
    assert proof["proposal_digest"] == proposal.proposal_digest
    assert proof["selection_digest"] == state.selected.selection_digest
    assert proof["assertion_class"] == "selected-semantic-source-integrity-only"
    assert proof["promotable"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "proposal",
        "discovery",
        "native",
        "revoked",
        "missing-discovery",
        "missing-native",
        "state",
    ],
)
def test_crossed_or_revoked_host_selection_refuses(tmp_path: Path, fault: str) -> None:
    """One forged, unavailable or revoked source class cannot supply the other."""
    proposal, state, _ = _fixture(tmp_path)
    if fault == "proposal":
        state = replace(state, selected=replace(state.selected, proposal_digest="0" * 64))
    elif fault == "discovery":
        state = replace(
            state, selected=replace(state.selected, discovery_selection_digest="0" * 64)
        )
    elif fault == "native":
        state = replace(state, selected=replace(state.selected, native_pin_digest="0" * 64))
    elif fault == "revoked":
        state = replace(
            state, revoked_selection_digests=frozenset({state.selected.selection_digest})
        )
    elif fault == "missing-discovery":
        state = replace(state, discovery_verifier=cast(object, None))
    elif fault == "missing-native":
        state = replace(state, native_verifier=cast(object, None))
    else:
        state = cast(HostSemanticSourceState, object())
    with pytest.raises((PermissionError, ValueError)):
        _verify(_verifier(state), proposal)


def test_native_drift_or_changed_capture_refuses(tmp_path: Path) -> None:
    """A correct discovery receipt cannot borrow a changed native session."""
    proposal, state, path = _fixture(tmp_path)
    with pytest.raises((PermissionError, ValueError)):
        _verify(_verifier(state), proposal, question=b"different question\n")
    path.write_bytes(path.read_bytes() + b"{}\n")
    with pytest.raises((PermissionError, ValueError)):
        _verify(_verifier(state), proposal)


@pytest.mark.parametrize("source_class", ["discovery", "native"])
def test_valid_but_crossed_source_selection_refuses(tmp_path: Path, source_class: str) -> None:
    """Even a well-formed host selection cannot borrow the other proof class."""
    proposal, state, _ = _fixture(tmp_path)
    selected = HostSemanticSourceSelection.build(
        proposal_digest=state.selected.proposal_digest,
        discovery_selection_digest=(
            "0" * 64 if source_class == "discovery" else state.selected.discovery_selection_digest
        ),
        native_pin_digest=(
            "0" * 64 if source_class == "native" else state.selected.native_pin_digest
        ),
    )
    crossed = replace(
        state, selected=selected, expected_selection_digest=selected.selection_digest
    )
    with pytest.raises(ValueError, match="proofs do not match"):
        _verify(_verifier(crossed), proposal)


def test_host_cannot_suppress_composed_failure(tmp_path: Path) -> None:
    """A swallowed nested read failure cannot become a source proof."""
    proposal, state, path = _fixture(tmp_path)
    path.write_bytes(path.read_bytes() + b"{}\n")

    @contextmanager
    def suppressing_state() -> Iterator[HostSemanticSourceState]:
        with suppress(ValueError):
            yield state

    with pytest.raises(PermissionError, match="suppressed verification failure"):
        _verify(HostSemanticSourceVerifier(suppressing_state), proposal)
