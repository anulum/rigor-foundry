# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-held native source verification tests
"""Exercise selected, revoked and changed source state under one lease."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_native_source_pin import _pin

from rigor_foundry.native_source_host import HostNativeSourceState, HostNativeSourceVerifier
from rigor_foundry.native_source_pin import NativeSourcePin


def _captures(kwargs: dict[str, object]) -> dict[str, bytes]:
    question = kwargs["question_capture"]
    reply = kwargs["reply_capture"]
    assert isinstance(question, bytes)
    assert isinstance(reply, bytes)
    return {"question_capture": question, "reply_capture": reply}


def test_host_holds_selection_through_native_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Source bytes are checked while the host-selected snapshot is held."""
    pin, kwargs, _ = _pin(tmp_path)
    active = False
    entered = 0
    original = NativeSourcePin.verify_with_host_pin

    def checked_read(
        self: NativeSourcePin,
        *,
        expected_pin_digest: str,
        question_capture: bytes,
        reply_capture: bytes,
    ) -> dict[str, object]:
        assert active
        return original(
            self,
            expected_pin_digest=expected_pin_digest,
            question_capture=question_capture,
            reply_capture=reply_capture,
        )

    monkeypatch.setattr(NativeSourcePin, "verify_with_host_pin", checked_read)

    @contextmanager
    def state() -> Iterator[HostNativeSourceState]:
        nonlocal active, entered
        entered += 1
        active = True
        try:
            yield HostNativeSourceState(pin, pin.pin_digest, frozenset())
        finally:
            active = False

    verifier = HostNativeSourceVerifier(state)
    result = verifier.verify(**_captures(kwargs))
    assert result["assertion_class"] == "host-pinned-native-integrity-only"
    assert result["promotable"] is False
    assert entered == 1
    assert not active


@pytest.mark.parametrize(
    "fault",
    [
        "revoked",
        "different-selection",
        "changed-pin",
        "bad-anchor",
        "unavailable-state",
        "changed-question",
        "changed-file",
    ],
)
def test_untrusted_or_changed_state_refuses(tmp_path: Path, fault: str) -> None:
    """Fail closed before or during one host-held source verification."""
    pin, kwargs, path = _pin(tmp_path)
    expected = pin.pin_digest
    revoked: frozenset[str] = frozenset()
    selected = pin
    captures = _captures(kwargs)
    if fault == "revoked":
        revoked = frozenset({expected})
    elif fault == "different-selection":
        expected = "0" * 64
    elif fault == "changed-pin":
        selected = replace(pin, source_id="another-source")
    elif fault == "bad-anchor":
        expected = "invalid"
    elif fault == "changed-question":
        captures["question_capture"] = b"Another question.\n"
    elif fault == "changed-file":
        path.write_bytes(path.read_bytes() + b"{}\n")

    @contextmanager
    def state() -> Iterator[HostNativeSourceState]:
        if fault == "unavailable-state":
            yield cast(HostNativeSourceState, None)
        else:
            yield HostNativeSourceState(selected, expected, revoked)

    verifier = HostNativeSourceVerifier(state)
    with pytest.raises((ValueError, PermissionError)):
        verifier.verify(**captures)


def test_each_call_reacquires_current_revocation(tmp_path: Path) -> None:
    """A prior valid read cannot outlive host revocation on a later call."""
    pin, kwargs, _ = _pin(tmp_path)
    revoked = False
    calls = 0

    @contextmanager
    def state() -> Iterator[HostNativeSourceState]:
        nonlocal calls
        calls += 1
        yield HostNativeSourceState(
            pin,
            pin.pin_digest,
            frozenset({pin.pin_digest}) if revoked else frozenset(),
        )

    verifier = HostNativeSourceVerifier(state)
    assert verifier.verify(**_captures(kwargs))["promotable"] is False
    revoked = True
    with pytest.raises(PermissionError):
        verifier.verify(**_captures(kwargs))
    assert calls == 2


def test_host_cannot_suppress_native_source_failure(tmp_path: Path) -> None:
    """A swallowed native mismatch remains a refusal at the verifier boundary."""
    pin, kwargs, _ = _pin(tmp_path)
    captures = _captures(kwargs)
    captures["question_capture"] = b"wrong question\n"

    @contextmanager
    def suppressing_state() -> Iterator[HostNativeSourceState]:
        with suppress(ValueError):
            yield HostNativeSourceState(pin, pin.pin_digest, frozenset())

    with pytest.raises(PermissionError, match="suppressed verification failure"):
        HostNativeSourceVerifier(suppressing_state).verify(**captures)
