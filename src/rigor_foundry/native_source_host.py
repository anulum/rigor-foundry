# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-held native source verification
"""Acquire selected native-source state from a trusted host-held lease."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from .model_primitives import require_digest
from .native_source_pin import NativeSourcePin


@dataclass(frozen=True)
class HostNativeSourceState:
    """Host-selected pin and revocation snapshot, never request parameters.

    Only trusted host composition may provide this state. A caller supplying
    its own state provider or trust anchor can authorize its own source and
    must not be treated as a production admission boundary.
    """

    selected_pin: NativeSourcePin
    expected_pin_digest: str
    revoked_pin_digests: frozenset[str]


@dataclass(frozen=True)
class HostNativeSourceVerifier:
    """Verify within a current host-held state lease without accepting pins.

    The provider must hold a consistent selection and revocation snapshot
    through the full native-file read. This class does not make the source a
    semantic owner grant, select a rule profile or authorize effects.
    """

    state: Callable[[], AbstractContextManager[HostNativeSourceState]]

    def verify(self, *, question_capture: bytes, reply_capture: bytes) -> dict[str, object]:
        """Return integrity evidence only for the currently selected source."""
        proof: dict[str, object] | None = None
        with self.state() as current:
            if not isinstance(current, HostNativeSourceState):
                raise PermissionError("native source host state is unavailable")
            expected = require_digest(
                current.expected_pin_digest, "native source host.expected_pin_digest"
            )
            if expected in current.revoked_pin_digests:
                raise PermissionError("native source host pin is revoked")
            pin = NativeSourcePin.from_dict(current.selected_pin.to_dict())
            if pin != current.selected_pin or pin.pin_digest != expected:
                raise PermissionError("native source host selection differs")
            proof = pin.verify_with_host_pin(
                expected_pin_digest=expected,
                question_capture=question_capture,
                reply_capture=reply_capture,
            )
        if proof is None:
            raise PermissionError("native source host state suppressed verification failure")
        return proof
