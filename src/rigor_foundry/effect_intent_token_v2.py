# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — journal-issued effect intent mistake guard
"""Check process-local journal issuance before the first operation's mutations.

This is a mistake guard over pinned code, not an adversarial capability or a
cross-process receipt. Journal custody and selected handler ownership remain
the responsibility of the protected transaction owner.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final, Literal, cast
from weakref import WeakKeyDictionary

from .effect_journal_records_v2 import EffectJournalRecordV2, _uuid, parse_effect_journal_frame_v2
from .model_primitives import require_digest


@dataclass(frozen=True)
class EffectIntentBindingV2:
    """The current handler's exact permit, part and durable intent digest.

    Attributes
    ----------
    permit_id : str
        Canonical UUID naming the current operation's permit.
    part_index : int
        Nonnegative extracted part index; booleans refuse.
    effect_intent_record_digest : str
        Exact lowercase SHA-256 of the durable intent record.

    Raises
    ------
    ValueError
        Construction receives a malformed UUID, index or digest.

    Notes
    -----
    A valid binding supplies no token issuance or journal custody.
    """

    permit_id: str
    part_index: int
    effect_intent_record_digest: str

    def __post_init__(self) -> None:
        """Reject malformed identifiers without selecting policy or authority."""
        _uuid(self.permit_id, "effect intent permit")
        if type(self.part_index) is not int or self.part_index < 0:
            raise ValueError("effect intent part must be a nonnegative integer")
        require_digest(self.effect_intent_record_digest, "effect intent record")


class EffectIntentTokenV2:
    """Opaque process-local identity issued after the journal's successful intent fsync.

    Attributes
    ----------
    binding : EffectIntentBindingV2
        Registered immutable binding, available even after mutation invalidation.

    Raises
    ------
    PermissionError
        Direct construction or copying attempts to replace actual journal issuance.

    Notes
    -----
    Obtain this identity from ``EffectJournalLeaseV2.append_effect_intent_from_host``.
    Fork inheritance, receipt bytes and a matching binding do not issue a token
    in another process. Protected journal and handler custody remain separate.
    """

    __slots__ = ("__weakref__",)

    def __new__(cls) -> EffectIntentTokenV2:
        """Refuse construction; journal issuance registers a separate opaque identity."""
        raise PermissionError("effect intent token requires journal issuance")

    @property
    def binding(self) -> EffectIntentBindingV2:
        """Return the registered intent binding, including after invalidation.

        Returns
        -------
        EffectIntentBindingV2
            Original immutable permit, part and durable record digest.

        Raises
        ------
        PermissionError
            This identity was not issued in the current process.
        """
        return _registered(self).binding

    def require_current(self, current: EffectIntentBindingV2, *, unlink: bool = False) -> None:
        """Refuse an unissued, foreign, inherited or invalidated token before I/O.

        Parameters
        ----------
        current : EffectIntentBindingV2
            Exact current handler binding, retained by its operation owner.
        unlink : bool
            Allow only temporary unlink after failure preparation, before outcome.

        Returns
        -------
        None
            The token permits this local phase check; no I/O is performed.

        Raises
        ------
        PermissionError
            Issuance is absent, inherited, bound to another part or invalidated
            for the requested phase.

        Notes
        -----
        The protected operation owner repeats this check before actual mutation.
        It is a pinned-code mistake guard, not an adversarial capability.
        """
        state = _registered(self)
        if type(current) is not EffectIntentBindingV2 or state.binding != current:
            raise PermissionError("effect intent token differs from current handler part")
        if state.phase == "closed" or (state.phase == "failure-prepared" and not unlink):
            raise PermissionError("effect intent token is invalidated for this mutation")


@dataclass
class _Issued:
    """Registered identity and monotone local mutation lifetime."""

    binding: EffectIntentBindingV2
    journal_identity: tuple[int, int]
    process_id: int
    frame: bytes
    previous_head: str
    seq: int
    phase: Literal["active", "failure-prepared", "closed"] = "active"


_ISSUED: Final[WeakKeyDictionary[EffectIntentTokenV2, _Issued]] = WeakKeyDictionary()


def _registered(token: EffectIntentTokenV2) -> _Issued:
    """Require actual identity issuance in the current process."""
    if type(token) is not EffectIntentTokenV2:
        raise PermissionError("effect intent token was not issued by the journal")
    state = _ISSUED.get(token)
    if state is None or state.process_id != os.getpid():
        raise PermissionError("effect intent token was not issued in this process")
    return state


def _issue_effect_intent_token_v2(
    record: EffectJournalRecordV2, journal_identity: tuple[int, int]
) -> EffectIntentTokenV2:
    """Register the frame returned by the journal after its actual successful fsync."""
    permit = cast(str, record.body["permit_id"])
    part = cast(int, record.body["part_index"])
    binding = EffectIntentBindingV2(permit, part, record.record_digest)
    token = object.__new__(EffectIntentTokenV2)
    _ISSUED[token] = _Issued(
        binding, journal_identity, os.getpid(), record.frame, record.previous_head, record.seq
    )
    return token


def _prepare_effect_failure_v2(
    token: EffectIntentTokenV2,
    current: EffectIntentBindingV2,
    journal_identity: tuple[int, int],
) -> None:
    """Permit temporary unlink alone while the same journal prepares failure."""
    EffectIntentTokenV2.require_current(token, current)
    state = _registered(token)
    if state.journal_identity != journal_identity:
        raise PermissionError("effect intent token belongs to another journal")
    state.phase = "failure-prepared"


def _close_effect_intent_tokens_v2(
    record: EffectJournalRecordV2, journal_identity: tuple[int, int]
) -> None:
    """Invalidate matching tokens before an actual outcome append attempt."""
    if record.kind not in ("effect-complete", "effect-failed"):
        return
    for state in _ISSUED.values():
        if (
            state.journal_identity == journal_identity
            and state.binding.permit_id == record.body["permit_id"]
            and state.binding.part_index == record.body["part_index"]
        ):
            state.phase = "closed"


def _export_effect_intent_record_v2(
    token: EffectIntentTokenV2,
    current: EffectIntentBindingV2,
    journal_identity: tuple[int, int],
) -> EffectJournalRecordV2:
    """Return only the actual immutable frame retained at successful journal issuance."""
    EffectIntentTokenV2.require_current(token, current)
    state = _registered(token)
    if state.journal_identity != journal_identity:
        raise PermissionError("effect intent token belongs to another journal")
    return parse_effect_journal_frame_v2(
        state.frame, previous_head=bytes.fromhex(state.previous_head), expected_seq=state.seq
    )
