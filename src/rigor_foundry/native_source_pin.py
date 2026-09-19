# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected native source pin
"""Bind a native message proof to an independently selected host source pin."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .audit_primitives import require_exact_fields, require_integer
from .discovery_source_schema import capture_name
from .model_primitives import require_digest, require_identifier
from .models import canonical_digest, require_mapping, require_string
from .native_message_pair import (
    NativeMessageSelector,
    NativeReadLimits,
    verify_native_message_pair,
)

NATIVE_SOURCE_PIN_SCHEMA: Final = "native-source-pin.v1"
NATIVE_SOURCE_VERIFICATION_SCHEMA: Final = "native-source-verification.v1"
_PIN_FIELDS: Final = frozenset(
    {
        "schema_version",
        "source_id",
        "root",
        "filename",
        "session_id",
        "file_digest",
        "question",
        "reply",
        "total_bytes",
        "line_bytes",
        "intervening_lines",
        "pin_digest",
    }
)
_SELECTOR_FIELDS: Final = frozenset(
    {"line_number", "message_id", "timestamp", "line_digest", "capture_digest"}
)


def _selector(value: object) -> NativeMessageSelector:
    """Parse exactly one immutable native line selector."""
    data = require_mapping(value, "native source selector")
    require_exact_fields(data, _SELECTOR_FIELDS, "native source selector")
    return NativeMessageSelector.build(
        line_number=require_integer(data.get("line_number"), "selector.line_number", minimum=1),
        message_id=require_identifier(data.get("message_id"), "selector.message_id"),
        timestamp=require_string(data.get("timestamp"), "selector.timestamp"),
        line_digest=require_digest(data.get("line_digest"), "selector.line_digest"),
        capture_digest=require_digest(data.get("capture_digest"), "selector.capture_digest"),
    )


@dataclass(frozen=True)
class NativeSourcePin:
    """Exact source selection; trusted only when its digest is host-pinned."""

    source_id: str
    root: Path
    filename: str
    session_id: str
    file_digest: str
    question: NativeMessageSelector
    reply: NativeMessageSelector
    limits: NativeReadLimits
    pin_digest: str

    @classmethod
    def build(
        cls,
        *,
        source_id: str,
        root: Path,
        filename: str,
        session_id: str,
        file_digest: str,
        question: NativeMessageSelector,
        reply: NativeMessageSelector,
        limits: NativeReadLimits,
    ) -> NativeSourcePin:
        """Construct an integrity-bound pin without choosing host authority."""
        if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
            raise ValueError("native source root must be an absolute untraversed path")
        name = capture_name(filename)
        session = require_identifier(session_id, "native source.session_id")
        if not name.endswith(".jsonl") or session not in name:
            raise ValueError("native filename does not bind session")
        first = _selector(question.to_dict())
        second = _selector(reply.to_dict())
        if first.line_number <= 1 or second.line_number <= first.line_number:
            raise ValueError("native source message order is invalid")
        gap = second.line_number - first.line_number - 1
        if gap > limits.intervening_lines:
            raise ValueError("native source message gap exceeds limit")
        body: dict[str, object] = {
            "schema_version": NATIVE_SOURCE_PIN_SCHEMA,
            "source_id": require_identifier(source_id, "native source.source_id"),
            "root": str(root),
            "filename": name,
            "session_id": session,
            "file_digest": require_digest(file_digest, "native source.file_digest"),
            "question": first.to_dict(),
            "reply": second.to_dict(),
            "total_bytes": limits.total_bytes,
            "line_bytes": limits.line_bytes,
            "intervening_lines": limits.intervening_lines,
        }
        return cls(
            source_id=str(body["source_id"]),
            root=root,
            filename=name,
            session_id=session,
            file_digest=str(body["file_digest"]),
            question=first,
            reply=second,
            limits=limits,
            pin_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the full source pin; no implicit trusted state is encoded."""
        return {
            "schema_version": NATIVE_SOURCE_PIN_SCHEMA,
            "source_id": self.source_id,
            "root": str(self.root),
            "filename": self.filename,
            "session_id": self.session_id,
            "file_digest": self.file_digest,
            "question": self.question.to_dict(),
            "reply": self.reply.to_dict(),
            "total_bytes": self.limits.total_bytes,
            "line_bytes": self.limits.line_bytes,
            "intervening_lines": self.limits.intervening_lines,
            "pin_digest": self.pin_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> NativeSourcePin:
        """Reject field injection, malformed bounds and recomputed pin aliases."""
        data = require_mapping(value, "native source pin")
        require_exact_fields(data, _PIN_FIELDS, "native source pin")
        if data.get("schema_version") != NATIVE_SOURCE_PIN_SCHEMA:
            raise ValueError("unsupported native source pin schema")
        root_text = require_string(data.get("root"), "native source.root")
        root = Path(root_text)
        if str(root) != root_text:
            raise ValueError("native source root is not in canonical path spelling")
        pin = cls.build(
            source_id=require_identifier(data.get("source_id"), "native source.source_id"),
            root=root,
            filename=require_string(data.get("filename"), "native source.filename"),
            session_id=require_identifier(data.get("session_id"), "native source.session_id"),
            file_digest=require_digest(data.get("file_digest"), "native source.file_digest"),
            question=_selector(data.get("question")),
            reply=_selector(data.get("reply")),
            limits=NativeReadLimits(
                total_bytes=require_integer(
                    data.get("total_bytes"), "native source.total_bytes", minimum=1
                ),
                line_bytes=require_integer(
                    data.get("line_bytes"), "native source.line_bytes", minimum=1
                ),
                intervening_lines=require_integer(
                    data.get("intervening_lines"), "native source.intervening_lines", minimum=1
                ),
            ),
        )
        if require_digest(data.get("pin_digest"), "native source.pin_digest") != pin.pin_digest:
            raise ValueError("native source pin digest differs")
        return pin

    def verify_with_host_pin(
        self,
        *,
        expected_pin_digest: str,
        question_capture: bytes,
        reply_capture: bytes,
    ) -> dict[str, object]:
        """Verify exact native bytes only against a host-authenticated pin.

        The caller must obtain ``expected_pin_digest`` from independent trusted
        host configuration. Supplying a self-chosen digest proves no authority.
        Even a matched result is a source dependency, never semantic acceptance
        or an effect grant.
        """
        pin = NativeSourcePin.from_dict(self.to_dict())
        if pin != self or pin.pin_digest != require_digest(
            expected_pin_digest, "native source.expected_pin_digest"
        ):
            raise ValueError("native source is not the selected host pin")
        native = verify_native_message_pair(
            root=pin.root,
            filename=pin.filename,
            session_id=pin.session_id,
            question=pin.question,
            reply=pin.reply,
            question_capture=question_capture,
            reply_capture=reply_capture,
            limits=pin.limits,
        )
        if native["file_digest"] != pin.file_digest:
            raise ValueError("native file digest is not the host-pinned file")
        body: dict[str, object] = {
            "schema_version": NATIVE_SOURCE_VERIFICATION_SCHEMA,
            "assertion_class": "host-pinned-native-integrity-only",
            "promotable": False,
            "source_id": pin.source_id,
            "pin_digest": pin.pin_digest,
            "native_verification_digest": native["verification_digest"],
            "file_digest": pin.file_digest,
            "question_capture_digest": pin.question.capture_digest,
            "reply_capture_digest": pin.reply.capture_digest,
        }
        return {**body, "source_verification_digest": canonical_digest(body)}
