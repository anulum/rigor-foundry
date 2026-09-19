# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded native message pair verification
"""Verify exact retained owner-message text against one stable native JSONL."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal

from .discovery_source_schema import capture_name, parse_json
from .git_inventory import open_directory_no_follow
from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .models import canonical_digest, require_mapping, require_string

NATIVE_PAIR_SCHEMA: Final = "native-message-pair-verification.v1"
MessageRole = Literal["assistant", "user"]


@dataclass(frozen=True)
class NativeReadLimits:
    """Explicit positive byte and intervening-line budgets for one native read."""

    total_bytes: int
    line_bytes: int
    intervening_lines: int

    def __post_init__(self) -> None:
        """Refuse boolean, zero and implausibly large resource budgets."""
        for value in (self.total_bytes, self.line_bytes, self.intervening_lines):
            if type(value) is not int or not 0 < value <= 2**31 - 1:
                raise ValueError("invalid native read limit")
        if self.line_bytes > self.total_bytes:
            raise ValueError("native line limit exceeds total limit")


@dataclass(frozen=True)
class NativeMessageSelector:
    """Host-pinned identity and digests for one exact native response item."""

    line_number: int
    message_id: str
    timestamp: str
    line_digest: str
    capture_digest: str

    @classmethod
    def build(
        cls,
        *,
        line_number: int,
        message_id: str,
        timestamp: str,
        line_digest: str,
        capture_digest: str,
    ) -> NativeMessageSelector:
        """Validate an exact source-line selector without reading the transcript."""
        if type(line_number) is not int or not 0 < line_number <= 2**31 - 1:
            raise ValueError("native message line number is invalid")
        return cls(
            line_number=line_number,
            message_id=require_identifier(message_id, "native.message_id"),
            timestamp=require_utc_timestamp(timestamp, "native.timestamp"),
            line_digest=require_digest(line_digest, "native.line_digest"),
            capture_digest=require_digest(capture_digest, "native.capture_digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the exact native selector without source text."""
        return {
            "line_number": self.line_number,
            "message_id": self.message_id,
            "timestamp": self.timestamp,
            "line_digest": self.line_digest,
            "capture_digest": self.capture_digest,
        }


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Retain the metadata fields that must not change during a source read."""
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _message(
    raw: bytes,
    *,
    selector: NativeMessageSelector,
    role: MessageRole,
    capture: bytes,
) -> None:
    """Check one source line and extracted text against host-pinned bytes."""
    if sha256(raw).hexdigest() != selector.line_digest:
        raise ValueError("native message line digest differs")
    event = require_mapping(parse_json(raw), "native message event")
    payload = require_mapping(event.get("payload"), "native message payload")
    content = payload.get("content")
    if (
        event.get("type") != "response_item"
        or payload.get("type") != "message"
        or payload.get("role") != role
        or payload.get("id") != selector.message_id
        or require_utc_timestamp(event.get("timestamp"), "native.timestamp") != selector.timestamp
        or not isinstance(content, list)
        or len(content) != 1
    ):
        raise ValueError("native message identity differs")
    part = require_mapping(content[0], "native message content")
    expected_type = "output_text" if role == "assistant" else "input_text"
    message_text = require_string(part.get("text"), "native message text")
    if part.get("type") != expected_type or message_text.encode("utf-8") + b"\n" != capture:
        raise ValueError("native message text differs from retained capture")
    if sha256(capture).hexdigest() != selector.capture_digest:
        raise ValueError("native message capture digest differs")


def _session(raw: bytes, expected_session_id: str) -> None:
    """Bind the file's first native record to the selected session identity."""
    event = require_mapping(parse_json(raw), "native session event")
    payload = require_mapping(event.get("payload"), "native session payload")
    if event.get("type") != "session_meta" or payload.get("id") != expected_session_id:
        raise ValueError("native session identity differs")


def verify_native_message_pair(
    *,
    root: Path,
    filename: str,
    session_id: str,
    question: NativeMessageSelector,
    reply: NativeMessageSelector,
    question_capture: bytes,
    reply_capture: bytes,
    limits: NativeReadLimits,
) -> dict[str, object]:
    """Hash a stable no-follow JSONL and verify one adjacent owner decision.

    Only selected lines and intervening response roles are parsed. The whole
    file is hashed in one bounded streaming pass; no transcript is copied,
    archived, logged or rewritten. A successful receipt proves captured byte
    identity and native-file adjacency, not owner identity beyond the pinned
    session, semantic entailment, source authority or a Guard grant.
    """
    name = capture_name(filename)
    session = require_identifier(session_id, "native.session_id")
    if session not in name or not name.endswith(".jsonl"):
        raise ValueError("native filename does not bind selected session")
    first = NativeMessageSelector.build(
        line_number=question.line_number,
        message_id=question.message_id,
        timestamp=question.timestamp,
        line_digest=question.line_digest,
        capture_digest=question.capture_digest,
    )
    second = NativeMessageSelector.build(
        line_number=reply.line_number,
        message_id=reply.message_id,
        timestamp=reply.timestamp,
        line_digest=reply.line_digest,
        capture_digest=reply.capture_digest,
    )
    if (
        first.line_number <= 1
        or second.line_number <= first.line_number
        or second.line_number - first.line_number - 1 > limits.intervening_lines
    ):
        raise ValueError("native message order or gap is invalid")
    if not isinstance(question_capture, bytes) or not isinstance(reply_capture, bytes):
        raise ValueError("native captures must be bytes")
    if len(question_capture) > limits.line_bytes or len(reply_capture) > limits.line_bytes:
        raise ValueError("native capture exceeds line limit")
    parent = open_directory_no_follow(root)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, dir_fd=parent)
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _file_identity(before) != _file_identity(path_before)
            or before.st_size > limits.total_bytes
        ):
            raise ValueError("native source is not a bounded stable regular file")
        digest = sha256()
        byte_count = 0
        found: set[int] = set()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for line_number, line in enumerate(
                iter(lambda: stream.readline(limits.line_bytes + 1), b""), start=1
            ):
                if len(line) > limits.line_bytes or not line.endswith(b"\n"):
                    raise ValueError("native JSONL line exceeds limit or lacks LF")
                byte_count += len(line)
                if byte_count > limits.total_bytes:
                    raise ValueError("native transcript exceeds byte limit")
                digest.update(line)
                if line_number == 1:
                    _session(line, session)
                elif line_number == first.line_number:
                    _message(line, selector=first, role="assistant", capture=question_capture)
                    found.add(line_number)
                elif line_number == second.line_number:
                    _message(line, selector=second, role="user", capture=reply_capture)
                    found.add(line_number)
                elif first.line_number < line_number < second.line_number:
                    event = require_mapping(parse_json(line), "native intervening event")
                    if event.get("type") == "response_item":
                        payload = require_mapping(event.get("payload"), "native intervening item")
                        if payload.get("role") in {"assistant", "user"}:
                            raise ValueError("another native message intervenes")
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            found != {first.line_number, second.line_number}
            or byte_count != before.st_size
            or _file_identity(before) != _file_identity(after)
            or _file_identity(before) != _file_identity(path_after)
        ):
            raise ValueError("native source changed or selected messages are missing")
        body: dict[str, object] = {
            "schema_version": NATIVE_PAIR_SCHEMA,
            "assertion_class": "native-message-integrity-only",
            "promotable": False,
            "session_id": session,
            "file_digest": digest.hexdigest(),
            "file_bytes": byte_count,
            "question": first.to_dict(),
            "reply": second.to_dict(),
        }
        return {**body, "verification_digest": canonical_digest(body)}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
