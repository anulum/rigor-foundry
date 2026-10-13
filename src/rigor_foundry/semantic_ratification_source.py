# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native owner ratification source
"""Verify the exact native full-text question and owner reply as integrity only."""

from __future__ import annotations

import os
import stat
from hashlib import sha256
from pathlib import Path
from typing import Final, TypedDict

from .audit_primitives import require_exact_fields, require_integer
from .discovery_source_schema import parse_json
from .git_inventory import open_directory_no_follow
from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .models import canonical_digest, require_mapping, require_string

RATIFICATION_SOURCE_SCHEMA: Final = "owner-ratification-source-integrity.v1"
_NAMES: Final = ("CEO_QUESTION_FULL_TEXT.txt", "OWNER_REPLY.txt")
_ENTRY_FIELDS: Final = frozenset(
    {
        "jsonl_line",
        "uuid",
        "timestamp",
        "type",
        "text_bytes",
        "text_sha256",
        "native_line_sha256",
    }
)
_MAX_PREFIX: Final = 64 * 1024 * 1024
_MAX_LINE: Final = 2 * 1024 * 1024


class _CaptureEntry(TypedDict):
    """Validated native line and capture selector."""

    jsonl_line: int
    uuid: str
    timestamp: str
    type: str
    text_sha256: str
    native_line_sha256: str


def _identity(value: os.stat_result) -> tuple[int, int, int, int]:
    """Capture stable file identity while allowing later transcript appends."""
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
    )


def _prefix_digest(descriptor: int, length: int) -> str:
    """Re-read exactly the selected prefix from the open descriptor."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = sha256()
    remaining = length
    while remaining:
        part = os.read(descriptor, min(1024 * 1024, remaining))
        if not part:
            raise ValueError("ratification selected prefix disappeared")
        digest.update(part)
        remaining -= len(part)
    return digest.hexdigest()


def _entry(value: object, role: str, capture: bytes) -> _CaptureEntry:
    """Validate one capture selector and its exact LF-terminated bytes."""
    data = require_mapping(value, "ratification capture")
    require_exact_fields(data, _ENTRY_FIELDS, "ratification capture")
    if data.get("type") != role or not isinstance(capture, bytes):
        raise ValueError("ratification capture type differs")
    if not 0 < len(capture) <= 16 * 1024 or not capture.endswith(b"\n"):
        raise ValueError("ratification capture is not bounded LF text")
    size = require_integer(data.get("text_bytes"), "ratification.text_bytes", minimum=1)
    digest = require_digest(data.get("text_sha256"), "ratification.text_sha256")
    if size != len(capture) or digest != sha256(capture).hexdigest():
        raise ValueError("ratification capture differs from manifest")
    return {
        "jsonl_line": require_integer(
            data.get("jsonl_line"), "ratification.jsonl_line", minimum=2
        ),
        "uuid": require_identifier(data.get("uuid"), "ratification.uuid"),
        "timestamp": require_utc_timestamp(data.get("timestamp"), "ratification.timestamp"),
        "type": role,
        "text_sha256": digest,
        "native_line_sha256": require_digest(
            data.get("native_line_sha256"), "ratification.native_line_sha256"
        ),
    }


def _message(raw: bytes, entry: _CaptureEntry, session: str, capture: bytes) -> str:
    """Match a selected Claude JSONL message to its pinned line and text."""
    if sha256(raw).hexdigest() != entry["native_line_sha256"]:
        raise ValueError("ratification native line differs")
    event = require_mapping(parse_json(raw), "ratification native event")
    role = entry["type"]
    message = require_mapping(event.get("message"), "ratification native message")
    if (
        event.get("type") != role
        or event.get("uuid") != entry["uuid"]
        or require_utc_timestamp(event.get("timestamp"), "ratification.native_timestamp")
        != entry["timestamp"]
        or event.get("sessionId") != session
        or message.get("role") != role
    ):
        raise ValueError("ratification native identity differs")
    if any(
        event.get(marker, False) is not False
        for marker in ("isSidechain", "isMeta", "isCompactSummary")
    ):
        raise ValueError("ratification capture is not an unmarked main-chain message")
    origin = event.get("origin")
    if role == "user" and (not isinstance(origin, dict) or origin.get("kind") != "human"):
        raise ValueError("ratification reply requires explicit human origin")
    content = message.get("content")
    if role == "assistant":
        if not isinstance(content, list) or len(content) != 1:
            raise ValueError("ratification question content differs")
        part = require_mapping(content[0], "ratification question")
        if part.get("type") != "text":
            raise ValueError("ratification question is not text")
        content = part.get("text")
    if require_string(content, "ratification native text").encode("utf-8") + b"\n" != capture:
        raise ValueError("ratification native text differs")
    return require_identifier(event.get("uuid"), "ratification native uuid")


def verify_full_text_ratification_source(
    *,
    manifest_bytes: bytes,
    question_capture: bytes,
    reply_capture: bytes,
    transcript_path: Path,
    expected_manifest_sha256: str,
    expected_question_sha256: str,
    expected_reply_sha256: str,
) -> dict[str, object]:
    """Verify native capture integrity without conferring host admission.

    Parameters
    ----------
    manifest_bytes : bytes
        Bounded manifest selecting one native question and one owner reply.
    question_capture, reply_capture : bytes
        Bounded complete LF-terminated UTF-8 captures.
    transcript_path : Path
        Absolute physical no-follow path to the retained Claude JSONL source.
    expected_manifest_sha256, expected_question_sha256, expected_reply_sha256 : str
        Independently selected exact retained-byte digests.

    Returns
    -------
    dict[str, object]
        Deterministic source relation with ``guard_admissible`` false.

    Raises
    ------
    PermissionError
        Capture or transcript selection differs from expected pins.
    ValueError
        Fields, native lineage, file identity, selected prefix or bounds differ.
    OSError
        A path component or transcript cannot be opened safely.

    Notes
    -----
    The signed hashes and transcript path must later come from protected host
    selection. Caller-chosen values prove only a structural source relation.
    This function requires human-origin replies and unmarked main-chain messages.
    Missing origin and bookkeeping without UUID lineage refuse. It checks native
    record identity and lineage, not decision meaning or an authenticated owner.
    Caller-owned records can forge these markers; protected custody is separate.
    Appends beyond the selected prefix are permitted.
    """
    if not isinstance(manifest_bytes, bytes) or not 0 < len(manifest_bytes) <= 16 * 1024:
        raise ValueError("ratification manifest is not bounded bytes")
    manifest_digest = sha256(manifest_bytes).hexdigest()
    if manifest_digest != require_digest(expected_manifest_sha256, "ratification.manifest"):
        raise PermissionError("ratification manifest differs from signed acceptance")
    if not isinstance(transcript_path, Path) or not transcript_path.is_absolute():
        raise ValueError("ratification transcript path must be absolute")
    manifest = require_mapping(parse_json(manifest_bytes), "ratification manifest")
    require_exact_fields(
        manifest, frozenset({"transcript", "session", "captures"}), "ratification manifest"
    )
    if manifest.get("transcript") != str(transcript_path):
        raise PermissionError("ratification transcript differs from manifest")
    session = require_identifier(manifest.get("session"), "ratification.session")
    captures = require_mapping(manifest.get("captures"), "ratification captures")
    require_exact_fields(captures, frozenset(_NAMES), "ratification captures")
    question = _entry(captures[_NAMES[0]], "assistant", question_capture)
    reply = _entry(captures[_NAMES[1]], "user", reply_capture)
    if question["text_sha256"] != require_digest(
        expected_question_sha256, "ratification.question"
    ) or reply["text_sha256"] != require_digest(expected_reply_sha256, "ratification.reply"):
        raise PermissionError("ratification captures differ from signed acceptance")
    first = question["jsonl_line"]
    last = reply["jsonl_line"]
    if not 0 < last - first - 1 <= 16:
        raise ValueError("ratification message order or gap differs")
    parent = open_directory_no_follow(transcript_path.parent)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(transcript_path.name, flags, dir_fd=parent)
        before = os.fstat(descriptor)
        path_before = os.stat(transcript_path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _identity(before) != _identity(path_before)
        ):
            raise ValueError("ratification transcript is not a stable regular file")
        found: set[int] = set()
        previous: str | None = None
        prefix_hash = sha256()
        prefix_bytes = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for number in range(1, last + 1):
                line = stream.readline(_MAX_LINE + 1)
                if not line:
                    raise ValueError("ratification selected messages are missing")
                prefix_bytes += len(line)
                if prefix_bytes > _MAX_PREFIX:
                    raise ValueError("ratification selected prefix exceeds bound")
                if len(line) > _MAX_LINE or not line.endswith(b"\n"):
                    raise ValueError("ratification native line is malformed or oversized")
                prefix_hash.update(line)
                if number == first:
                    previous = _message(line, question, session, question_capture)
                    found.add(number)
                elif first < number <= last:
                    event = require_mapping(parse_json(line), "ratification adjacent event")
                    if event.get("parentUuid") != previous:
                        raise ValueError("ratification lineage differs")
                    if number == last:
                        _message(line, reply, session, reply_capture)
                        found.add(number)
                    else:
                        if event.get("type") in {"assistant", "user"}:
                            raise ValueError("ratification has an intervening message")
                        previous = require_identifier(
                            event.get("uuid"), "ratification adjacent uuid"
                        )
        after = os.fstat(descriptor)
        path_after = os.stat(transcript_path.name, dir_fd=parent, follow_symlinks=False)
        if (
            found != {first, last}
            or _identity(before) != _identity(after)
            or _identity(before) != _identity(path_after)
            or _prefix_digest(descriptor, prefix_bytes) != prefix_hash.hexdigest()
        ):
            raise ValueError("ratification source changed or messages are missing")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
    proof: dict[str, object] = {
        "schema_version": RATIFICATION_SOURCE_SCHEMA,
        "assertion_class": "native-full-text-ratification-integrity-only",
        "guard_admissible": False,
        "session": session,
        "manifest_sha256": manifest_digest,
        "question_sha256": question["text_sha256"],
        "reply_sha256": reply["text_sha256"],
    }
    return {**proof, "proof_digest": canonical_digest(proof)}
