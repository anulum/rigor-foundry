# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native message pair tests
"""Exercise bounded native JSONL evidence without making an owner grant."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import TypedDict, cast

import pytest

from rigor_foundry.native_message_pair import (
    NativeMessageSelector,
    NativeReadLimits,
    verify_native_message_pair,
)

SESSION = "01a054a2-760e-7840-94a8-8e485d7f2e20"
FILENAME = f"rollout-2026-08-30T23-45-28-{SESSION}.jsonl"
QUESTION_ID = "msg_question"
REPLY_ID = "msg_reply"
QUESTION_TIME = "2026-09-12T13:11:14.226Z"
REPLY_TIME = "2026-09-12T13:12:23.830Z"
LIMITS = NativeReadLimits(total_bytes=2000, line_bytes=1000, intervening_lines=3)


class NativeArguments(TypedDict):
    root: Path
    filename: str
    session_id: str
    question: NativeMessageSelector
    reply: NativeMessageSelector
    question_capture: bytes
    reply_capture: bytes
    limits: NativeReadLimits


def _line(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _message(role: str, message_id: str, timestamp: str, text: str) -> bytes:
    return _line(
        {
            "timestamp": timestamp,
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": role,
                "id": message_id,
                "content": [
                    {"type": "output_text" if role == "assistant" else "input_text", "text": text}
                ],
            },
        }
    )


def _fixture(tmp_path: Path) -> tuple[Path, NativeArguments]:
    session = _line({"type": "session_meta", "payload": {"id": SESSION}})
    question = _message("assistant", QUESTION_ID, QUESTION_TIME, "Exact question?")
    middle = _line({"type": "event_msg", "payload": {"type": "token_count"}})
    reply = _message("user", REPLY_ID, REPLY_TIME, "Yes, this direction.")
    path = tmp_path / FILENAME
    path.write_bytes(session + question + middle + reply)
    kwargs: NativeArguments = {
        "root": tmp_path,
        "filename": FILENAME,
        "session_id": SESSION,
        "question": NativeMessageSelector.build(
            line_number=2,
            message_id=QUESTION_ID,
            timestamp=QUESTION_TIME,
            line_digest=sha256(question).hexdigest(),
            capture_digest=sha256(b"Exact question?\n").hexdigest(),
        ),
        "reply": NativeMessageSelector.build(
            line_number=4,
            message_id=REPLY_ID,
            timestamp=REPLY_TIME,
            line_digest=sha256(reply).hexdigest(),
            capture_digest=sha256(b"Yes, this direction.\n").hexdigest(),
        ),
        "question_capture": b"Exact question?\n",
        "reply_capture": b"Yes, this direction.\n",
        "limits": LIMITS,
    }
    return path, kwargs


def test_exact_pair_yields_integrity_only_receipt(tmp_path: Path) -> None:
    """Bind the selected native lines and captured text without promotion."""
    path, kwargs = _fixture(tmp_path)
    receipt = verify_native_message_pair(**kwargs)
    assert receipt["schema_version"] == "native-message-pair-verification.v1"
    assert receipt["assertion_class"] == "native-message-integrity-only"
    assert receipt["promotable"] is False
    assert receipt["file_digest"] == sha256(path.read_bytes()).hexdigest()
    assert receipt["file_bytes"] == path.stat().st_size
    assert isinstance(receipt["verification_digest"], str)


@pytest.mark.parametrize(
    "fault",
    [
        "question-id",
        "reply-id",
        "question-time",
        "reply-time",
        "question-digest",
        "reply-digest",
        "question-capture-digest",
        "reply-capture-digest",
        "question-capture",
        "reply-capture",
        "session-id",
        "filename",
        "reversed-lines",
        "large-gap",
        "small-file-budget",
        "small-line-budget",
        "short-file",
        "changed-question",
        "changed-reply",
        "intervening-user",
        "intervening-assistant",
        "invalid-intervening-json",
        "invalid-session-json",
        "missing-lf",
        "hardlink",
        "symlink",
    ],
)
def test_changed_or_unbounded_native_source_is_refused(tmp_path: Path, fault: str) -> None:
    """Reject fabricated identities, altered bytes, gaps, links, and truncation."""
    path, kwargs = _fixture(tmp_path)
    if fault in {"question-id", "question-time", "question-digest", "question-capture-digest"}:
        selector = kwargs["question"]
        assert isinstance(selector, NativeMessageSelector)
        field = {
            "question-id": "message_id",
            "question-time": "timestamp",
            "question-digest": "line_digest",
            "question-capture-digest": "capture_digest",
        }[fault]
        replacement = (
            "0" * 64 if "digest" in fault else (REPLY_TIME if field == "timestamp" else REPLY_ID)
        )
        kwargs["question"] = replace(selector, **{field: replacement})
    elif fault in {"reply-id", "reply-time", "reply-digest", "reply-capture-digest"}:
        selector = kwargs["reply"]
        assert isinstance(selector, NativeMessageSelector)
        field = {
            "reply-id": "message_id",
            "reply-time": "timestamp",
            "reply-digest": "line_digest",
            "reply-capture-digest": "capture_digest",
        }[fault]
        replacement = (
            "0" * 64
            if "digest" in fault
            else (QUESTION_TIME if field == "timestamp" else QUESTION_ID)
        )
        kwargs["reply"] = replace(selector, **{field: replacement})
    elif fault in {"question-capture", "reply-capture"}:
        kwargs[fault.replace("-", "_")] = b"Changed.\n"
    elif fault == "session-id":
        kwargs["session_id"] = "different-session"
    elif fault == "filename":
        kwargs["filename"] = "../traversal.jsonl"
    elif fault == "reversed-lines":
        kwargs["reply"] = replace(kwargs["reply"], line_number=1)
    elif fault == "large-gap":
        kwargs["reply"] = replace(kwargs["reply"], line_number=9)
    elif fault == "small-file-budget":
        kwargs["limits"] = NativeReadLimits(total_bytes=100, line_bytes=100, intervening_lines=3)
    elif fault == "small-line-budget":
        kwargs["limits"] = NativeReadLimits(total_bytes=2000, line_bytes=20, intervening_lines=3)
    elif fault == "short-file":
        path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:-1]))
    elif fault in {"changed-question", "changed-reply"}:
        old = b"Exact question?" if fault == "changed-question" else b"Yes, this direction."
        path.write_bytes(path.read_bytes().replace(old, b"Not the same text."))
    elif fault in {"intervening-user", "intervening-assistant"}:
        lines = path.read_bytes().splitlines(keepends=True)
        lines[2] = _message(fault.split("-")[1], "intervening", REPLY_TIME, "No.")
        path.write_bytes(b"".join(lines))
    elif fault == "invalid-intervening-json":
        lines = path.read_bytes().splitlines(keepends=True)
        lines[2] = b"{invalid}\n"
        path.write_bytes(b"".join(lines))
    elif fault == "invalid-session-json":
        lines = path.read_bytes().splitlines(keepends=True)
        lines[0] = b"{invalid}\n"
        path.write_bytes(b"".join(lines))
    elif fault == "missing-lf":
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
    elif fault == "hardlink":
        os.link(path, tmp_path / "linked.jsonl")
    elif fault == "symlink":
        path.rename(tmp_path / "target.jsonl")
        path.symlink_to(tmp_path / "target.jsonl")
    with pytest.raises((ValueError, OSError)):
        verify_native_message_pair(**kwargs)


@pytest.mark.parametrize("value", [0, -1, True, 2**31, "1"])
def test_invalid_budgets_and_selectors_are_refused(value: object) -> None:
    """Do not accept bools or implicit integer coercions for limits."""
    with pytest.raises(ValueError):
        NativeReadLimits(total_bytes=cast(int, value), line_bytes=1, intervening_lines=1)
    with pytest.raises(ValueError):
        NativeMessageSelector.build(
            line_number=cast(int, value),
            message_id=QUESTION_ID,
            timestamp=QUESTION_TIME,
            line_digest="0" * 64,
            capture_digest="0" * 64,
        )


def test_line_limit_must_fit_total_limit() -> None:
    """The two byte budgets must be internally consistent."""
    with pytest.raises(ValueError, match="line limit"):
        NativeReadLimits(total_bytes=1, line_bytes=2, intervening_lines=1)


@pytest.mark.parametrize("fault", ["wrong-native-session", "nonbytes", "large-capture"])
def test_invalid_session_or_capture_is_refused(tmp_path: Path, fault: str) -> None:
    """A matching filename alone cannot establish session identity."""
    path, kwargs = _fixture(tmp_path)
    if fault == "wrong-native-session":
        path.write_bytes(path.read_bytes().replace(SESSION.encode(), b"0" * len(SESSION)))
    elif fault == "nonbytes":
        kwargs["question_capture"] = "Exact question?\n"
    else:
        kwargs["question_capture"] = b"X" * 1001
    with pytest.raises(ValueError):
        verify_native_message_pair(**kwargs)


@pytest.mark.parametrize("suffix", ["event", "tool-response"])
def test_unselected_trailing_events_are_hashed(tmp_path: Path, suffix: str) -> None:
    """The full native file remains bound without treating tool events as replies."""
    path, kwargs = _fixture(tmp_path)
    if suffix == "event":
        addition = _line({"type": "event_msg", "payload": {"type": "turn_complete"}})
    else:
        addition = _line(
            {"type": "response_item", "payload": {"type": "function_call", "role": "tool"}}
        )
    path.write_bytes(path.read_bytes() + addition)
    result = verify_native_message_pair(**kwargs)
    assert result["file_digest"] == sha256(path.read_bytes()).hexdigest()


def test_intervening_tool_event_is_not_owner_message(tmp_path: Path) -> None:
    """A tool response item between turns is not itself an owner decision."""
    path, kwargs = _fixture(tmp_path)
    lines = path.read_bytes().splitlines(keepends=True)
    lines[2] = _line({"type": "response_item", "payload": {"role": "tool"}})
    path.write_bytes(b"".join(lines))
    assert verify_native_message_pair(**kwargs)["promotable"] is False


def test_growth_past_budget_during_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the streaming limit even if a source grows after the first fstat."""
    path, kwargs = _fixture(tmp_path)
    original_stat = os.stat
    initial_size = path.stat().st_size
    kwargs["limits"] = NativeReadLimits(
        total_bytes=initial_size + 1, line_bytes=400, intervening_lines=3
    )
    called = False

    def growing_stat(
        pathname: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        nonlocal called
        result = original_stat(pathname, *args, **kwargs)
        if pathname == FILENAME and kwargs.get("dir_fd") is not None and not called:
            called = True
            with path.open("ab") as stream:
                stream.write(_line({"type": "event_msg", "payload": {"type": "extra"}}))
        return result

    monkeypatch.setattr(os, "stat", growing_stat)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {growing_stat})
    monkeypatch.setattr(
        os, "supports_follow_symlinks", os.supports_follow_symlinks | {growing_stat}
    )
    with pytest.raises(ValueError, match="native transcript exceeds byte limit"):
        verify_native_message_pair(**kwargs)
    assert called
