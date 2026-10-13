# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native full-text ratification tests
"""Exercise the public native ratification source boundary with real JSONL."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from threading import Event, Thread
from types import FrameType
from typing import TypedDict, cast

import pytest

import rigor_foundry.semantic_ratification_source as ratification_source
from rigor_foundry.semantic_ratification_source import verify_full_text_ratification_source


@contextmanager
def _filesystem_change(
    action: Callable[[], None], match: Callable[[FrameType, str, object], bool]
) -> Iterator[None]:
    """Synchronize one real filesystem writer at an unpatched observation boundary."""
    started = Event()
    finished = Event()
    stopped = Event()
    errors: list[BaseException] = []
    reached = False
    previous = sys.getprofile()

    def mutate() -> None:
        """Perform the competing operation once the public operation reaches it."""
        if not started.wait(5) or stopped.is_set():
            return
        try:
            action()
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    def observe(frame: FrameType, event: str, arg: object) -> None:
        """Observe timing without changing production code, results or exceptions."""
        nonlocal reached
        if not reached and match(frame, event, arg):
            reached = True
            started.set()
            assert finished.wait(5), "filesystem mutation timed out"
            assert not errors, errors

    worker = Thread(target=mutate)
    worker.start()
    sys.setprofile(observe)
    try:
        yield
    finally:
        sys.setprofile(previous)
        stopped.set()
        started.set()
        worker.join(5)
        assert not worker.is_alive(), "filesystem worker did not terminate"
        assert reached, "public operation did not reach its observation boundary"
        assert not errors, errors


_SESSION = "4447d917-48db-4f68-a94c-5562be2af58f"
_QUESTION = b"Do you approve the four full clauses?\n"
_REPLY = b"I approve the full clauses.\n"


class _Args(TypedDict):
    """Typed inputs to the public ratification verifier."""

    manifest_bytes: bytes
    question_capture: bytes
    reply_capture: bytes
    transcript_path: Path
    expected_manifest_sha256: str
    expected_question_sha256: str
    expected_reply_sha256: str


def _line(value: Mapping[str, object]) -> bytes:
    """Encode one stable native JSONL event."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _fixture(root: Path) -> _Args:
    """Build an adjacent assistant-system-owner pair and exact manifest."""
    transcript = root / f"{_SESSION}.jsonl"
    question = {
        "type": "assistant",
        "uuid": "question-1",
        "timestamp": "2026-09-22T22:00:38.772Z",
        "sessionId": _SESSION,
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": _QUESTION[:-1].decode()}],
        },
    }
    intervening = {"type": "system", "uuid": "system-1", "parentUuid": "question-1"}
    reply = {
        "type": "user",
        "origin": {"kind": "human"},
        "uuid": "reply-1",
        "timestamp": "2026-09-22T22:02:00.404Z",
        "sessionId": _SESSION,
        "parentUuid": "system-1",
        "message": {"role": "user", "content": _REPLY[:-1].decode()},
    }
    raw = [_line({"type": "mode"}), _line(question), _line(intervening), _line(reply)]
    transcript.write_bytes(b"".join(raw))
    entries = {}
    for name, number, role, event, capture in (
        ("CEO_QUESTION_FULL_TEXT.txt", 2, "assistant", question, _QUESTION),
        ("OWNER_REPLY.txt", 4, "user", reply, _REPLY),
    ):
        entries[name] = {
            "jsonl_line": number,
            "uuid": event["uuid"],
            "timestamp": event["timestamp"],
            "type": role,
            "text_bytes": len(capture),
            "text_sha256": sha256(capture).hexdigest(),
            "native_line_sha256": sha256(raw[number - 1]).hexdigest(),
        }
    manifest = json.dumps(
        {"transcript": str(transcript), "session": _SESSION, "captures": entries},
        separators=(",", ":"),
    ).encode()
    return {
        "manifest_bytes": manifest,
        "question_capture": _QUESTION,
        "reply_capture": _REPLY,
        "transcript_path": transcript,
        "expected_manifest_sha256": sha256(manifest).hexdigest(),
        "expected_question_sha256": sha256(_QUESTION).hexdigest(),
        "expected_reply_sha256": sha256(_REPLY).hexdigest(),
    }


def _verify(args: _Args, change: dict[str, object] | None = None) -> dict[str, object]:
    """Call the public verifier with typed fixture values and optional faults."""
    data: dict[str, object] = dict(args)
    if change is not None:
        data.update(change)
    return verify_full_text_ratification_source(
        manifest_bytes=cast(bytes, data["manifest_bytes"]),
        question_capture=cast(bytes, data["question_capture"]),
        reply_capture=cast(bytes, data["reply_capture"]),
        transcript_path=cast(Path, data["transcript_path"]),
        expected_manifest_sha256=cast(str, data["expected_manifest_sha256"]),
        expected_question_sha256=cast(str, data["expected_question_sha256"]),
        expected_reply_sha256=cast(str, data["expected_reply_sha256"]),
    )


def _change_manifest(args: _Args, name: str, field: str, value: object) -> None:
    """Change a selected manifest entry while keeping the manifest hash current."""
    manifest = json.loads(args["manifest_bytes"])
    manifest["captures"][name][field] = value
    args["manifest_bytes"] = json.dumps(manifest, separators=(",", ":")).encode()
    args["expected_manifest_sha256"] = sha256(args["manifest_bytes"]).hexdigest()


def _change_native(args: _Args, line_number: int, field: str, value: object) -> None:
    """Change one native event and update only its manifest line pin."""
    lines = args["transcript_path"].read_bytes().splitlines(keepends=True)
    event = json.loads(lines[line_number - 1])
    event[field] = value
    lines[line_number - 1] = _line(event)
    args["transcript_path"].write_bytes(b"".join(lines))
    name = "CEO_QUESTION_FULL_TEXT.txt" if line_number == 2 else "OWNER_REPLY.txt"
    _change_manifest(args, name, "native_line_sha256", sha256(lines[line_number - 1]).hexdigest())


def test_exact_native_ratification_proves_integrity_only(tmp_path: Path) -> None:
    """A selected native pair yields a deterministic non-admissible proof."""
    args = _fixture(tmp_path)
    proof = _verify(args)
    assert proof == _verify(args)
    assert proof["guard_admissible"] is False
    assert proof["question_sha256"] == args["expected_question_sha256"]


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"expected_manifest_sha256": "0" * 64}, "manifest differs"),
        ({"expected_question_sha256": "0" * 64}, "captures differ"),
        ({"expected_reply_sha256": "0" * 64}, "captures differ"),
        ({"question_capture": b"Changed question\n"}, "capture differs"),
        ({"reply_capture": b"Changed reply\n"}, "capture differs"),
        ({"reply_capture": b"missing final LF"}, "bounded LF"),
    ],
)
def test_changed_capture_or_signed_hash_refuses(
    tmp_path: Path, change: dict[str, object], match: str
) -> None:
    """A caller cannot substitute bytes under the selected hashes."""
    args = _fixture(tmp_path)
    with pytest.raises((ValueError, PermissionError), match=match):
        _verify(args, change)


def test_native_line_mutation_and_intervening_message_refuse(tmp_path: Path) -> None:
    """Pinned native line bytes and the adjacent conversation chain are required."""
    args = _fixture(tmp_path)
    transcript = args["transcript_path"]
    original = transcript.read_bytes()
    transcript.write_bytes(original.replace(b"question-1", b"question-2", 1))
    with pytest.raises(ValueError, match="native line differs"):
        _verify(args)
    transcript.write_bytes(original.replace(b'"type":"system"', b'"type":"assistant"'))
    with pytest.raises(ValueError, match="intervening message"):
        _verify(args)


def test_manifest_path_and_file_kind_refuse(tmp_path: Path) -> None:
    """Manifest-selected transcript and no-follow regular file are mandatory."""
    args = _fixture(tmp_path)
    with pytest.raises(PermissionError, match="transcript differs"):
        _verify(args, {"transcript_path": tmp_path / "different.jsonl"})
    transcript = args["transcript_path"]
    moved = tmp_path / "moved.jsonl"
    transcript.rename(moved)
    transcript.symlink_to(moved)
    with pytest.raises(OSError):
        _verify(args)
    transcript.unlink()
    transcript.mkdir()
    with pytest.raises(ValueError, match="stable regular file"):
        _verify(args)


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"manifest_bytes": b""}, "bounded bytes"),
        ({"manifest_bytes": b"0" * (16 * 1024 + 1)}, "bounded bytes"),
        ({"transcript_path": Path("relative.jsonl")}, "must be absolute"),
        ({"question_capture": b""}, "bounded LF"),
        ({"question_capture": b"Q\n" * (16 * 1024)}, "bounded LF"),
        ({"question_capture": "not bytes"}, "capture type"),
    ],
)
def test_malformed_public_inputs_refuse(
    tmp_path: Path, change: dict[str, object], match: str
) -> None:
    """Public inputs must not choose malformed capture or source shapes."""
    with pytest.raises((ValueError, PermissionError), match=match):
        _verify(_fixture(tmp_path), change)


@pytest.mark.parametrize(
    ("name", "field", "value", "match"),
    [
        ("CEO_QUESTION_FULL_TEXT.txt", "type", "user", "capture type"),
        ("OWNER_REPLY.txt", "text_bytes", 1, "capture differs"),
        ("OWNER_REPLY.txt", "text_sha256", "0" * 64, "capture differs"),
        ("OWNER_REPLY.txt", "jsonl_line", 2, "order or gap"),
        ("OWNER_REPLY.txt", "jsonl_line", 50, "order or gap"),
    ],
)
def test_crossed_manifest_selection_refuses(
    tmp_path: Path, name: str, field: str, value: object, match: str
) -> None:
    """A rehashed manifest cannot change roles, captures or adjacency."""
    args = _fixture(tmp_path)
    _change_manifest(args, name, field, value)
    with pytest.raises(ValueError, match=match):
        _verify(args)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("sessionId", "another-session", "identity differs"),
        ("type", "user", "identity differs"),
        ("message", {"role": "assistant", "content": []}, "question content"),
        ("message", {"role": "assistant", "content": [{"type": "tool", "text": "x"}]}, "not text"),
        (
            "message",
            {"role": "assistant", "content": [{"type": "text", "text": "wrong"}]},
            "text differs",
        ),
    ],
)
def test_rehashed_native_question_still_requires_exact_message(
    tmp_path: Path, field: str, value: object, match: str
) -> None:
    """A fresh line hash cannot hide changed role, session, content or text."""
    args = _fixture(tmp_path)
    _change_native(args, 2, field, value)
    with pytest.raises(ValueError, match=match):
        _verify(args)


def test_reply_lineage_and_selected_prefix_bounds_refuse(tmp_path: Path) -> None:
    """The selected reply follows the question within the bounded prefix."""
    args = _fixture(tmp_path)
    _change_native(args, 4, "parentUuid", "another-parent")
    with pytest.raises(ValueError, match="lineage differs"):
        _verify(args)
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    path.write_bytes(
        path.read_bytes().replace(b'"type":"mode"', b'"type":"mode"' + b" " * (2 * 1024 * 1024))
    )
    with pytest.raises(ValueError, match="malformed or oversized"):
        _verify(args)


def test_missing_selected_message_refuses(tmp_path: Path) -> None:
    """A manifest cannot point beyond the bounded native conversation."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:-1]))
    with pytest.raises(ValueError, match="messages are missing"):
        _verify(args)


def test_later_append_during_read_preserves_pinned_prefix(tmp_path: Path) -> None:
    """A real writer appends after the actual selected question was validated."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    before = path.read_bytes()
    expected = _verify(args)
    later = b'{"type":"later"}\n'

    def append() -> None:
        """Append and fsync the actual native transcript from another thread."""
        with path.open("ab") as stream:
            stream.write(later)
            stream.flush()
            os.fsync(stream.fileno())

    def after_question(frame: FrameType, event: str, arg: object) -> bool:
        """Observe the real selected-question helper return without changing it."""
        return (
            frame.f_code is ratification_source._message.__code__
            and event == "return"
            and frame.f_locals["entry"]["type"] == "assistant"
        )

    with _filesystem_change(append, after_question):
        assert _verify(args) == expected
    assert path.read_bytes() == before + later


def test_large_later_suffix_does_not_exhaust_prefix_limit(tmp_path: Path) -> None:
    """A transcript larger than 64 MiB remains valid when ratification is early."""
    args = _fixture(tmp_path)
    with args["transcript_path"].open("ab") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    assert _verify(args)["guard_admissible"] is False


def test_selected_prefix_mutation_during_read_refuses(tmp_path: Path) -> None:
    """Actual same-size outside rewriting is detected by the real prefix rehash."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    before = path.read_bytes()

    def rewrite() -> None:
        """Change and fsync an already-read byte in the selected transcript."""
        with path.open("r+b") as stream:
            stream.write(b"X")
            stream.flush()
            os.fsync(stream.fileno())

    def before_rehash(frame: FrameType, event: str, arg: object) -> bool:
        """Observe entry into the actual rehash without replacing its result."""
        return frame.f_code is ratification_source._prefix_digest.__code__ and event == "call"

    with (
        _filesystem_change(rewrite, before_rehash),
        pytest.raises(ValueError, match="source changed"),
    ):
        _verify(args)
    assert path.read_bytes() == b"X" + before[1:]


def test_selected_prefix_truncation_before_rehash_refuses(tmp_path: Path) -> None:
    """A real truncate after initial reads cannot pass the retained-prefix check."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]

    def truncate() -> None:
        """Truncate and fsync the real selected inode from an outside writer."""
        with path.open("r+b") as stream:
            stream.truncate(0)
            os.fsync(stream.fileno())

    def before_rehash(frame: FrameType, event: str, arg: object) -> bool:
        """Observe the actual rehash call after the ordinary file postchecks."""
        return frame.f_code is ratification_source._prefix_digest.__code__ and event == "call"

    with (
        _filesystem_change(truncate, before_rehash),
        pytest.raises(ValueError, match="prefix disappeared"),
    ):
        _verify(args)
    assert path.stat().st_size == 0


def test_selected_transcript_replacement_during_read_refuses(tmp_path: Path) -> None:
    """A byte-identical replacement inode cannot borrow the selected descriptor."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    before = path.read_bytes()
    original_inode = path.stat().st_ino
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_bytes(before)
    replacement_inode = replacement.stat().st_ino
    assert replacement_inode != original_inode

    def swap() -> None:
        """Replace the selected pathname with a real distinct regular inode."""
        os.replace(replacement, path)

    def after_question(frame: FrameType, event: str, arg: object) -> bool:
        """Observe the actual question read while the original fd remains open."""
        return (
            frame.f_code is ratification_source._message.__code__
            and event == "return"
            and frame.f_locals["entry"]["type"] == "assistant"
        )

    with (
        _filesystem_change(swap, after_question),
        pytest.raises(ValueError, match="source changed"),
    ):
        _verify(args)
    assert path.stat().st_ino == replacement_inode
    assert path.read_bytes() == before


def test_real_selected_prefix_exceeding_64_mib_refuses(tmp_path: Path) -> None:
    """Real individually bounded JSONL records can exceed the aggregate prefix cap."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    selected = path.read_bytes()
    start = b'{"type":"mode","padding":"'
    end = b'"}\n'
    line = start + b"x" * (2 * 1024 * 1024 - len(start) - len(end)) + end
    assert len(line) == 2 * 1024 * 1024
    with path.open("wb") as stream:
        for _ in range(32):
            stream.write(line)
        stream.write(selected)
    _change_manifest(args, "CEO_QUESTION_FULL_TEXT.txt", "jsonl_line", 34)
    _change_manifest(args, "OWNER_REPLY.txt", "jsonl_line", 36)
    with pytest.raises(ValueError, match="selected prefix exceeds bound"):
        _verify(args)


def test_hard_linked_native_transcript_refuses(tmp_path: Path) -> None:
    """A second real directory entry invalidates the selected single-link source."""
    args = _fixture(tmp_path)
    second = tmp_path / "second-link.jsonl"
    os.link(args["transcript_path"], second)
    assert args["transcript_path"].stat().st_nlink == 2
    with pytest.raises(ValueError, match="stable regular file"):
        _verify(args)


@pytest.mark.parametrize("origin", [None, {}, {"kind": "peer"}, {"kind": "task-notification"}])
def test_native_reply_origin_must_be_human(tmp_path: Path, origin: object) -> None:
    """A fresh line pin does not turn an unknown or machine origin into a human."""
    args = _fixture(tmp_path)
    _change_native(args, 4, "origin", origin)
    with pytest.raises(ValueError, match="human origin"):
        _verify(args)


@pytest.mark.parametrize("marker", ["isMeta", "isSidechain", "isCompactSummary"])
@pytest.mark.parametrize("line_number", [2, 4])
def test_native_question_and_reply_markers_refuse(
    tmp_path: Path, marker: str, line_number: int
) -> None:
    """Main-chain refusal applies before either selected capture is accepted."""
    args = _fixture(tmp_path)
    _change_native(args, line_number, marker, True)
    with pytest.raises(ValueError, match="main-chain"):
        _verify(args)


@pytest.mark.parametrize("value", [None, 0, "false"])
def test_native_marker_requires_literal_false(tmp_path: Path, value: object) -> None:
    """Malformed metadata cannot imitate an explicitly false main-chain marker."""
    args = _fixture(tmp_path)
    _change_native(args, 4, "isMeta", value)
    with pytest.raises(ValueError, match="main-chain"):
        _verify(args)


def test_explicit_false_markers_preserve_human_reply(tmp_path: Path) -> None:
    """Human-origin messages may explicitly declare all three main-chain flags false."""
    args = _fixture(tmp_path)
    for marker in ("isSidechain", "isMeta", "isCompactSummary"):
        _change_native(args, 4, marker, False)
    assert _verify(args)["guard_admissible"] is False


def test_bookkeeping_without_uuid_lineage_remains_unsupported(tmp_path: Path) -> None:
    """A real provider bookkeeping record refuses instead of being silently skipped."""
    args = _fixture(tmp_path)
    path = args["transcript_path"]
    lines = path.read_bytes().splitlines(keepends=True)
    lines.insert(3, _line({"type": "file-history-snapshot", "messageId": "history-1"}))
    path.write_bytes(b"".join(lines))
    _change_manifest(args, "OWNER_REPLY.txt", "jsonl_line", 5)
    with pytest.raises(ValueError, match="lineage differs"):
        _verify(args)
