# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — owner-confirmation record wire tests
"""Exercise exact record parsing before native owner evidence is considered."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.effect_class_authority_requirement_v2 import EffectClassAuthorityRequirementV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.models import canonical_digest
from rigor_foundry.owner_confirmation_v2 import (
    OwnerConfirmationRecordV2,
    verify_owner_confirmation_v2,
)

_SESSION = "4447d917-48db-4f68-a94c-5562be2af58f"
_QUESTION_UUID = "10b1e730-9c3d-4f20-a985-0da942111111"
_REPLY_UUID = "10b1e730-9c3d-4f20-a985-0da942222222"
_SYSTEM_UUID = "10b1e730-9c3d-4f20-a985-0da942333333"


def _record() -> dict[str, object]:
    return {
        "schema": "rigor.owner-confirmation.v2",
        "subject_kind": "effect-class-authority-requirement",
        "subject_digest": "a" * 64,
        "question_sha256": "b" * 64,
        "reply_sha256": "c" * 64,
        "capture_manifest_digest": "e" * 64,
        "transcript": {
            "path": "/protected/owner.jsonl",
            "question_line": 2,
            "reply_line": 4,
            "reply_uuid": "4447d917-48db-4f68-a94c-5562be2af58f",
            "reply_line_sha256": "d" * 64,
        },
        "captured_at": "2026-09-23T08:52:00Z",
    }


def test_exact_record_is_canonical_but_not_native_proof() -> None:
    """Parse exact confirmation data and digest bindings without claiming native owner authority."""
    body = _record()
    wire = canonical_journal_json_v2(body)
    value = OwnerConfirmationRecordV2.from_bytes(wire)
    assert value.body_bytes == wire
    assert value.record_digest == canonical_digest(body)
    assert value.subject_digest == "a" * 64
    assert value.transcript_path == Path("/protected/owner.jsonl")
    assert value.question_line == 2 and value.reply_line == 4


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("schema", "rigor.owner-confirmation.v1", "subject differs"),
        ("subject_kind", "clause-semantics-set", "subject differs"),
        ("subject_digest", "short", "digest"),
        ("captured_at", "yesterday", "timestamp"),
    ],
)
def test_changed_body_fields_refuse(field: str, value: object, error: str) -> None:
    """Reject invalid top-level confirmation values through the public canonical parser."""
    body = _record()
    body[field] = value
    with pytest.raises(ValueError, match=error):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("path", "relative.jsonl", "absolute"),
        ("question_line", True, "integer"),
        ("reply_line", 2, "integer"),
        ("reply_uuid", 3, "must be text"),
        ("reply_uuid", "bad", "invalid"),
        ("reply_uuid", "4447D917-48DB-4F68-A94C-5562BE2AF58F", "invalid"),
        ("reply_line_sha256", "x", "digest"),
    ],
)
def test_changed_transcript_fields_refuse(field: str, value: object, error: str) -> None:
    """Reject invalid transcript locator, identity and captured-line fields."""
    body = _record()
    transcript = cast(dict[str, object], body["transcript"])
    transcript[field] = value
    with pytest.raises(ValueError, match=error):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))


def test_unknown_missing_or_noncanonical_fields_refuse() -> None:
    """Reject open field sets, malformed JSON, non-byte inputs and noncanonical confirmation bytes."""
    body = _record()
    body["extra"] = "x"
    with pytest.raises(ValueError, match="fields differ"):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    body = _record()
    del body["transcript"]
    with pytest.raises(ValueError, match="fields differ"):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    body = _record()
    cast(dict[str, object], body["transcript"])["extra"] = "x"
    with pytest.raises(ValueError, match="transcript fields differ"):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    with pytest.raises(ValueError, match="not canonical"):
        OwnerConfirmationRecordV2.from_bytes(b"  " + canonical_journal_json_v2(_record()))
    with pytest.raises(ValueError, match="strict JSON"):
        OwnerConfirmationRecordV2.from_bytes(b"not json")
    with pytest.raises(ValueError, match="must be bytes"):
        OwnerConfirmationRecordV2.from_bytes(cast(bytes, "not bytes"))
    with pytest.raises(ValueError, match="fields differ"):
        OwnerConfirmationRecordV2.from_bytes(b"[]")


def test_reply_line_must_follow_question() -> None:
    """Require the selected reply line to follow its selected question line."""
    body = _record()
    cast(dict[str, object], body["transcript"])["question_line"] = 4
    with pytest.raises(ValueError, match="not later"):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))


@pytest.mark.parametrize("reply_line", [3, 20])
def test_record_requires_the_source_verifiers_bounded_gap(reply_line: int) -> None:
    """Adjacent replies and oversized lineage gaps cannot produce usable records."""
    body = _record()
    cast(dict[str, object], body["transcript"])["reply_line"] = reply_line
    with pytest.raises(ValueError, match="bounded lineage gap"):
        OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))


def _native(
    root: Path,
    *,
    question: bytes | None = None,
    reply: bytes | None = None,
    reply_at: str = "2026-09-23T08:52:00Z",
    question_role: str = "assistant",
    reply_origin: str | None = "human",
    reply_markers: dict[str, object] | None = None,
    question_markers: dict[str, object] | None = None,
) -> tuple[OwnerConfirmationRecordV2, EffectClassAuthorityRequirementV2, bytes, bytes, bytes]:
    """Retain a real native fixture question, lineage and owner reply on disk."""
    requirement = EffectClassAuthorityRequirementV2.build_default()
    decision = f"SCHVAĽUJEM effect-class-authority-requirement {requirement.requirement_digest}"
    question_bytes = (
        question
        or (
            "Confirm this exact effect-class authority requirement.\n"
            "--- enforced_required ---\n"
            + "".join(f"{item}\n" for item in requirement.enforced_required)
            + "--- end ---\n"
            + decision
            + "\n"
        ).encode()
    )
    reply_bytes = reply or (decision + "\n").encode()
    question_at = "2026-09-23T08:50:00Z"
    question_event: dict[str, object] = {
        "type": question_role,
        "uuid": _QUESTION_UUID,
        "timestamp": question_at,
        "sessionId": _SESSION,
        "message": {
            "role": question_role,
            "content": [{"type": "text", "text": question_bytes[:-1].decode()}],
        },
    }
    question_event.update(question_markers or {})
    system_event = {"type": "system", "uuid": _SYSTEM_UUID, "parentUuid": _QUESTION_UUID}
    reply_event: dict[str, object] = {
        "type": "user",
        "uuid": _REPLY_UUID,
        "timestamp": reply_at,
        "sessionId": _SESSION,
        "parentUuid": _SYSTEM_UUID,
        "message": {"role": "user", "content": reply_bytes[:-1].decode()},
    }
    if reply_origin is not None:
        reply_event["origin"] = {"kind": reply_origin}
    reply_event.update(reply_markers or {})
    lines = [
        json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        for item in ({"type": "mode"}, question_event, system_event, reply_event)
    ]
    transcript = root / f"{_SESSION}.jsonl"
    transcript.write_bytes(b"".join(lines))
    captures = {}
    for name, number, role, timestamp, uuid, capture in (
        (
            "CEO_QUESTION_FULL_TEXT.txt",
            2,
            question_role,
            question_at,
            _QUESTION_UUID,
            question_bytes,
        ),
        ("OWNER_REPLY.txt", 4, "user", reply_at, _REPLY_UUID, reply_bytes),
    ):
        captures[name] = {
            "jsonl_line": number,
            "uuid": uuid,
            "timestamp": timestamp,
            "type": role,
            "text_bytes": len(capture),
            "text_sha256": sha256(capture).hexdigest(),
            "native_line_sha256": sha256(lines[number - 1]).hexdigest(),
        }
    manifest = json.dumps(
        {"transcript": str(transcript), "session": _SESSION, "captures": captures},
        separators=(",", ":"),
    ).encode()
    body = {
        "schema": "rigor.owner-confirmation.v2",
        "subject_kind": "effect-class-authority-requirement",
        "subject_digest": requirement.requirement_digest,
        "question_sha256": sha256(question_bytes).hexdigest(),
        "reply_sha256": sha256(reply_bytes).hexdigest(),
        "capture_manifest_digest": sha256(manifest).hexdigest(),
        "transcript": {
            "path": str(transcript),
            "question_line": 2,
            "reply_line": 4,
            "reply_uuid": _REPLY_UUID,
            "reply_line_sha256": sha256(lines[3]).hexdigest(),
        },
        "captured_at": "2026-09-23T08:53:00Z",
    }
    record = OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    return record, requirement, manifest, question_bytes, reply_bytes


def _verify(
    record: OwnerConfirmationRecordV2,
    requirement: EffectClassAuthorityRequirementV2,
    manifest: bytes,
    question: bytes,
    reply: bytes,
    *,
    requirement_digest: str | None = None,
    confirmation_digest: str | None = None,
) -> dict[str, object]:
    """Verify selected fixture bytes through the public confirmation API."""
    return verify_owner_confirmation_v2(
        record=record,
        requirement=requirement,
        manifest_bytes=manifest,
        question_capture=question,
        reply_capture=reply,
        expected_authority_requirement_digest=requirement_digest or requirement.requirement_digest,
        expected_owner_confirmation_digest=confirmation_digest or record.record_digest,
    )


def test_native_owner_confirmation_is_integrity_only(tmp_path: Path) -> None:
    """Bind actual fixture captures to selected records while retaining guard_admissible=false."""
    record, requirement, manifest, question, reply = _native(tmp_path)
    proof = _verify(record, requirement, manifest, question, reply)
    assert proof["guard_admissible"] is False
    assert proof["authority_requirement_digest"] == requirement.requirement_digest
    assert proof["owner_confirmation_digest"] == record.record_digest


def test_changed_selected_record_or_manifest_refuses(tmp_path: Path) -> None:
    """Reject changed selected record digests, altered manifests and missing capture bytes."""
    record, requirement, manifest, question, reply = _native(tmp_path)
    with pytest.raises(PermissionError, match="selected records"):
        _verify(record, requirement, manifest, question, reply, confirmation_digest="0" * 64)
    with pytest.raises(PermissionError, match="selected records"):
        _verify(record, requirement, manifest, question, reply, requirement_digest="0" * 64)
    with pytest.raises(PermissionError, match="selected records"):
        _verify(
            OwnerConfirmationRecordV2.from_bytes(record.body_bytes),
            EffectClassAuthorityRequirementV2.from_bytes(requirement.body_bytes),
            manifest,
            question,
            reply,
            requirement_digest="0" * 64,
        )
    with pytest.raises(PermissionError, match="manifest differs"):
        _verify(record, requirement, manifest + b" ", question, reply)
    with pytest.raises(PermissionError, match="captures are missing"):
        _verify(record, requirement, cast(bytes, None), question, reply)


def test_question_and_reply_must_match_exact_meaning(tmp_path: Path) -> None:
    """Require the exact selected question and approval spelling without duplicates or paraphrases."""
    record, requirement, manifest, question, reply = _native(
        tmp_path,
        question=b"Another list\n--- enforced_required ---\nread\n--- end ---\n"
        + f"SCHVAĽUJEM effect-class-authority-requirement {EffectClassAuthorityRequirementV2.build_default().requirement_digest}\n".encode(),
    )
    with pytest.raises(PermissionError, match="question differs"):
        _verify(record, requirement, manifest, question, reply)
    record, requirement, manifest, question, reply = _native(tmp_path, reply=b"I agree\n")
    with pytest.raises(PermissionError, match="exact decision"):
        _verify(record, requirement, manifest, question, reply)
    decision = f"SCHVAĽUJEM effect-class-authority-requirement {requirement.requirement_digest}\n"
    record, requirement, manifest, question, reply = _native(
        tmp_path, question=question.replace(decision.encode(), (decision * 2).encode())
    )
    with pytest.raises(PermissionError, match="question differs"):
        _verify(record, requirement, manifest, question, reply)


def test_native_chronology_and_manifest_binding_refuse(tmp_path: Path) -> None:
    """Reject reversed chronology, changed manifest identities/hashes and altered actual reply lines."""
    record, requirement, manifest, question, reply = _native(
        tmp_path, reply_at="2026-09-23T08:49:00Z"
    )
    with pytest.raises(PermissionError, match="not later"):
        _verify(record, requirement, manifest, question, reply)
    record, requirement, manifest, question, reply = _native(tmp_path)
    body = json.loads(record.body_bytes)
    body["transcript"]["reply_uuid"] = "10b1e730-9c3d-4f20-a985-0da942444444"
    changed = OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    with pytest.raises(PermissionError, match="native capture manifest"):
        _verify(changed, requirement, manifest, question, reply)
    body = json.loads(record.body_bytes)
    body["transcript"]["reply_line_sha256"] = "0" * 64
    changed = OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    with pytest.raises(PermissionError, match="native capture manifest"):
        _verify(changed, requirement, manifest, question, reply)
    lines = record.transcript_path.read_bytes().splitlines(keepends=True)
    reply_event = json.loads(lines[3])
    reply_event["type"] = "assistant"
    reply_event["message"]["role"] = "assistant"
    lines[3] = json.dumps(reply_event, separators=(",", ":")).encode() + b"\n"
    record.transcript_path.write_bytes(b"".join(lines))
    with pytest.raises(ValueError, match="native line differs"):
        _verify(record, requirement, manifest, question, reply)


def test_tool_question_does_not_count_as_owner_visible_question(tmp_path: Path) -> None:
    """Reject a tool-role question instead of treating it as an owner-visible message."""
    record, requirement, manifest, question, reply = _native(tmp_path, question_role="tool")
    with pytest.raises(ValueError, match="capture type differs"):
        _verify(record, requirement, manifest, question, reply)


@pytest.mark.parametrize("origin", [None, "peer", "task-notification", "scheduled"])
def test_reply_requires_explicit_human_origin(tmp_path: Path, origin: str | None) -> None:
    """Absent or machine-injected native origin cannot satisfy an owner decision."""
    record, requirement, manifest, question, reply = _native(tmp_path, reply_origin=origin)
    with pytest.raises(ValueError, match="human origin"):
        _verify(record, requirement, manifest, question, reply)


@pytest.mark.parametrize("marker", ["isMeta", "isSidechain", "isCompactSummary"])
@pytest.mark.parametrize("role", ["question", "reply"])
def test_marked_question_or_reply_is_not_main_chain(
    tmp_path: Path, marker: str, role: str
) -> None:
    """Native metadata, sidechain and compaction messages cannot carry confirmation."""
    record, requirement, manifest, question, reply = _native(
        tmp_path,
        question_markers={marker: True} if role == "question" else None,
        reply_markers={marker: True} if role == "reply" else None,
    )
    with pytest.raises(ValueError, match="main-chain"):
        _verify(record, requirement, manifest, question, reply)


def test_selected_record_subject_must_be_the_selected_requirement(tmp_path: Path) -> None:
    """Independently selected record and requirement pins cannot cross subjects."""
    record, requirement, manifest, question, reply = _native(tmp_path)
    body = json.loads(record.body_bytes)
    body["subject_digest"] = "0" * 64
    changed = OwnerConfirmationRecordV2.from_bytes(canonical_journal_json_v2(body))
    with pytest.raises(PermissionError, match="selected records"):
        _verify(changed, requirement, manifest, question, reply)


def test_unicode_line_separator_cannot_create_a_decision_line(tmp_path: Path) -> None:
    """Only an actual LF boundary can begin the exact decision in a question."""
    record, requirement, manifest, question, reply = _native(tmp_path)
    decision = f"SCHVAĽUJEM effect-class-authority-requirement {requirement.requirement_digest}\n"
    changed_question = question.replace(decision.encode(), ("prefix\u0085" + decision).encode())
    record, requirement, manifest, question, reply = _native(tmp_path, question=changed_question)
    with pytest.raises(PermissionError, match="question differs"):
        _verify(record, requirement, manifest, question, reply)
