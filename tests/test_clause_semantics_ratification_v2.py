# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact owner ratification tests
"""Exercise native owner approval of the fully rendered signed-body meaning."""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import TypedDict, cast

import pytest
from test_clause_semantics_set_v2 import _body
from test_semantic_ratification_source import _line

from rigor_foundry.clause_semantics_ratification_v2 import (
    render_clause_semantics_question_v2,
    verify_clause_semantics_ratification_v2,
)
from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2

_SESSION = "4447d917-48db-4f68-a94c-5562be2af58f"


class _Args(TypedDict):
    """Typed exact native source inputs to the public verifier."""

    manifest_bytes: bytes
    question_capture: bytes
    reply_capture: bytes
    transcript_path: Path
    expected_manifest_sha256: str
    expected_question_sha256: str
    expected_reply_sha256: str


def _args(
    root: Path,
    *,
    reply: str | None = None,
    question: bytes | None = None,
    question_at: str = "2026-09-22T22:00:38.772Z",
    reply_at: str = "2026-09-22T22:02:00.404Z",
) -> tuple[ClauseSemanticsSetV2, _Args]:
    """Retain a native question and owner reply with exact hash-selected bytes."""
    body = ClauseSemanticsSetV2.from_bytes(canonical_journal_json_v2(_body()))
    question_bytes = question or render_clause_semantics_question_v2(body)
    reply_bytes = (reply or f"SCHVAĽUJEM clause-semantics-set {body.body_digest}").encode() + b"\n"
    transcript = root / f"{_SESSION}.jsonl"
    question_event: dict[str, object] = {
        "type": "assistant",
        "uuid": "question-1",
        "timestamp": question_at,
        "sessionId": _SESSION,
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": question_bytes[:-1].decode()}],
        },
    }
    intervening = {"type": "system", "uuid": "system-1", "parentUuid": "question-1"}
    reply_event: dict[str, object] = {
        "type": "user",
        "origin": {"kind": "human"},
        "uuid": "reply-1",
        "timestamp": reply_at,
        "sessionId": _SESSION,
        "parentUuid": "system-1",
        "message": {"role": "user", "content": reply_bytes[:-1].decode()},
    }
    lines = [
        _line({"type": "mode"}),
        _line(question_event),
        _line(intervening),
        _line(reply_event),
    ]
    transcript.write_bytes(b"".join(lines))
    captures: dict[str, object] = {}
    for name, number, role, timestamp, capture in (
        ("CEO_QUESTION_FULL_TEXT.txt", 2, "assistant", question_at, question_bytes),
        ("OWNER_REPLY.txt", 4, "user", reply_at, reply_bytes),
    ):
        captures[name] = {
            "jsonl_line": number,
            "uuid": "question-1" if number == 2 else "reply-1",
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
    return body, {
        "manifest_bytes": manifest,
        "question_capture": question_bytes,
        "reply_capture": reply_bytes,
        "transcript_path": transcript,
        "expected_manifest_sha256": sha256(manifest).hexdigest(),
        "expected_question_sha256": sha256(question_bytes).hexdigest(),
        "expected_reply_sha256": sha256(reply_bytes).hexdigest(),
    }


def _verify(body: ClauseSemanticsSetV2, args: _Args) -> dict[str, object]:
    """Call the public verifier with all real source selections."""
    return verify_clause_semantics_ratification_v2(
        body=body,
        manifest_bytes=args["manifest_bytes"],
        question_capture=args["question_capture"],
        reply_capture=args["reply_capture"],
        transcript_path=args["transcript_path"],
        expected_manifest_sha256=args["expected_manifest_sha256"],
        expected_question_sha256=args["expected_question_sha256"],
        expected_reply_sha256=args["expected_reply_sha256"],
    )


def test_exact_native_approval_and_complete_rendering(tmp_path: Path) -> None:
    """The owner sees every canonical entry and approves its exact full digest."""
    body, args = _args(tmp_path)
    question = render_clause_semantics_question_v2(body)
    assert body.body_bytes in question
    assert body.body_digest.encode() in question
    assert question.endswith(f"SCHVAĽUJEM clause-semantics-set {body.body_digest}\n".encode())
    proof = _verify(body, args)
    assert proof == _verify(body, args)
    assert proof["guard_admissible"] is False
    assert proof["semantics_set_digest"] == body.body_digest


def test_owner_rendering_flags_narrowed_veto() -> None:
    """A veto exclusion is explicitly marked as narrowing the veto."""
    value = _body()
    entries = cast(list[dict[str, object]], value["entries"])
    veto_scope = cast(dict[str, object], entries[1]["scope"])
    veto_scope["exclusions"] = ["path:/tmp/rigor/sub"]
    body = ClauseSemanticsSetV2.from_bytes(canonical_journal_json_v2(value))
    question = render_clause_semantics_question_v2(body)
    assert f"Veto {entries[1]['clause_digest']}: exclusions narrow a veto.".encode() in question


@pytest.mark.parametrize(
    "reply_template",
    [
        "SCHVAĽUJEM clause-semantics-set {digest}\nI do not approve this set",
        "SCHVAĽUJEM clause-semantics-set {digest}\nwithdraw my approval",
        "I approve {digest}",
        "SCHVAĽUJEM clause-semantics-set {digest} extra",
        "SCHVAĽUJEM  clause-semantics-set {digest}",
        "SCHVAĽUJEM clause-semantics-set {prefix}",
        '"SCHVAĽUJEM clause-semantics-set {digest}"',
        "SCHVAĽUJEM clause-semantics-set {wrong}",
    ],
)
def test_other_native_reply_content_refuses(tmp_path: Path, reply_template: str) -> None:
    """A quoted, shortened or qualified digest response is never approval."""
    body, _ = _args(tmp_path)
    reply = reply_template.format(
        digest=body.body_digest,
        prefix=body.body_digest[:31],
        wrong="0" * 64,
    )
    body, args = _args(tmp_path, reply=reply)
    with pytest.raises(PermissionError, match="exact semantics approval"):
        _verify(body, args)


def test_surrounding_whitespace_and_nfc_pass(tmp_path: Path) -> None:
    """Only the specified trim characters and NFC are normalized."""
    body, _ = _args(tmp_path)
    reply = f" \t\nSCHVAĽUJEM clause-semantics-set {body.body_digest}\r\n "
    body, args = _args(tmp_path, reply=reply)
    assert _verify(body, args)["semantics_set_digest"] == body.body_digest


def test_older_reply_or_different_question_refuses(tmp_path: Path) -> None:
    """Lineage and digest alone cannot replace chronology or owner rendering."""
    body, args = _args(tmp_path, reply_at="2026-09-22T21:00:00.000Z")
    with pytest.raises(PermissionError, match="not later"):
        _verify(body, args)
    body, args = _args(tmp_path, question=b"Do you approve this set?\n")
    with pytest.raises(PermissionError, match="does not render"):
        _verify(body, args)


def test_forged_body_instance_refuses_render(tmp_path: Path) -> None:
    """A mutable in-memory digest cannot masquerade as the canonical body."""
    body, _ = _args(tmp_path)
    with pytest.raises(ValueError, match="canonical bytes"):
        render_clause_semantics_question_v2(replace(body, body_digest="0" * 64))
