# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual native corpus source tests
"""Exercise real retained JSONL, selected native pins and exact full corpus statements."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from test_policy_source_selection import selection
from test_rule_source_document import source_document

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.native_message_pair import NativeMessageSelector, NativeReadLimits
from rigor_foundry.native_source_host import HostNativeSourceState
from rigor_foundry.native_source_pin import NativeSourcePin
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_records import PolicySourceRecord1
from rigor_foundry.policy_source_spans import SourceSpan1
from rigor_foundry.retained_policy_source import RetainedPolicySource
from rigor_foundry.rule_corpus_acceptance import rule_corpus_document_digests
from rigor_foundry.rule_corpus_native import (
    RuleCorpusNativeOwner,
    render_rule_corpus_question,
    rule_corpus_native_binding_digest,
    rule_corpus_ratification_statement,
)
from rigor_foundry.rule_corpus_ratification import RuleCorpusRatification1
from rigor_foundry.rule_source_document import RuleSourceDocument1
from rigor_foundry.typed_object_reference import TypedObjectRef1


def corpus_budget(*, size: int = 262144, references: int = 2048) -> PolicyReadBudget1:
    """Bound both complete native JSONL and full rendered documents explicitly."""
    return PolicyReadBudget1.build(
        max_document_bytes=size,
        max_source_bytes=size,
        max_total_source_bytes=2 * size,
        max_sources=16,
        max_rules=32,
        max_references=references,
        max_depth=32,
    )


class NativeOwnerArguments(TypedDict):
    """Actual selected source and host inputs for public native-owner construction."""

    metadata: RetainedContextSource
    transcript: RetainedPolicySource
    state: HostNativeSourceState
    issuer_id: str
    corpus_id: str
    expected_issuer_binding_digest: str
    question_capture: bytes
    reply_capture: bytes
    budget: PolicyReadBudget1


@dataclass(frozen=True)
class CorpusNativeSelection:
    """Actual original fixture paths, selected metadata and borrowed owner arguments."""

    arguments: NativeOwnerArguments
    path: Path
    metadata_path: Path
    pin: NativeSourcePin
    ratification: RuleCorpusRatification1
    budget: PolicyReadBudget1


def native_message_line(role: str, text: bytes, timestamp: str, message_id: str) -> bytes:
    """Encode actual native message grammar with escaped Unicode and explicit text boundaries."""
    value = {
        "timestamp": timestamp,
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": role,
            "id": message_id,
            "content": [
                {
                    "type": "output_text" if role == "assistant" else "input_text",
                    "text": text.decode("utf-8"),
                }
            ],
        },
    }
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        + b"\n"
    )


@contextmanager
def corpus_native_selection(
    root: Path,
    document: RuleSourceDocument1,
    *,
    budget: PolicyReadBudget1,
    question_text: bytes | None = None,
    user_text: bytes | None = None,
    reply_time: str = "2026-10-18T12:01:00Z",
    reply_number: int = 4,
    final_lf: bool = True,
    declared_file_digest: str | None = None,
) -> Iterator[CorpusNativeSelection]:
    """Create actual original native JSONL and pin metadata before opening any retained lease."""
    root.mkdir()
    raw, meta = root / "raw", root / "meta"
    raw.mkdir()
    meta.mkdir()
    session = "corpus-native-fixture"
    question_time = "2026-10-18T12:00:00Z"
    question = (
        render_rule_corpus_question(document, budget=budget)
        if question_text is None
        else question_text
    )
    statement = (
        rule_corpus_ratification_statement(document, budget=budget)
        if user_text is None
        else user_text
    )
    session_line = (
        json.dumps({"type": "session_meta", "payload": {"id": session}}).encode() + b"\n"
    )
    question_line = native_message_line("assistant", question, question_time, "question")
    middle = b'{"type":"event_msg","payload":{"type":"token_count"}}\n'
    reply_line = native_message_line("user", statement, reply_time, "reply")
    payload = session_line + question_line + middle + reply_line
    if not final_lf:
        payload = payload[:-1]
    path = raw / f"rollout-{session}.jsonl"
    path.write_bytes(payload)
    pin = NativeSourcePin.build(
        source_id="corpus-native-approval",
        root=raw,
        filename=path.name,
        session_id=session,
        file_digest=hashlib.sha256(payload).hexdigest()
        if declared_file_digest is None
        else declared_file_digest,
        question=NativeMessageSelector.build(
            line_number=2,
            message_id="question",
            timestamp=question_time,
            line_digest=hashlib.sha256(question_line).hexdigest(),
            capture_digest=hashlib.sha256(question + b"\n").hexdigest(),
        ),
        reply=NativeMessageSelector.build(
            line_number=reply_number,
            message_id="reply",
            timestamp=reply_time,
            line_digest=hashlib.sha256(reply_line).hexdigest(),
            capture_digest=hashlib.sha256(statement + b"\n").hexdigest(),
        ),
        limits=NativeReadLimits(
            total_bytes=budget.max_source_bytes,
            line_bytes=min(budget.max_source_bytes, budget.max_document_bytes),
            intervening_lines=max(2, reply_number - 3),
        ),
    )
    record = PolicySourceRecord1(pin, budget)
    reference = TypedObjectRef1.from_dict(record.reference())
    metadata_path = meta / "native-pin.json"
    metadata_bytes = json.dumps(record.to_dict()).encode()
    metadata_path.write_bytes(metadata_bytes)
    binding = rule_corpus_document_digests(document, budget=budget)
    span = SourceSpan1.build(
        span_id="actual-native-reply",
        source_id=pin.source_id,
        start_byte=len(session_line + question_line + middle),
        end_byte=len(payload),
        payload=payload,
    )
    ratification = RuleCorpusRatification1.build(
        corpus_id=binding["corpus_id"],
        document_digest=binding["document_digest"],
        universe_digest=binding["universe_digest"],
        decision_set_digest=binding["decision_set_digest"],
        issuer_id="installed-native-issuer",
        native_capture=reference,
        statement_span=span,
        statement_digest=hashlib.sha256(statement).hexdigest(),
        budget=budget,
    )
    with ExitStack() as stack:
        metadata = stack.enter_context(
            RetainedContextSource(
                metadata_path,
                reference=reference,
                raw_digest=hashlib.sha256(metadata_bytes).hexdigest(),
                budget=budget,
            )
        )
        transcript = stack.enter_context(
            RetainedPolicySource(
                path,
                byte_digest=hashlib.sha256(payload).hexdigest(),
                byte_count=len(payload),
                budget=budget,
            )
        )
        arguments: NativeOwnerArguments = {
            "metadata": metadata,
            "transcript": transcript,
            "state": HostNativeSourceState(pin, pin.pin_digest, frozenset()),
            "issuer_id": ratification.issuer_id,
            "corpus_id": document.corpus_id,
            "expected_issuer_binding_digest": rule_corpus_native_binding_digest(
                issuer_id=ratification.issuer_id,
                corpus_id=document.corpus_id,
                native_capture=reference,
            ),
            "question_capture": question + b"\n",
            "reply_capture": statement + b"\n",
            "budget": budget,
        }
        yield CorpusNativeSelection(arguments, path, metadata_path, pin, ratification, budget)


def changed_ratification(
    value: RuleCorpusRatification1, *, budget: PolicyReadBudget1, **changes: object
) -> RuleCorpusRatification1:
    """Rehash a public candidate while leaving the actual original native bytes untouched."""
    wire = {**value.to_dict(budget=budget), **changes}
    wire.pop("ratification_digest")
    return RuleCorpusRatification1.from_dict(
        {**wire, "ratification_digest": canonical_digest(wire)}, budget=budget
    )


def test_actual_native_three_preimages_and_borrowed_leases_remain_distinct(tmp_path: Path) -> None:
    """Actual escaped Unicode carrier, original capture LF and decoded statement all verify."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        with RuleCorpusNativeOwner(**selected.arguments) as actual:
            assert actual.verify(document, selected.ratification) == selected.pin
            raw = selected.path.read_bytes()
            assert b"\\u013d" in raw and b"SCHVA\xc4\xbdUJEM" not in raw
            statement = rule_corpus_ratification_statement(document, budget=limits)
            assert selected.arguments["reply_capture"] == statement + b"\n"
            assert not statement.endswith(b"\n")
            assert (
                len(
                    {
                        selected.ratification.statement_digest,
                        selected.pin.reply.capture_digest,
                        selected.ratification.statement_span.byte_digest,
                    }
                )
                == 3
            )
            assert (
                selected.ratification.statement_span.byte_digest == selected.pin.reply.line_digest
            )
            assert selected.ratification.statement_span.end_byte == len(raw)
            assert actual.verify(document, selected.ratification) == selected.pin
        actual.close()
        with pytest.raises(ValueError, match="closed"):
            actual.verify(document, selected.ratification)
        assert selected.arguments["transcript"].read() == raw
        assert (
            selected.arguments["metadata"].read().to_dict()
            == PolicySourceRecord1(selected.pin, limits).to_dict()
        )


@pytest.mark.parametrize(
    "fault",
    [
        "statement-capture-hash",
        "statement-line-hash",
        "question-span",
        "wrong-offset",
        "wrong-native-reference",
        "wrong-corpus",
        "wrong-document",
        "wrong-universe",
        "wrong-decisions",
        "wrong-issuer",
    ],
)
def test_exact_native_statement_and_whole_body_relations_refuse_rehashed_candidates(
    tmp_path: Path, fault: str
) -> None:
    """Rehashed metadata cannot swap text/capture/raw line, native issuer or complete subject."""
    document, limits = source_document(), corpus_budget()
    with (
        corpus_native_selection(tmp_path / "native", document, budget=limits) as selected,
        RuleCorpusNativeOwner(**selected.arguments) as actual,
    ):
        native = selected.ratification
        changes: dict[str, object] = {}
        if fault == "statement-capture-hash":
            changes["statement_digest"] = selected.pin.reply.capture_digest
        elif fault == "statement-line-hash":
            changes["statement_digest"] = selected.pin.reply.line_digest
        elif fault in {"question-span", "wrong-offset"}:
            start = 0 if fault == "question-span" else native.statement_span.start_byte + 1
            changes["statement_span"] = SourceSpan1.build(
                span_id="different",
                source_id=selected.pin.source_id,
                start_byte=start,
                end_byte=native.statement_span.end_byte,
                payload=selected.path.read_bytes(),
            ).to_dict()
        elif fault == "wrong-native-reference":
            changes["native_capture"] = TypedObjectRef1.build(
                kind="native-source-pin",
                format_version="native-source-pin.v1",
                object_id=selected.pin.source_id,
                object_digest="b" * 64,
            ).to_dict()
        else:
            field = {
                "wrong-corpus": "corpus_id",
                "wrong-document": "document_digest",
                "wrong-universe": "universe_digest",
                "wrong-decisions": "decision_set_digest",
                "wrong-issuer": "issuer_id",
            }[fault]
            changes[field] = "other" if field in {"issuer_id", "corpus_id"} else "c" * 64
        changed = changed_ratification(native, budget=limits, **changes)
        with pytest.raises((ValueError, PermissionError)):
            actual.verify(document, changed)


@pytest.mark.parametrize(
    "fault",
    [
        "abbreviated-question",
        "user-authored-lf",
        "space",
        "old-reply-time",
        "missing-reply-line",
        "carrier-no-lf",
    ],
)
def test_actual_native_messages_do_not_gain_approval_from_near_matches(
    tmp_path: Path, fault: str
) -> None:
    """Original source integrity can pass while exact full-text, LF or chronology semantics refuse."""
    document, limits = source_document(), corpus_budget()
    question = b"Abbreviated corpus?" if fault == "abbreviated-question" else None
    statement = rule_corpus_ratification_statement(document, budget=limits)
    user = (
        statement + b"\n"
        if fault == "user-authored-lf"
        else statement + b" "
        if fault == "space"
        else None
    )
    with (
        corpus_native_selection(
            tmp_path / "native",
            document,
            budget=limits,
            question_text=question,
            user_text=user,
            reply_time="2026-10-18T11:59:00Z"
            if fault == "old-reply-time"
            else "2026-10-18T12:01:00Z",
            reply_number=100 if fault == "missing-reply-line" else 4,
            final_lf=fault != "carrier-no-lf",
        ) as selected,
        RuleCorpusNativeOwner(**selected.arguments) as actual,
        pytest.raises((ValueError, PermissionError)),
    ):
        actual.verify(document, selected.ratification)


@pytest.mark.parametrize(
    "fault",
    [
        "issuer-binding",
        "scope-binding",
        "wrong-host-pin",
        "revoked",
        "mutable-revocations",
        "oversize-revocations",
        "revocation-digest",
        "source-budget",
        "capture-budget",
        "foreign-metadata-type",
        "foreign-transcript-type",
        "foreign-state-type",
        "foreign-selected-pin",
        "capture-type",
    ],
)
def test_actual_native_owner_requires_whole_selected_host_and_source_contracts(
    tmp_path: Path, fault: str
) -> None:
    """Caller-selected aliases, malformed originals and missing explicit native bounds refuse."""
    document, limits = source_document(), corpus_budget()
    with corpus_native_selection(tmp_path / "native", document, budget=limits) as selected:
        args = selected.arguments.copy()
        state = args["state"]
        if fault == "issuer-binding":
            args["issuer_id"] = "other-issuer"
        elif fault == "scope-binding":
            args["corpus_id"] = "other-corpus"
        elif fault == "wrong-host-pin":
            args["state"] = replace(state, expected_pin_digest="c" * 64)
        elif fault == "revoked":
            args["state"] = replace(
                state, revoked_pin_digests=frozenset({selected.pin.pin_digest})
            )
        elif fault == "mutable-revocations":
            args["state"] = replace(state, revoked_pin_digests=cast(frozenset[str], set()))
        elif fault == "oversize-revocations":
            args["state"] = replace(
                state,
                revoked_pin_digests=frozenset(
                    f"{i:064x}" for i in range(limits.max_references + 1)
                ),
            )
        elif fault == "revocation-digest":
            args["state"] = replace(state, revoked_pin_digests=frozenset({"invalid"}))
        elif fault == "source-budget":
            values = limits.to_dict()
            values.pop("budget_digest")
            values["max_source_bytes"] = 1
            args["budget"] = PolicyReadBudget1.from_dict(
                {**values, "budget_digest": canonical_digest(values)}
            )
        elif fault == "capture-budget":
            args["question_capture"] = b"x" * (limits.max_document_bytes + 1)
        elif fault == "foreign-metadata-type":
            args["metadata"] = cast(RetainedContextSource, "not-a-source")
        elif fault == "foreign-transcript-type":
            args["transcript"] = cast(RetainedPolicySource, "not-a-source")
        elif fault == "foreign-state-type":
            args["state"] = cast(HostNativeSourceState, "not-a-state")
        elif fault == "foreign-selected-pin":
            args["state"] = replace(state, selected_pin=cast(NativeSourcePin, "not-a-pin"))
        else:
            args["reply_capture"] = cast(bytes, "not-byte-capture")
        with pytest.raises((ValueError, PermissionError)):
            RuleCorpusNativeOwner(**args)


def test_complete_question_budget_and_model_type_are_checked(tmp_path: Path) -> None:
    """A complete render exceeding its bound refuses even when the document alone fits."""
    doc = source_document()
    size = len(
        json.dumps(
            doc.to_dict(budget=corpus_budget()),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
    )
    with pytest.raises(ValueError, match="complete corpus question"):
        render_rule_corpus_question(doc, budget=corpus_budget(size=size))
    with pytest.raises(ValueError):
        rule_corpus_ratification_statement(
            cast(RuleSourceDocument1, "not-a-document"), budget=corpus_budget()
        )
    with (
        corpus_native_selection(tmp_path / "native", doc, budget=corpus_budget()) as selected,
        RuleCorpusNativeOwner(**selected.arguments) as actual,
        pytest.raises(ValueError, match="actual corpus ratification"),
    ):
        actual.verify(doc, cast(RuleCorpusRatification1, "not-a-ratification"))


@pytest.mark.parametrize("fault", ["native-bytes", "native-metadata", "revocation-snapshot"])
def test_actual_held_mutation_refuses_and_closes_borrowing_owner(
    tmp_path: Path, fault: str
) -> None:
    """Initial successful real verification cannot hide changed source or held selection at close."""
    doc, limits = source_document(), corpus_budget()
    actual: RuleCorpusNativeOwner | None = None
    with (
        pytest.raises((ValueError, PermissionError)),
        corpus_native_selection(tmp_path / "native", doc, budget=limits) as selected,
    ):
        actual = RuleCorpusNativeOwner(**selected.arguments)
        assert actual.verify(doc, selected.ratification) == selected.pin
        if fault == "native-bytes":
            selected.path.write_bytes(selected.path.read_bytes() + b"changed")
        elif fault == "native-metadata":
            selected.metadata_path.write_bytes(selected.metadata_path.read_bytes() + b" ")
        else:
            object.__setattr__(
                selected.arguments["state"], "revoked_pin_digests", frozenset({"f" * 64})
            )
        try:
            with pytest.raises((ValueError, PermissionError)):
                actual.verify(doc, selected.ratification)
        finally:
            actual.close()
    assert actual is not None
    actual.close()


@pytest.mark.parametrize(
    "fault", ["capture-metadata", "task-metadata", "same-bytes-other-path", "declared-file-hash"]
)
def test_actual_retained_original_source_kinds_paths_and_file_hashes_cannot_be_swapped(
    tmp_path: Path, fault: str
) -> None:
    """Actual valid retained files still must join the selected original native kind, path and hash."""
    doc, limits = source_document(), corpus_budget()
    with ExitStack() as stack:
        selected = stack.enter_context(
            corpus_native_selection(
                tmp_path / "native",
                doc,
                budget=limits,
                declared_file_digest="e" * 64 if fault == "declared-file-hash" else None,
            )
        )
        args = selected.arguments.copy()
        if fault in {"capture-metadata", "task-metadata"}:
            other = stack.enter_context(
                selection(
                    tmp_path / "other", fault="wrong-kind" if fault == "task-metadata" else ""
                )
            )
            args["metadata"] = other.source.metadata
        elif fault == "same-bytes-other-path":
            root = tmp_path / "other-raw"
            root.mkdir()
            alias = root / selected.path.name
            payload = selected.path.read_bytes()
            alias.write_bytes(payload)
            args["transcript"] = stack.enter_context(
                RetainedPolicySource(
                    alias,
                    byte_digest=hashlib.sha256(payload).hexdigest(),
                    byte_count=len(payload),
                    budget=limits,
                )
            )
        with pytest.raises(
            ValueError, match=r"actual original native pin|exact original host pin"
        ):
            RuleCorpusNativeOwner(**args)
