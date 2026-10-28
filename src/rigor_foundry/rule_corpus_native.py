# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained native corpus statement owner
"""Join a full corpus question and exact statement to one independently selected native source."""

from __future__ import annotations

import hashlib
import json
from types import TracebackType

from .audit_primitives import canonical_digest
from .context_source_lease import RetainedContextSource
from .model_primitives import parse_utc_timestamp, require_digest, require_identifier
from .native_source_host import HostNativeSourceState
from .native_source_pin import NativeSourcePin
from .policy_model_inputs import checked_policy_budget, policy_reference
from .policy_read_budget import PolicyReadBudget1
from .policy_source_records import PolicySourceRecord1
from .retained_policy_source import RetainedPolicySource
from .rule_corpus_acceptance import rule_corpus_document_digests
from .rule_corpus_ratification import RuleCorpusRatification1
from .rule_source_document import RuleSourceDocument1
from .typed_object_reference import TypedObjectRef1

_NATIVE_FORMATS = frozenset({("native-source-pin", "native-source-pin.v1")})


def rule_corpus_native_binding_digest(
    *,
    issuer_id: str,
    corpus_id: str,
    native_capture: TypedObjectRef1,
) -> str:
    """Identify one explicit issuer/corpus/original-native selection, without installing it.

    Parameters
    ----------
    issuer_id, corpus_id : str
        Exact issuer and corpus scope chosen by trusted host configuration.
    native_capture : TypedObjectRef1
        Actual original native pin identity, including its complete digest.

    Returns
    -------
    str
        Canonical binding identity. The independently expected digest must come
        from protected installed host selection, never the request itself.
    """
    native = policy_reference(native_capture, allowed=_NATIVE_FORMATS)
    return canonical_digest(
        {
            "contract": "rigor-foundry.rule-corpus-native-issuer-binding.v1",
            "issuer_id": require_identifier(issuer_id, "native corpus issuer"),
            "corpus_id": require_identifier(corpus_id, "native corpus scope"),
            "native_capture": native.to_dict(),
        }
    )


def rule_corpus_ratification_statement(
    document: RuleSourceDocument1,
    *,
    budget: PolicyReadBudget1,
) -> bytes:
    """Render the exact required user text without the native capture owner's LF.

    Parameters
    ----------
    document : RuleSourceDocument1
        Complete actual bounded corpus declaration.
    budget : PolicyReadBudget1
        Explicit document allocation limits.

    Returns
    -------
    bytes
        Exact UTF8 approval line binding corpus, document, universe and decisions.
        Rendering neither sends a message nor supplies native issuer authority.
    """
    binding = rule_corpus_document_digests(document, budget=budget)
    return (
        f"SCHVAĽUJEM rule-corpus {binding['corpus_id']} {binding['document_digest']} "
        f"{binding['universe_digest']} {binding['decision_set_digest']}"
    ).encode()


def render_rule_corpus_question(
    document: RuleSourceDocument1,
    *,
    budget: PolicyReadBudget1,
) -> bytes:
    """Render the complete corpus and exact decision line for an explicitly authorized read.

    Parameters
    ----------
    document : RuleSourceDocument1
        Entire actual declaration, including all dispositions and original arrays.
        Its classification/read authorization belongs to the installed caller.
    budget : PolicyReadBudget1
        Explicit bound for the entire rendered question, including prose.

    Returns
    -------
    bytes
        Exact decoded assistant text, without the original capture owner's
        appended LF. Interior newlines are retained; the final text byte is the
        decision line's last character. No history is fetched or sent.

    Raises
    ------
    ValueError
        The document or complete rendering exceeds its explicit original budget.
    """
    limits = checked_policy_budget(budget)
    statement = rule_corpus_ratification_statement(document, budget=limits)
    wire = document.to_dict(budget=limits)
    complete = json.dumps(
        wire, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    result = (
        b"Do you ratify this exact complete rule corpus and its extraction/dispositions?\n"
        + complete
        + b"\nReply with this exact decision line:\n"
        + statement
    )
    if len(result) + 1 > limits.max_document_bytes:
        raise ValueError("complete corpus question exceeds the document byte budget")
    return result


def _line_bounds(payload: bytes, number: int) -> tuple[int, int]:
    """Locate one actual original LF-terminated JSONL line without copying a line array."""
    start = 0
    for _ in range(1, number):
        end = payload.find(b"\n", start)
        if end < 0:
            raise ValueError("selected native reply line is absent")
        start = end + 1
    end = payload.find(b"\n", start)
    if end < 0:
        raise ValueError("selected native reply line lacks LF")
    return start, end + 1


class RuleCorpusNativeOwner:
    """Borrow actual original leases and one already-held host native/issuer selection.

    Parameters
    ----------
    metadata : RetainedContextSource
        Original retained NativeSourcePin metadata, resolved by its fixed owner.
    transcript : RetainedPolicySource
        Actual held complete native JSONL bytes, not extracted plaintext.
    state : HostNativeSourceState
        Original host pin/revocation snapshot already held by the outer host.
    issuer_id, corpus_id, expected_issuer_binding_digest : str
        Independently installed issuer/scope/source binding and protected digest.
        Caller-picked values authenticate no issuer or host selection.
    question_capture, reply_capture : bytes
        Original selected plaintext captures, each with its owner's final LF.
    budget : PolicyReadBudget1
        Explicit native and complete-document processing limits.

    Notes
    -----
    No wire/parser/CLI installs this owner, its state or an issuer. Trusted host
    composition must independently authenticate/protect the issuer binding and
    hold the original selection/revocation snapshot through use and close. The
    original native role markers establish no issuer competence by themselves.
    Closing revalidates borrowed resources and never closes their owning leases.
    """

    def __init__(
        self,
        *,
        metadata: RetainedContextSource,
        transcript: RetainedPolicySource,
        state: HostNativeSourceState,
        issuer_id: str,
        corpus_id: str,
        expected_issuer_binding_digest: str,
        question_capture: bytes,
        reply_capture: bytes,
        budget: PolicyReadBudget1,
    ) -> None:
        """Retain only actual original source objects and explicit selected identities."""
        self._budget = checked_policy_budget(budget)
        if (
            type(metadata) is not RetainedContextSource
            or type(transcript) is not RetainedPolicySource
        ):
            raise ValueError("corpus native owner requires actual original retained sources")
        if type(state) is not HostNativeSourceState:
            raise ValueError("corpus native owner requires an already-held original host state")
        if type(question_capture) is not bytes or type(reply_capture) is not bytes:
            raise ValueError("corpus native owner requires actual original byte captures")
        if max(len(question_capture), len(reply_capture)) > self._budget.max_document_bytes:
            raise ValueError("native captures exceed the document byte budget")
        self._metadata, self._transcript, self._state = metadata, transcript, state
        self._issuer = require_identifier(issuer_id, "native corpus issuer")
        self._corpus = require_identifier(corpus_id, "native corpus scope")
        self._expected = require_digest(
            expected_issuer_binding_digest, "selected corpus issuer binding"
        )
        self._question, self._reply = question_capture, reply_capture
        self._closed = False
        self._initial = self._read()[2]

    def _read(self) -> tuple[NativeSourcePin, bytes, str]:
        """Revalidate actual metadata, bytes, scope and the whole original host snapshot."""
        if self._closed:
            raise ValueError("corpus native owner is closed")
        record = self._metadata.read()
        if type(record) is not PolicySourceRecord1 or type(record.record) is not NativeSourcePin:
            raise ValueError("corpus native metadata must retain an actual original native pin")
        pin = NativeSourcePin.from_dict(record.record.to_dict())
        native_ref = TypedObjectRef1.from_dict(record.reference())
        state = self._state
        if (
            type(state.selected_pin) is not NativeSourcePin
            or type(state.revoked_pin_digests) is not frozenset
        ):
            raise ValueError("actual immutable original native host snapshot is required")
        if len(state.revoked_pin_digests) > self._budget.max_references:
            raise ValueError("native revocation snapshot exceeds the reference budget")
        revoked = sorted(
            require_digest(item, "revoked native pin") for item in state.revoked_pin_digests
        )
        expected_pin = require_digest(state.expected_pin_digest, "selected native pin")
        if expected_pin in state.revoked_pin_digests:
            raise PermissionError("selected native corpus source is revoked")
        if (
            pin != NativeSourcePin.from_dict(state.selected_pin.to_dict())
            or pin.pin_digest != expected_pin
        ):
            raise PermissionError("native corpus source differs from the held host selection")
        if (
            pin.limits.total_bytes > self._budget.max_source_bytes
            or pin.limits.intervening_lines > self._budget.max_references
        ):
            raise ValueError("original native processing limits exceed the corpus budget")
        binding = rule_corpus_native_binding_digest(
            issuer_id=self._issuer, corpus_id=self._corpus, native_capture=native_ref
        )
        if binding != self._expected:
            raise PermissionError("native issuer/corpus/source differs from installed selection")
        payload = self._transcript.read()
        if (
            self._transcript.path != pin.root / pin.filename
            or hashlib.sha256(payload).hexdigest() != pin.file_digest
        ):
            raise ValueError("retained native bytes differ from the exact original host pin")
        snapshot = canonical_digest(
            {
                "issuer_binding": self._expected,
                "native_pin": expected_pin,
                "revoked_pins": revoked,
                "metadata": self._metadata.snapshot_id,
                "transcript": self._transcript.snapshot_id,
                "question": hashlib.sha256(self._question).hexdigest(),
                "reply": hashlib.sha256(self._reply).hexdigest(),
            }
        )
        return pin, payload, snapshot

    def _check(self) -> tuple[NativeSourcePin, bytes]:
        """Refuse any changed whole snapshot or original retained source lifetime."""
        pin, payload, snapshot = self._read()
        if snapshot != self._initial:
            raise PermissionError("native corpus selection changed during its retained lifetime")
        return pin, payload

    def verify(
        self,
        document: RuleSourceDocument1,
        ratification: RuleCorpusRatification1,
    ) -> NativeSourcePin:
        """Verify complete question, actual issuer selection and all three statement preimages.

        Parameters
        ----------
        document : RuleSourceDocument1
            Entire exact corpus; its source compiler verification is separate.
        ratification : RuleCorpusRatification1
            Actual record binding this corpus to the selected original native pin.

        Returns
        -------
        NativeSourcePin
            Exact verified original pin for the same held source-independence
            check. It remains source metadata, not a selected policy or grant.

        Raises
        ------
        ValueError, PermissionError, OSError
            The source, scope, chronology, complete text, raw coordinates, native
            identity, revocation snapshot or closing retained check differs.
        """
        pin, payload = self._check()
        if type(ratification) is not RuleCorpusRatification1:
            raise ValueError("actual corpus ratification is required")
        native = RuleCorpusRatification1.from_dict(
            ratification.to_dict(budget=self._budget), budget=self._budget
        )
        binding = rule_corpus_document_digests(document, budget=self._budget)
        if self._corpus != binding["corpus_id"] or native.issuer_id != self._issuer:
            raise PermissionError("ratification issuer or corpus is outside installed scope")
        if any(
            getattr(native, name) != binding[name]
            for name in ("corpus_id", "document_digest", "universe_digest", "decision_set_digest")
        ):
            raise ValueError("native ratification does not bind the actual full corpus")
        if native.native_capture != self._metadata.reference:
            raise ValueError("ratification references a different original native source")
        statement = rule_corpus_ratification_statement(document, budget=self._budget)
        if (
            self._question != render_rule_corpus_question(document, budget=self._budget) + b"\n"
            or self._reply != statement + b"\n"
        ):
            raise PermissionError(
                "actual native question or reply does not ratify the complete corpus"
            )
        if parse_utc_timestamp(pin.reply.timestamp, "native reply") <= parse_utc_timestamp(
            pin.question.timestamp, "native question"
        ):
            raise PermissionError("native corpus reply is not later than its exact question")
        start, end = _line_bounds(payload, pin.reply.line_number)
        span = native.statement_span
        if (span.source_id, span.start_byte, span.end_byte, span.byte_digest) != (
            pin.source_id,
            start,
            end,
            pin.reply.line_digest,
        ):
            raise ValueError(
                "ratification span is not the selected original user-message JSONL line"
            )
        span.verify(payload)
        if native.statement_digest != hashlib.sha256(statement).hexdigest():
            raise ValueError("ratification statement digest differs from exact decoded UTF8 text")
        pin.verify_with_host_pin(
            expected_pin_digest=self._state.expected_pin_digest,
            question_capture=self._question,
            reply_capture=self._reply,
        )
        self._check()
        return pin

    def close(self) -> None:
        """Recheck the actual entire selection and close only this borrowing owner."""
        if self._closed:
            return
        try:
            self._check()
        finally:
            self._closed = True

    def __enter__(self) -> RuleCorpusNativeOwner:
        """Verify the retained source selection before exposing its borrowing owner."""
        self._check()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Recheck original native custody without suppressing a consumer failure."""
        self.close()
