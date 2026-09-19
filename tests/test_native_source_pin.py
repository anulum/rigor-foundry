# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected native source pin tests
"""Keep caller-supplied source bytes separate from host-selected authority."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_native_message_pair import FILENAME, LIMITS, SESSION, _fixture

from rigor_foundry.native_message_pair import NativeMessageSelector, NativeReadLimits
from rigor_foundry.native_source_pin import NativeSourcePin


def _pin(tmp_path: Path) -> tuple[NativeSourcePin, dict[str, object], Path]:
    path, kwargs = _fixture(tmp_path)
    question = kwargs["question"]
    reply = kwargs["reply"]
    assert isinstance(question, NativeMessageSelector)
    assert isinstance(reply, NativeMessageSelector)
    pin = NativeSourcePin.build(
        source_id="owner-decision-2026-09-12",
        root=tmp_path,
        filename=FILENAME,
        session_id=SESSION,
        file_digest=sha256(path.read_bytes()).hexdigest(),
        question=question,
        reply=reply,
        limits=LIMITS,
    )
    return pin, kwargs, path


def test_exact_external_pin_verifies_source_without_promoting_it(tmp_path: Path) -> None:
    """The source digest is not a semantic verdict or an effect permit."""
    pin, kwargs, _ = _pin(tmp_path)
    assert NativeSourcePin.from_dict(pin.to_dict()) == pin
    result = pin.verify_with_host_pin(
        expected_pin_digest=pin.pin_digest,
        question_capture=cast(bytes, kwargs["question_capture"]),
        reply_capture=cast(bytes, kwargs["reply_capture"]),
    )
    assert result["schema_version"] == "native-source-verification.v1"
    assert result["promotable"] is False
    assert result["assertion_class"] == "host-pinned-native-integrity-only"
    assert result["pin_digest"] == pin.pin_digest
    assert isinstance(result["source_verification_digest"], str)


@pytest.mark.parametrize(
    "fault",
    [
        "host-pin",
        "root",
        "filename",
        "session",
        "file-digest",
        "question-id",
        "reply-line",
        "question-capture",
        "reply-capture",
        "file-content",
        "source-id",
        "budget",
    ],
)
def test_changed_source_or_selection_cannot_match_host_pin(tmp_path: Path, fault: str) -> None:
    """Reject pin substitution, selected file drift and retained-text drift."""
    pin, kwargs, path = _pin(tmp_path)
    host_digest = pin.pin_digest
    if fault == "host-pin":
        host_digest = "0" * 64
    elif fault == "root":
        pin = replace(pin, root=tmp_path / "other")
    elif fault == "filename":
        pin = replace(pin, filename="different.jsonl")
    elif fault == "session":
        pin = replace(pin, session_id="different-session")
    elif fault == "file-digest":
        pin = replace(pin, file_digest="0" * 64)
    elif fault == "question-id":
        pin = replace(pin, question=replace(pin.question, message_id="different-message"))
    elif fault == "reply-line":
        pin = replace(pin, reply=replace(pin.reply, line_number=5))
    elif fault == "question-capture":
        kwargs["question_capture"] = b"Changed question.\n"
    elif fault == "reply-capture":
        kwargs["reply_capture"] = b"Changed answer.\n"
    elif fault == "file-content":
        path.write_bytes(path.read_bytes() + b"{}\n")
    elif fault == "source-id":
        pin = replace(pin, source_id="another-source")
    elif fault == "budget":
        pin = replace(pin, limits=NativeReadLimits(2000, 999, 3))
    with pytest.raises((ValueError, OSError)):
        pin.verify_with_host_pin(
            expected_pin_digest=host_digest,
            question_capture=cast(bytes, kwargs["question_capture"]),
            reply_capture=cast(bytes, kwargs["reply_capture"]),
        )


@pytest.mark.parametrize(
    "fault",
    [
        "extra-field",
        "schema",
        "pin-digest",
        "question-extra",
        "line-bool",
        "budget-bool",
        "relative-root",
        "root-alias",
        "filename-traversal",
        "wrong-session-name",
    ],
)
def test_malformed_pin_is_refused(tmp_path: Path, fault: str) -> None:
    """Only exact typed source selections can be compared to a host pin."""
    pin, _, _ = _pin(tmp_path)
    value = pin.to_dict()
    if fault == "extra-field":
        value["grant"] = True
    elif fault == "schema":
        value["schema_version"] = "native-source-pin.v2"
    elif fault == "pin-digest":
        value["pin_digest"] = "0" * 64
    elif fault in {"question-extra", "line-bool"}:
        question = value["question"]
        assert isinstance(question, dict)
        question["grant" if fault == "question-extra" else "line_number"] = True
    elif fault == "budget-bool":
        value["total_bytes"] = True
    elif fault == "relative-root":
        value["root"] = "relative"
    elif fault == "root-alias":
        value["root"] = f"{pin.root}/."
    elif fault == "filename-traversal":
        value["filename"] = "../native.jsonl"
    elif fault == "wrong-session-name":
        value["filename"] = "rollout-other.jsonl"
    with pytest.raises(ValueError):
        NativeSourcePin.from_dict(value)


def test_bad_source_order_or_gap_is_refused(tmp_path: Path) -> None:
    """An oversized or inverted turn gap cannot be a source pin."""
    pin, _, _ = _pin(tmp_path)
    with pytest.raises(ValueError):
        NativeSourcePin.build(
            source_id=pin.source_id,
            root=pin.root,
            filename=pin.filename,
            session_id=pin.session_id,
            file_digest=pin.file_digest,
            question=pin.question,
            reply=replace(pin.reply, line_number=100),
            limits=pin.limits,
        )
    with pytest.raises(ValueError):
        NativeSourcePin.build(
            source_id=pin.source_id,
            root=pin.root,
            filename=pin.filename,
            session_id=pin.session_id,
            file_digest=pin.file_digest,
            question=pin.question,
            reply=replace(pin.reply, line_number=1),
            limits=pin.limits,
        )
