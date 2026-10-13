# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — clause-semantics owner ratification
"""Require an exact rendered set and a later native owner digest response."""

from __future__ import annotations

import unicodedata
from datetime import datetime
from pathlib import Path
from typing import cast

from .clause_semantics_set_v2 import ClauseSemanticsSetV2
from .discovery_source_schema import parse_json
from .models import canonical_digest, require_mapping
from .semantic_ratification_source import verify_full_text_ratification_source


def render_clause_semantics_question_v2(body: ClauseSemanticsSetV2) -> bytes:
    """Render the complete canonical set and exact digest approval line.

    Parameters
    ----------
    body : ClauseSemanticsSetV2
        Canonical semantics set whose full entries, edges and exclusions are presented to the owner.

    Returns
    -------
    bytes
        UTF-8 question containing the full body, veto warnings and exact decision line.

    Raises
    ------
    ValueError
        The supplied object differs from its canonical bytes.
    """
    exact = ClauseSemanticsSetV2.from_bytes(body.body_bytes)
    if exact != body:
        raise ValueError("clause semantics body differs from canonical bytes")
    parsed = body.to_dict()
    entries = cast(list[dict[str, object]], parsed["entries"])
    narrowed_vetoes = [
        cast(str, entry["clause_digest"])
        for entry in entries
        if entry["subject"] == "veto" and cast(dict[str, object], entry["scope"])["exclusions"]
    ]
    warnings = "".join(f"Veto {digest}: exclusions narrow a veto.\n" for digest in narrowed_vetoes)
    return (
        "Do you ratify this exact clause-semantics set?\n"
        f"Body SHA-256: {body.body_digest}\n"
        "Every entry, supersession edge, veto exclusion and failed-completion marker follows:\n"
        + body.body_bytes.decode("utf-8")
        + "\n"
        + warnings
        + "Copy only this exact decision line as your reply:\n"
        + f"SCHVAĽUJEM clause-semantics-set {body.body_digest}\n"
    ).encode("utf-8")


def verify_clause_semantics_ratification_v2(
    *,
    body: ClauseSemanticsSetV2,
    manifest_bytes: bytes,
    question_capture: bytes,
    reply_capture: bytes,
    transcript_path: Path,
    expected_manifest_sha256: str,
    expected_question_sha256: str,
    expected_reply_sha256: str,
) -> dict[str, object]:
    """Bind rendered semantics to a later exact native human decision.

    Parameters
    ----------
    body : ClauseSemanticsSetV2
        Exact canonical semantics set to ratify.
    manifest_bytes : bytes
        Bounded native capture manifest selected by the host.
    question_capture : bytes
        Exact bytes of the fully rendered question.
    reply_capture : bytes
        Exact owner approval bytes; NFC and surrounding ASCII whitespace are normalized.
    transcript_path : Path
        Host-selected original native JSONL source opened without following links.
    expected_manifest_sha256 : str
        Protected SHA-256 precondition for the manifest.
    expected_question_sha256 : str
        Protected SHA-256 precondition for the question capture.
    expected_reply_sha256 : str
        Protected SHA-256 precondition for the reply capture.

    Returns
    -------
    dict[str, object]
        Digest-bound native ratification dependency with guard_admissible false.

    Raises
    ------
    ValueError
        Native manifest, capture, lineage, human-origin or source identity validation fails.
    PermissionError
        The question, chronology or exact semantics approval differs.
    OSError
        Original native source cannot be safely opened or inspected.

    Notes
    -----
    The source verifier authenticates integrity of selected bytes, not the owner of an arbitrary
    caller-supplied transcript or the accuracy of declared capture clocks.
    """
    integrity = verify_full_text_ratification_source(
        manifest_bytes=manifest_bytes,
        question_capture=question_capture,
        reply_capture=reply_capture,
        transcript_path=transcript_path,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_question_sha256=expected_question_sha256,
        expected_reply_sha256=expected_reply_sha256,
    )
    exact_question = render_clause_semantics_question_v2(body)
    if question_capture != exact_question:
        raise PermissionError("owner question does not render the exact semantics set")
    manifest = require_mapping(parse_json(manifest_bytes), "ratification manifest")
    captures = require_mapping(manifest["captures"], "ratification captures")
    question = require_mapping(captures["CEO_QUESTION_FULL_TEXT.txt"], "ratification question")
    reply = require_mapping(captures["OWNER_REPLY.txt"], "ratification reply")
    question_at = datetime.fromisoformat(cast(str, question["timestamp"]))
    reply_at = datetime.fromisoformat(cast(str, reply["timestamp"]))
    if reply_at <= question_at:
        raise PermissionError("owner reply is not later than the question")
    reply_text = reply_capture.decode("utf-8")
    normalized = unicodedata.normalize("NFC", reply_text).strip(" \t\n\r")
    expected = unicodedata.normalize("NFC", f"SCHVAĽUJEM clause-semantics-set {body.body_digest}")
    if normalized.encode("utf-8") != expected.encode("utf-8"):
        raise PermissionError("owner reply is not the exact semantics approval")
    proof: dict[str, object] = {
        "schema": "rigor.clause-semantics-ratification.v2",
        "assertion_class": "native-owner-ratification-dependency-only",
        "guard_admissible": False,
        "semantics_set_digest": body.body_digest,
        "source_proof_digest": integrity["proof_digest"],
    }
    return {**proof, "proof_digest": canonical_digest(proof)}
