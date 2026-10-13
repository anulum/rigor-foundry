# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — accepted semantic source matching
"""Match one signed acceptance body to exact proposal links and source spans."""

from __future__ import annotations

from hashlib import sha256
from typing import Final

from .model_primitives import require_digest
from .models import canonical_digest
from .semantic_transition import SemanticTransitionProposal
from .semantic_transition_acceptance_v2 import SemanticAcceptanceBodyV2

ACCEPTED_SOURCE_PROOF_SCHEMA: Final = "accepted-semantic-source-match.v1"


def match_accepted_semantic_source(
    proposal: SemanticTransitionProposal,
    acceptance: SemanticAcceptanceBodyV2,
    *,
    normative_source: bytes,
) -> dict[str, object]:
    """Check four exact changed-meaning links against LF-terminated source bytes.

    This is an integrity relation only. The caller must independently verify
    the reviewer signature, protected host selection, owner ratification and
    source receipt before an accepted transition may enter a signed pack.

    Parameters
    ----------
    proposal : SemanticTransitionProposal
        Exact unchanged four-successor proposal.
    acceptance : SemanticAcceptanceBodyV2
        Reviewer-signed body, parsed before this relation is checked.
    normative_source : bytes
        Exact source file selected by the protected host.

    Returns
    -------
    dict[str, object]
        Non-admissible relation proof with a canonical digest.

    Raises
    ------
    ValueError
        If the source is malformed or the proposal is not exact.
    PermissionError
        If any accepted link, statement or source hash differs.
    """
    parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
    body = SemanticAcceptanceBodyV2.from_dict(acceptance.to_dict()).to_dict()
    if not isinstance(normative_source, bytes) or not normative_source.endswith(b"\n"):
        raise ValueError("normative source must be LF-terminated bytes")
    lines = normative_source.splitlines(keepends=True)
    if any(not line.endswith(b"\n") or line.endswith(b"\r\n") for line in lines):
        raise ValueError("normative source line endings differ")
    if len(parsed.replacements) != 4:
        raise ValueError("accepted semantic source requires four proposal links")
    expected_links: list[dict[str, str]] = []
    for item in parsed.replacements:
        if item.last_line > len(lines):
            raise ValueError("proposal source span is outside the selected file")
        span = b"".join(lines[item.first_line - 1 : item.last_line])
        digest = sha256(span).hexdigest()
        if digest != item.statement_digest:
            raise PermissionError("proposal statement differs from selected source")
        expected_links.append(
            {
                "predecessor_id": item.predecessor_id,
                "successor_id": item.successor_id,
                "statement_sha256": digest,
            }
        )
    source_digest = sha256(normative_source).hexdigest()
    if (
        body["proposal_digest"] != parsed.proposal_digest
        or body["parent_replay_digest"] != parsed.parent_replay_digest
        or body["normative_source_sha256"] != source_digest
        or body["replacements"] != expected_links
        or body["statement_sha256"] != [item["statement_sha256"] for item in expected_links]
    ):
        raise PermissionError("accepted semantic source differs from proposal")
    proof: dict[str, object] = {
        "schema_version": ACCEPTED_SOURCE_PROOF_SCHEMA,
        "assertion_class": "accepted-source-integrity-only",
        "guard_admissible": False,
        "proposal_digest": parsed.proposal_digest,
        "acceptance_body_digest": acceptance.payload_digest,
        "normative_source_sha256": require_digest(source_digest, "accepted_source.sha256"),
        "statement_sha256": [item["statement_sha256"] for item in expected_links],
    }
    return {**proof, "proof_digest": canonical_digest(proof)}
