# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed-vulnerability advisory tests
"""Verify append-only advisory evidence without publication authority."""

from __future__ import annotations

from dataclasses import replace

import pytest

from rigor_foundry.cra_advisories import (
    FixedVulnerabilityAdvisory,
    validate_advisory_successor,
)

DIGEST = "a" * 64


def advisory(**changes: object) -> FixedVulnerabilityAdvisory:
    """Return one strict draft fixture."""
    values: dict[str, object] = {
        "product_key": "widget",
        "event_key": "EVENT-1",
        "revision_digest": DIGEST,
        "state": "draft",
        "security_update_ref": "release/v1.2.3",
        "advisory_path": "SECURITY/ADV-1.md",
        "advisory_sha256": "c" * 64,
        "drafted_at": "2026-07-20T00:00:00Z",
    }
    values.update(changes)
    return FixedVulnerabilityAdvisory.build(**values)  # type: ignore[arg-type]


def test_advisory_round_trip_and_monotonic_successors() -> None:
    """Draft, delay, and publication revisions preserve immutable identity."""
    draft = advisory()
    assert FixedVulnerabilityAdvisory.from_dict(draft.to_dict()) == draft
    assert draft.to_json().endswith("\n")
    delayed = advisory(
        state="justified-delay",
        delay_reason="Coordinated release review is incomplete.",
        delay_review_at="2026-07-27T00:00:00Z",
        delay_evidence_path="evidence/delay.txt",
        delay_evidence_sha256="d" * 64,
        previous_advisory_digest=draft.advisory_digest,
    )
    validate_advisory_successor(draft, delayed)
    published = advisory(
        revision_digest="b" * 64,
        state="published",
        published_at="2026-07-21T00:00:00Z",
        publication_evidence_path="evidence/publication.txt",
        publication_evidence_sha256="e" * 64,
        previous_advisory_digest=delayed.advisory_digest,
    )
    validate_advisory_successor(delayed, published)


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"state": "unknown"}, "unsupported"),
        ({"published_at": "2026-07-21T00:00:00Z"}, "draft advisory"),
        ({"state": "published"}, "requires time"),
        (
            {
                "state": "published",
                "published_at": "2026-07-21T00:00:00Z",
                "publication_evidence_path": "evidence/publication.txt",
                "publication_evidence_sha256": "e" * 64,
                "delay_reason": "x",
            },
            "requires time",
        ),
        (
            {
                "state": "justified-delay",
                "delay_reason": "x",
                "delay_review_at": "2026-07-27T00:00:00Z",
                "delay_evidence_path": "evidence/delay.txt",
            },
            "requires reason",
        ),
        (
            {
                "state": "published",
                "published_at": "2026-07-19T00:00:00Z",
                "publication_evidence_path": "evidence/publication.txt",
                "publication_evidence_sha256": "e" * 64,
            },
            "must not precede",
        ),
        (
            {
                "state": "justified-delay",
                "delay_reason": "x",
                "delay_review_at": "2026-07-20T00:00:00Z",
                "delay_evidence_path": "evidence/delay.txt",
                "delay_evidence_sha256": "d" * 64,
            },
            "must be after",
        ),
        ({"previous_advisory_digest": "bad"}, "digest"),
        ({"advisory_path": "../escape"}, "repository-relative"),
    ],
)
def test_advisory_rejects_contradictory_states(changes: dict[str, object], message: str) -> None:
    """Every impossible state/field relation fails closed."""
    with pytest.raises(ValueError, match=message):
        advisory(**changes)


def test_advisory_parser_and_successor_reject_tampering() -> None:
    """Digest mutation and non-monotonic transitions cannot replay."""
    draft = advisory()
    tampered = draft.to_dict()
    tampered["security_update_ref"] = "release/forged"
    with pytest.raises(ValueError, match="digest"):
        FixedVulnerabilityAdvisory.from_dict(tampered)
    malformed = draft.to_dict()
    malformed["extra"] = True
    with pytest.raises(ValueError, match="fields"):
        FixedVulnerabilityAdvisory.from_dict(malformed)
    wrong_schema = draft.to_dict()
    wrong_schema["schema_version"] = "9.0"
    with pytest.raises(ValueError, match="schema_version"):
        FixedVulnerabilityAdvisory.from_dict(wrong_schema)

    published = advisory(
        state="published",
        published_at="2026-07-21T00:00:00Z",
        publication_evidence_path="evidence/publication.txt",
        publication_evidence_sha256="e" * 64,
        previous_advisory_digest=draft.advisory_digest,
    )
    variants = (
        replace(published, previous_advisory_digest="b" * 64),
        replace(published, advisory_path="SECURITY/OTHER.md"),
        replace(published, state="draft", published_at=None),
    )
    for invalid in variants:
        with pytest.raises(ValueError):
            validate_advisory_successor(draft, invalid)
    with pytest.raises(ValueError, match="transition"):
        validate_advisory_successor(
            published,
            replace(published, previous_advisory_digest=published.advisory_digest),
        )
