# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact native corpus ratification model tests
"""Exercise new metadata over actual original JSONL references and byte spans."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_rule_corpus_native import corpus_budget, corpus_native_selection
from test_rule_source_document import source_document
from test_typed_object_reference import reference

from rigor_foundry.policy_source_spans import SourceSpan1
from rigor_foundry.rule_corpus_ratification import RuleCorpusRatification1


def test_exact_eleven_fields_roundtrip_and_reference_keep_distinct_preimages(
    tmp_path: Path,
) -> None:
    """The real native line span is not reinterpreted as the decoded statement hash."""
    limits = corpus_budget()
    with corpus_native_selection(
        tmp_path / "native", source_document(), budget=limits
    ) as selected:
        value = selected.ratification
        wire = value.to_dict(budget=limits)
        assert len(wire) == 11
        assert (
            wire["schema_version"] == "1.0" and wire["object_kind"] == "rule-corpus-ratification"
        )
        assert RuleCorpusRatification1.from_dict(wire, budget=limits) == value
        ref = value.reference(budget=limits)
        assert (ref.kind, ref.format_version, ref.object_id, ref.object_digest) == (
            "rule-corpus-ratification",
            "1.0",
            value.corpus_id,
            value.ratification_digest,
        )
        assert value.statement_digest != value.statement_span.byte_digest
        assert value.native_capture == selected.arguments["metadata"].reference


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "native-approval"),
        ("issuer_id", "other"),
        ("document_digest", "b" * 64),
        ("ratification_digest", "c" * 64),
    ],
)
def test_closed_version_and_digest_mutations_refuse(
    tmp_path: Path, field: str, changed: str
) -> None:
    """Declared fields cannot change beneath the complete original metadata digest."""
    limits = corpus_budget()
    with corpus_native_selection(
        tmp_path / "native", source_document(), budget=limits
    ) as selected:
        wire = selected.ratification.to_dict(budget=limits)
        wire[field] = changed
        with pytest.raises(ValueError):
            RuleCorpusRatification1.from_dict(wire, budget=limits)


def test_actual_span_and_native_format_are_required_before_serialization(tmp_path: Path) -> None:
    """Direct objects cannot substitute arbitrary span data or another supported source kind."""
    limits = corpus_budget()
    with corpus_native_selection(
        tmp_path / "native", source_document(), budget=limits
    ) as selected:
        native = selected.ratification
        for invalid in [
            replace(native, statement_span=cast(SourceSpan1, "caller-span")),
            replace(native, native_capture=reference()),
            replace(
                native,
                statement_span=SourceSpan1.build(
                    span_id="other",
                    source_id="other-source",
                    start_byte=0,
                    end_byte=1,
                    payload=b"x",
                ),
            ),
        ]:
            with pytest.raises(ValueError):
                invalid.to_dict(budget=limits)
        wire = native.to_dict(budget=limits)
        with pytest.raises(ValueError):
            RuleCorpusRatification1.from_dict({**wire, "owner": "self"}, budget=limits)
        del wire["statement_digest"]
        with pytest.raises(ValueError):
            RuleCorpusRatification1.from_dict(wire, budget=limits)
        for budget in [corpus_budget(references=1), corpus_budget(size=10)]:
            with pytest.raises(ValueError):
                native.to_dict(budget=budget)
            with pytest.raises(ValueError):
                RuleCorpusRatification1.from_dict(native.to_dict(budget=limits), budget=budget)
