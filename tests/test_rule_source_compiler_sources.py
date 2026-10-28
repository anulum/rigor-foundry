# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete real retained source compilation tests
"""Verify real retained source joins, classification and closing owner lifetimes."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from test_rule_source_compiler import (
    changed_document,
    changed_rule,
    compiled_document,
    rehashed,
    verify,
)
from test_source_universe_owner import owner, universe_selection

from rigor_foundry.policy_source_regions import SourceRegion1
from rigor_foundry.policy_source_spans import SourceSpan1
from rigor_foundry.rule_source_compiler import (
    compile_rule_source_document,
    verify_rule_source_document,
)
from rigor_foundry.rule_source_document import RuleSourceDocument1
from rigor_foundry.semantic_decision import SemanticDecision1
from rigor_foundry.source_universe_owner import SourceUniverseOwner


def test_unknown_region_and_citation_links_cannot_borrow_valid_source_bytes(
    tmp_path: Path,
) -> None:
    """Complete actual byte custody still requires exact source, rule, decision and classification joins."""
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        region = doc.regions[0]
        region_updates: list[dict[str, object]] = [
            {"source_id": "missing"},
            {"rule_ids": ["missing"]},
            {"decision_ids": ["missing"]},
        ]
        for updates in region_updates:
            wrong = SourceRegion1.from_dict(rehashed(region.to_dict(), "region_digest", **updates))
            with pytest.raises(ValueError, match="unresolved source, rule or decision"):
                verify(
                    changed_document(doc, selected, regions=[wrong.to_dict()]),
                    targets,
                    selected,
                    actual,
                )
        span = doc.rules[0].source_spans[0]
        unknown = SourceSpan1.from_dict(
            rehashed(span.to_dict(), "span_digest", source_id="missing")
        )
        wrong_rule = changed_rule(doc, selected, source_spans=[unknown.to_dict()])
        with pytest.raises(ValueError, match="citation has an unresolved source"):
            verify(
                changed_document(
                    doc, selected, rules=[wrong_rule.to_dict(budget=selected.budget)]
                ),
                targets,
                selected,
                actual,
            )
        wrong_rule = changed_rule(doc, selected, classification="public")
        with pytest.raises(ValueError, match="classification would disclose"):
            verify(
                changed_document(
                    doc, selected, rules=[wrong_rule.to_dict(budget=selected.budget)]
                ),
                targets,
                selected,
                actual,
            )
        region_cases: list[tuple[dict[str, object], str]] = [
            ({"rule_ids": ["review-rule"], "decision_ids": []}, "citation lacks"),
            ({"disposition": "context"}, "normative source region"),
        ]
        for updates, pattern in region_cases:
            wrong_region = SourceRegion1.from_dict(
                rehashed(region.to_dict(), "region_digest", **updates)
            )
            with pytest.raises(ValueError, match=pattern):
                verify(
                    changed_document(doc, selected, regions=[wrong_region.to_dict()]),
                    targets,
                    selected,
                    actual,
                )
        raw = selected.actual.path.read_bytes()
        short = SourceSpan1.build(
            span_id=span.span_id, source_id=span.source_id, start_byte=0, end_byte=3, payload=raw
        )
        decision = SemanticDecision1.from_dict(
            rehashed(
                doc.decisions[0].to_dict(budget=selected.budget),
                "decision_digest",
                source_spans=[short.to_dict()],
            ),
            budget=selected.budget,
        )
        with pytest.raises(ValueError, match="span identity has conflicting"):
            verify(
                changed_document(
                    doc, selected, decisions=[decision.to_dict(budget=selected.budget)]
                ),
                targets,
                selected,
                actual,
            )
        wrong_rule = changed_rule(doc, selected, source_spans=[short.to_dict()])
        first = SourceRegion1.build(
            source_id=span.source_id,
            start_byte=0,
            end_byte=3,
            payload=raw,
            disposition="normative",
            rule_ids=("review-rule",),
            decision_ids=("adopt-original",),
            reason_code="declared-first",
        )
        second = SourceRegion1.build(
            source_id=span.source_id,
            start_byte=3,
            end_byte=len(raw),
            payload=raw,
            disposition="context",
            rule_ids=("review-rule",),
            decision_ids=(),
            reason_code="declared-second",
        )
        with pytest.raises(ValueError, match="region relation lacks a matching"):
            verify(
                changed_document(
                    doc,
                    selected,
                    rules=[wrong_rule.to_dict(budget=selected.budget)],
                    regions=[first.to_dict(), second.to_dict()],
                ),
                targets,
                selected,
                actual,
            )


def test_actual_owner_contract_identity_closure_and_source_mutation_are_rechecked(
    tmp_path: Path,
) -> None:
    """A valid detached document does not replace current original source or code custody."""
    from test_policy_model_inputs import budget

    with pytest.raises(ValueError, match="actual original source owner"):
        compile_rule_source_document(
            corpus_id="corpus",
            source_owner=cast(SourceUniverseOwner, {}),
            regions=(),
            rules=(),
            decisions=(),
            qualitative_controls=(),
            review_policies=(),
            legacy_control_bindings=(),
            authority_bindings=(),
            freshness_policies=(),
            targets=(),
            budget=budget(),
        )
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        for wrong_doc, wrong_owner in [
            (cast(RuleSourceDocument1, {}), actual),
            (doc, cast(SourceUniverseOwner, {})),
        ]:
            with pytest.raises(ValueError, match="actual document and original source owner"):
                verify_rule_source_document(
                    wrong_doc, source_owner=wrong_owner, targets=targets, budget=selected.budget
                )
        wrong = changed_document(doc, selected, compiler_contract_digest="f" * 64)
        with pytest.raises(ValueError, match="contract identity differs"):
            verify(wrong, targets, selected, actual)
        with pytest.raises(ValueError, match="complete actual entry cohort"):
            verify(changed_document(doc, selected, universe=[]), targets, selected, actual)
    with (
        pytest.raises(ValueError, match="identity changed"),
        universe_selection(tmp_path / "mutated") as selected,
        owner(selected) as actual,
    ):
        doc, targets = compiled_document(selected, actual)
        selected.actual.path.write_bytes(b"changed original bytes")
        with pytest.raises(ValueError, match="identity changed"):
            verify(doc, targets, selected, actual)
    with universe_selection(tmp_path / "closed") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        actual.close()
        with pytest.raises(ValueError, match="closed"):
            verify(doc, targets, selected, actual)


def test_actual_held_and_excluded_source_dispositions_are_not_byte_read_shortcuts(
    tmp_path: Path,
) -> None:
    """An exact live owner with protected or excluded selections cannot validate old included citations."""
    from dataclasses import replace

    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        for selected_source, pattern in [
            (
                replace(selected.sources[0], read_state="protected", payload=None),
                "outside included verified",
            ),
            (
                replace(
                    selected.sources[0], disposition="excluded", disposition_decision="missing"
                ),
                "unresolved source disposition",
            ),
            (
                replace(
                    selected.sources[0],
                    disposition="excluded",
                    disposition_decision="adopt-original",
                ),
                "lacks an exclusion decision",
            ),
        ]:
            with owner(selected, sources=(selected_source,)) as held:
                candidate = changed_document(
                    doc, selected, universe=[item.to_dict() for item in held.observe()]
                )
                with pytest.raises(ValueError, match=pattern):
                    verify(candidate, targets, selected, held)


def test_complete_source_only_exclusion_keeps_original_universe_without_fabricated_rules(
    tmp_path: Path,
) -> None:
    """Represent exclusion by exact source/region/decision joins, with no artificial rule endpoint."""
    from dataclasses import replace

    with (
        universe_selection(tmp_path / "selected", source_bytes=8) as selected,
        owner(selected) as actual,
    ):
        doc, targets = compiled_document(selected, actual)
        sources = (
            selected.sources[0],
            replace(
                selected.sources[1], disposition="excluded", disposition_decision="exclude-unused"
            ),
        )
        with owner(selected, sources=sources) as excluded:
            entries = excluded.observe()
            decision = SemanticDecision1.from_dict(
                rehashed(
                    doc.decisions[0].to_dict(budget=selected.budget),
                    "decision_digest",
                    decision_id="exclude-unused",
                    relation="exclusion",
                    affected_rule_ids=[],
                    successor_rule_ids=[],
                    authority_proof=entries[0].provenance.to_dict(),
                ),
                budget=selected.budget,
            )
            region = SourceRegion1.from_dict(
                rehashed(
                    doc.regions[0].to_dict(),
                    "region_digest",
                    decision_ids=["adopt-original", "exclude-unused"],
                )
            )
            candidate = changed_document(
                doc,
                selected,
                universe=[entry.to_dict() for entry in entries],
                regions=[region.to_dict()],
                decisions=[
                    doc.decisions[0].to_dict(budget=selected.budget),
                    decision.to_dict(budget=selected.budget),
                ],
            )
            assert verify(candidate, targets, selected, excluded) == ("review-rule",)
            assert len(candidate.universe) == 2 and len(candidate.rules) == 1
            assert not decision.affected_rule_ids and not decision.successor_rule_ids
            assert candidate.universe[1].disposition == "excluded"


def test_half_open_citation_boundaries_do_not_overlap_adjacent_declared_regions(
    tmp_path: Path,
) -> None:
    """An end at another region's start is not a source citation, even with valid original bytes."""
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        raw = selected.actual.path.read_bytes()
        span = SourceSpan1.build(
            span_id="short",
            source_id=doc.universe[0].source_id,
            start_byte=0,
            end_byte=3,
            payload=raw,
        )
        short = changed_rule(doc, selected, source_spans=[span.to_dict()])
        first = SourceRegion1.build(
            source_id=span.source_id,
            start_byte=0,
            end_byte=3,
            payload=raw,
            disposition="context",
            rule_ids=(),
            decision_ids=("adopt-original",),
            reason_code="declared-context",
        )
        second = SourceRegion1.build(
            source_id=span.source_id,
            start_byte=3,
            end_byte=len(raw),
            payload=raw,
            disposition="normative",
            rule_ids=("review-rule",),
            decision_ids=(),
            reason_code="declared-normative",
        )
        with pytest.raises(ValueError, match="citation lacks its exact"):
            verify(
                changed_document(
                    doc,
                    selected,
                    rules=[short.to_dict(budget=selected.budget)],
                    regions=[first.to_dict(), second.to_dict()],
                ),
                targets,
                selected,
                actual,
            )
