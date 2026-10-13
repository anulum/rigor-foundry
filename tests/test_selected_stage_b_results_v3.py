# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared selected Stage B result tests
"""Exercise the shared actual selected-stage evaluator and its authority source fences."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from selected_applicability_support import applicability_fixture

from rigor_foundry.constraint_evaluators_v2 import EvaluatorContextV2, PreconditionContextV2
from rigor_foundry.selected_dispatch_extraction_v2 import (
    ExtractedDispatchPartV2,
    SelectedDispatchExtractionV2,
    extract_selected_dispatch_request_v2,
)
from rigor_foundry.selected_stage_b_results_v3 import (
    derive_selected_stage_b_pins_v3,
    evaluate_selected_stage_b_results_v3,
)


@pytest.mark.parametrize("case", ["carrier", "list", "empty", "part-type", "part-order"])
def test_actual_extraction_shape_refusals(tmp_path: Path, case: str) -> None:
    """Malformed classifiers cannot omit, reorder or replace actual result parts."""
    with applicability_fixture(tmp_path) as fixture:
        selected = fixture
        extraction = extract_selected_dispatch_request_v2(
            fixture.request,
            selected_chain=selected.chain,
            chain_proof=selected.chain_proof,
            selected_semantics=selected.semantics,
            semantics_proof=selected.semantics_proof,
            observed_lock_digest=selected.chain_proof.lock_digest,
            observed_projection_digest=selected.chain_proof.rule_projection_digest,
        )
        if case == "carrier":
            extraction = cast(SelectedDispatchExtractionV2, None)
        elif case == "list":
            extraction = replace(
                extraction, parts=cast(tuple[ExtractedDispatchPartV2, ...], list(extraction.parts))
            )
        elif case == "empty":
            extraction = replace(extraction, parts=())
        elif case == "part-type":
            extraction = replace(
                extraction, parts=cast(tuple[ExtractedDispatchPartV2, ...], (None,))
            )
        else:
            extraction = replace(extraction, parts=(replace(extraction.parts[0], part_index=1),))
        with pytest.raises(ValueError, match="complete exact ordered"):
            evaluate_selected_stage_b_results_v3(
                extraction,
                semantics=selected.semantics,
                semantics_proof=selected.semantics_proof,
                context_for=fixture.context_for,
            )


@pytest.mark.parametrize("case", ["missing-original", "wrong-digest", "missing-binding"])
def test_expected_authority_requires_its_actual_original_and_binding(
    tmp_path: Path, case: str
) -> None:
    """Parsed expected digests cannot replace the selected requirement's exact signed relation."""
    evidence = tmp_path / "cooperative-verification"
    evidence.write_text("passed")

    def installed(_digest: str, _subject: str) -> EvaluatorContextV2:
        """Read ordinary real fixture evidence without claiming an enforced physical check."""
        actual = evidence.read_bytes()
        return PreconditionContextV2(
            "verify-passed", actual == b"passed", sha256(actual).hexdigest(), "cooperative"
        )

    with applicability_fixture(tmp_path, subject="precondition", context_for=installed) as fixture:
        selected = fixture
        extraction = extract_selected_dispatch_request_v2(
            fixture.request,
            selected_chain=selected.chain,
            chain_proof=selected.chain_proof,
            selected_semantics=selected.semantics,
            semantics_proof=selected.semantics_proof,
            observed_lock_digest=selected.chain_proof.lock_digest,
            observed_projection_digest=selected.chain_proof.rule_projection_digest,
        )
        semantics, proof = selected.semantics, selected.semantics_proof
        if case == "missing-original":
            semantics = replace(semantics, authority_requirement=None)
        elif case == "wrong-digest":
            semantics = replace(semantics, expected_authority_requirement_digest="b" * 64)
        else:
            proof = replace(
                proof, binding=replace(proof.binding, authority_requirement_digest=None)
            )
        with pytest.raises(PermissionError, match="not source-bound"):
            derive_selected_stage_b_pins_v3(
                selected.chain, extraction, semantics=semantics, semantics_proof=proof
            )


@pytest.mark.parametrize("subject", ["admit", "precondition"])
def test_actual_selected_pins_retain_optional_native_bound_requirement(
    tmp_path: Path, subject: str
) -> None:
    """The public pin consumer returns exact sources and only a genuinely selected requirement."""
    with applicability_fixture(tmp_path, subject=subject) as fixture:
        extraction = extract_selected_dispatch_request_v2(
            fixture.request,
            selected_chain=fixture.chain,
            chain_proof=fixture.chain_proof,
            selected_semantics=fixture.semantics,
            semantics_proof=fixture.semantics_proof,
            observed_lock_digest=fixture.chain_proof.lock_digest,
            observed_projection_digest=fixture.chain_proof.rule_projection_digest,
        )
        pins = derive_selected_stage_b_pins_v3(
            fixture.chain,
            extraction,
            semantics=fixture.semantics,
            semantics_proof=fixture.semantics_proof,
        )
        assert pins == {
            "expected_effect_vocabulary_digest": fixture.chain.effect_vocabulary.vocabulary_digest,
            "expected_effect_target_table_digest": fixture.chain.effect_target_table.table_digest,
            "expected_effect_operations_digest": fixture.chain.effect_operations.operations_digest,
            "extractor_registry_digest": fixture.chain.extractor_registry.registry_digest,
            "expected_evaluator_registry_digest": fixture.semantics.evaluator_registry.registry_digest,
            "expected_semantics_set_digest": fixture.semantics.signed.body.body_digest,
            "expected_resolver_version": fixture.semantics.expected_resolver_version,
            **(
                {
                    "expected_authority_requirement_digest": fixture.semantics.authority_requirement.requirement_digest
                }
                if fixture.semantics.authority_requirement is not None
                else {}
            ),
        }
        assert ("expected_authority_requirement_digest" in pins) == (subject == "precondition")
