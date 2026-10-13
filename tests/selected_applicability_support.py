# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual selected applicability fixture custody
"""Retain signed fixture sources without depending on future admission producers."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from test_clause_semantics_set_v2 import _entry
from test_owner_confirmation_v2 import _native
from test_selected_clause_semantics_host_v2 import _state

from rigor_foundry.constraint_evaluators_v2 import EvaluatorContextV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.instruction_dispatch import DispatchRequest
from rigor_foundry.instruction_scope import ActionScope
from rigor_foundry.selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    HostSelectedClauseSemanticsVerifierV2,
    SelectedClauseSemanticsProofV2,
)
from rigor_foundry.selected_dispatch_applicability_v2 import (
    SelectedDispatchApplicabilityV2,
    evaluate_selected_dispatch_applicability_v2,
)
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    SelectedRuleChainProofV2,
)


def no_constraint(_digest: str, _subject: str) -> EvaluatorContextV2:
    """Reject an unexpected context request from a signed all-admit fixture."""
    raise AssertionError("all-admit fixture requested a constraint context")


@dataclass(frozen=True)
class ApplicabilityFixture:
    """Actual signed fixture selection and physical invocation, without effect authority.

    Attributes
    ----------
    chain, chain_proof
        Source state and proof retained by the public verified context.
    semantics, semantics_proof
        Matching signed clauses and actual native-fixture capture integrity.
    target
        Existing ordinary file below the fixture's selected project directory.
    request
        Immutable atomic-replace invocation; the evaluator must leave its target unchanged.
    verifier
        Cooperative fixture source provider, not a protected installed host.
    context_for
        Ordinary installed fixture evidence reader for constraint evaluation.
    """

    chain: HostSelectedRuleChainStateV2
    chain_proof: SelectedRuleChainProofV2
    semantics: HostSelectedClauseSemanticsStateV2
    semantics_proof: SelectedClauseSemanticsProofV2
    target: Path
    request: DispatchRequest
    verifier: HostSelectedClauseSemanticsVerifierV2
    context_for: Callable[[str, str], EvaluatorContextV2]


@contextmanager
def applicability_fixture(
    root: Path,
    *,
    subject: str = "admit",
    context_for: Callable[[str, str], EvaluatorContextV2] = no_constraint,
) -> Iterator[ApplicabilityFixture]:
    """Retain actual signatures, owner-capture fixtures and a selected physical path.

    Parameters
    ----------
    root
        Owned ordinary directory. All fixture writes remain below this root.
    subject
        First signed clause's subject; the other three clauses remain admits.
    context_for
        Installed cooperative evidence reader, never a request-supplied success record.

    Yields
    ------
    ApplicabilityFixture
        Actual public verifier sources held through the caller's test.

    Notes
    -----
    Synthetic native-format transcripts establish fixture integrity only. They are
    neither an owner decision nor protected runtime qualification or deployment policy.
    """
    project = root / (
        "03_CODE/AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS/repositories/RIGOR-FOUNDRY"
    )
    project.mkdir(parents=True)
    target = project / "report.txt"
    target.write_bytes(b"original\n")

    def signed_scope(number: int, entry: dict[str, object]) -> None:
        """Bind the exact physical directory and first constraint before real signing."""
        if number == 1:
            entry.clear()
            entry.update(_entry(number, subject))
            if subject == "rate":
                cast(dict[str, object], entry["params"])["limit"] = 1
        cast(dict[str, object], entry["scope"])["targets"] = [f"path:{project}"]

    with _state(root, first_atomic=True, entry_mutator=signed_scope) as selected:
        if subject == "precondition":
            confirmation_root = root / "authority-confirmation"
            confirmation_root.mkdir()
            confirmation, requirement, manifest, question, reply = _native(confirmation_root)
            selected = replace(
                selected,
                authority_requirement=requirement,
                expected_authority_requirement_digest=requirement.requirement_digest,
                owner_confirmation=confirmation,
                expected_owner_confirmation_digest=confirmation.record_digest,
                confirmation_manifest=manifest,
                confirmation_question=question,
                confirmation_reply=reply,
            )
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with verifier.verified_context() as (semantics, chain, proof):
            payload = canonical_journal_json_v2(
                {
                    "operation_id": "local-file-write.atomic-replace",
                    "path": str(target),
                    "content_b64": "cmVwb3J0Cg==",
                    "declared": {
                        "target_ref": {"form": "path", "value": str(target)},
                        "byte_count": 7,
                        "operation_variant": "replace-or-create",
                    },
                }
            )
            action = ActionScope(
                "RIGOR-FOUNDRY/fixture",
                "fixture-runtime",
                "RIGOR-FOUNDRY",
                "write-report",
                "local-file-write",
                f"path:{target}",
                *("no-route",) * 4,
            )
            request = DispatchRequest(
                (action,), chain.current_adapters[0], *("no-route",) * 4, payload
            )
            yield ApplicabilityFixture(
                chain, proof.chain, semantics, proof, target, request, verifier, context_for
            )


def evaluate_applicability(
    fixture: ApplicabilityFixture,
    *,
    context_for: Callable[[str, str], EvaluatorContextV2] | None = None,
) -> SelectedDispatchApplicabilityV2:
    """Call the public composed evaluator with retained actual selected-boot identities.

    Parameters
    ----------
    fixture
        Real signed and physical sources retained by ``applicability_fixture``.
    context_for
        Explicit alternate installed test evidence source, such as a live journal reader.

    Returns
    -------
    SelectedDispatchApplicabilityV2
        Actual evaluated result after closing verification, always guard-inadmissible.

    Raises
    ------
    ValueError, PermissionError, OSError, RuntimeError
        Propagated refusal from the real extraction, selected lease or constraint reader.
    """
    return evaluate_selected_dispatch_applicability_v2(
        fixture.request,
        verifier=fixture.verifier,
        observed_lock_digest=fixture.chain_proof.lock_digest,
        observed_projection_digest=fixture.chain_proof.rule_projection_digest,
        context_for=fixture.context_for if context_for is None else context_for,
    )
