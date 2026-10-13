# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — leased selected dispatch applicability
"""Compose actual invocation extraction and clause evaluation under one selection lease."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .constraint_evaluators_v2 import EvaluatorContextV2
from .instruction_dispatch import DispatchRequest
from .selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsVerifierV2,
    SelectedClauseSemanticsProofV2,
)
from .selected_dispatch_extraction_v2 import (
    SelectedDispatchExtractionV2,
    extract_selected_dispatch_request_v2,
)
from .selected_stage_b_results_v3 import evaluate_selected_stage_b_results_v3
from .stage_b_result_v2 import StageBResultV2


@dataclass(frozen=True)
class SelectedDispatchApplicabilityV2:
    """Read-only evaluated request after the complete selection lease closes.

    Attributes
    ----------
    extraction : SelectedDispatchExtractionV2
        Actual invocation classification and its selected request, lock, registry and catalogue pins.
    semantics_proof : SelectedClauseSemanticsProofV2
        Signed clause, native capture and scope integrity checked against the same held chain.
    results : tuple[StageBResultV2, ...]
        Ordered applicability results for every extracted part.

    Notes
    -----
    Direct construction does not reproduce verification. An admitted clause result supplies no
    permission, reservation, permit or handler capability, and does not prove protected installation.
    """

    extraction: SelectedDispatchExtractionV2
    semantics_proof: SelectedClauseSemanticsProofV2
    results: tuple[StageBResultV2, ...]

    @property
    def guard_admissible(self) -> Literal[False]:
        """Keep applicability data separate from effect admission.

        Returns
        -------
        Literal[False]
            This record cannot grant an effect or substitute for current protected admission.
        """
        return False


def evaluate_selected_dispatch_applicability_v2(
    request: DispatchRequest,
    *,
    verifier: HostSelectedClauseSemanticsVerifierV2,
    observed_lock_digest: str,
    observed_projection_digest: str,
    context_for: Callable[[str, str], EvaluatorContextV2],
) -> SelectedDispatchApplicabilityV2:
    """Extract and evaluate the request before closing all selected source checks.

    Parameters
    ----------
    request : DispatchRequest
        Actual immutable invocation and its declared action, adapter and route.
    verifier : HostSelectedClauseSemanticsVerifierV2
        Installed source provider retaining the selected chain and semantics through the consumer.
    observed_lock_digest : str
        Exact lock identity returned by the task's selected boot.
    observed_projection_digest : str
        Exact rule projection identity returned by that same boot.
    context_for : Callable[[str, str], EvaluatorContextV2]
        Installed context source for applicable constraints. A journal rate source binds its actual
        retained journal history to each extracted part; request fields cannot select this source.

    Returns
    -------
    SelectedDispatchApplicabilityV2
        Actual extracted parts and evaluated results after successful closing verification.

    Raises
    ------
    ValueError
        Request, catalogue, observed digest or result structure is malformed.
    PermissionError
        Selected sources, current boot, scope, constraints or closing checks refuse.
    OSError
        A retained source or actual descriptor-backed target cannot be safely read.
    RuntimeError
        A provider suppresses a failure without completing the selected lease.

    Notes
    -----
    No target is prepared or changed, and no use is reserved, permit signed or handler invoked.
    Source-provider authentication and protected runtime qualification remain deployment obligations.
    """
    with verifier.verified_context() as (semantics, chain, proof):
        extraction = extract_selected_dispatch_request_v2(
            request,
            selected_chain=chain,
            chain_proof=proof.chain,
            selected_semantics=semantics,
            semantics_proof=proof,
            observed_lock_digest=observed_lock_digest,
            observed_projection_digest=observed_projection_digest,
        )
        results = evaluate_selected_stage_b_results_v3(
            extraction,
            semantics=semantics,
            semantics_proof=proof,
            context_for=context_for,
        )
        evaluated = SelectedDispatchApplicabilityV2(extraction, proof, results)
    return evaluated
