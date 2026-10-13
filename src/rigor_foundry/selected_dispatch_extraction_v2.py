# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected dispatch request extraction
"""Derive request parts from selected catalogues without granting effect authority."""

from __future__ import annotations

from dataclasses import dataclass

from .adapter_operations_v2 import AdapterOperationsV2
from .effect_target_render_v2 import render_target_v2
from .instruction_dispatch import DispatchRequest
from .instruction_scope import ActionScope
from .model_primitives import require_digest
from .models import canonical_digest
from .rule_chain_lock_v2 import EffectiveProfileLockV2
from .selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    SelectedClauseSemanticsProofV2,
)
from .selected_rule_chain_host_v2 import HostSelectedRuleChainStateV2, SelectedRuleChainProofV2
from .signed_instruction_dispatch import dispatch_request_digest
from .tier0_builtin.atomic_file_replace_extraction import extract_atomic_file_replace_for_scope_v2
from .tier0_builtin.atomic_file_replace_invocation import ATOMIC_FILE_REPLACE_OPERATION_ID
from .tier0_builtin.selected_path_scope_v2 import derive_selected_path_scope_v2


@dataclass(frozen=True)
class ExtractedDispatchPartV2:
    """Immutable fields derived from one selected operation's actual invocation.

    Attributes
    ----------
    action_index, part_index
        Indices assigned by extraction, never supplied as a request part list.
    operation_id, effect_class, target_kind
        Selected catalogue classification of the operation and its part.
    target_form, target_value
        Descriptor-checked target extracted from the invocation bytes.
    byte_count, operation_variant
        Values compared with every corresponding caller declaration.

    Notes
    -----
    The first selected catalogue supports one local atomic replacement part.
    This result carries no owner authorization, permit or mutation capability.
    """

    action_index: int
    part_index: int
    operation_id: str
    effect_class: str
    target_kind: str
    target_form: str
    target_value: str
    byte_count: int
    operation_variant: str

    @property
    def target_ref(self) -> dict[str, str]:
        """Return a fresh target mapping without exposing mutable retained state.

        Returns
        -------
        dict[str, str]
            Exact extracted form and value.
        """
        return {"form": self.target_form, "value": self.target_value}


@dataclass(frozen=True)
class SelectedDispatchExtractionV2:
    """Read-only request classification bound to one selected rule generation.

    Attributes
    ----------
    request_digest
        Existing v2 request digest, including actual invocation bytes.
    lock_digest, rule_projection_digest
        Selected lock and projection matched to the consumer's observed boot.
    registry_generation_id, registry_sha256, path_scope_digest
        Registry and freshly derived path scope used for extraction.
    effect_operations_digest
        Exact selected operation catalogue.
    parts
        Complete extracted parts of the supported invocation.

    Notes
    -----
    Consume this result within the surrounding verified host leases. Retaining
    it after closure establishes neither current state nor effect permission.
    """

    request_digest: str
    lock_digest: str
    rule_projection_digest: str
    registry_generation_id: str
    registry_sha256: str
    path_scope_digest: str
    effect_operations_digest: str
    parts: tuple[ExtractedDispatchPartV2, ...]

    @property
    def operations_digest(self) -> str:
        """Bind the original v2 operation-to-action and part-index representation.

        Returns
        -------
        str
            Digest used by the existing dispatch permit binder.
        """
        return canonical_digest(
            [
                {
                    "action_index": part.action_index,
                    "operation_id": part.operation_id,
                    "part_indices": [part.part_index],
                }
                for part in self.parts
            ]
        )


def extract_selected_dispatch_request_v2(
    request: DispatchRequest,
    *,
    selected_chain: HostSelectedRuleChainStateV2,
    chain_proof: SelectedRuleChainProofV2,
    selected_semantics: HostSelectedClauseSemanticsStateV2,
    semantics_proof: SelectedClauseSemanticsProofV2,
    observed_lock_digest: str,
    observed_projection_digest: str,
) -> SelectedDispatchExtractionV2:
    """Extract actual parts for common audit consumers under verified host leases.

    Parameters
    ----------
    request
        Actual actions, adapter, route and immutable invocation bytes.
    selected_chain, chain_proof, selected_semantics, semantics_proof
        State from the same retained host selection and its verified consumers.
        Audit request data cannot appoint these dependencies.
    observed_lock_digest, observed_projection_digest
        Both identities returned by the caller's task boot. A stale identity
        refuses before target extraction.

    Returns
    -------
    SelectedDispatchExtractionV2
        Complete classification of the selected first atomic operation.

    Raises
    ------
    ValueError
        If request structure or an observed digest is malformed.
    PermissionError
        If selection, registry, catalogue, scope, route or extraction differs.

    Notes
    -----
    This does not evaluate Stage A/B, reserve a use, prepare a target, sign or
    consume a permit, or invoke a handler. Selected state and proof dataclasses
    alone do not authenticate custody; the installed owner retains and rechecks
    the actual host leases through its decision and any subsequent effect.
    """
    expected_lock = require_digest(observed_lock_digest, "extraction observed boot lock")
    expected_projection = require_digest(
        observed_projection_digest, "extraction observed boot projection"
    )
    if (
        type(request) is not DispatchRequest
        or type(request.actions) is not tuple
        or not request.actions
        or type(request.actions[0]) is not ActionScope
        or type(request.payload) is not bytes
    ):
        raise ValueError("selected first operation requires one exact immutable action")
    if len(request.actions) != 1:
        raise PermissionError("selected first operation requires exactly one part and action")
    if (
        not isinstance(selected_chain, HostSelectedRuleChainStateV2)
        or not isinstance(chain_proof, SelectedRuleChainProofV2)
        or not isinstance(selected_semantics, HostSelectedClauseSemanticsStateV2)
        or not isinstance(semantics_proof, SelectedClauseSemanticsProofV2)
    ):
        raise PermissionError("selected extraction dependencies are unavailable")
    lock = EffectiveProfileLockV2.from_dict(selected_chain.lock.to_dict())
    if (
        lock != selected_chain.lock
        or lock.resolution_status != "effective"
        or selected_chain.expected_lock_digest != lock.lock_digest
        or chain_proof.lock_digest != lock.lock_digest
        or chain_proof.rule_projection_digest != lock.rule_projection_digest
        or chain_proof.acceptance_digest != lock.acceptance_digest
        or chain_proof.successor_clause_digests != lock.successor_clause_digests
        or expected_lock != lock.lock_digest
        or expected_projection != lock.rule_projection_digest
    ):
        raise PermissionError("selected extraction differs from current boot and chain")
    require_digest(chain_proof.candidate_report_digest, "extraction selected candidate report")
    action = request.actions[0]
    if (
        action.project != lock.project_id
        or request.adapter not in lock.adapter_custody
        or (action.provider, action.account, action.cost_class, action.privacy_class)
        != request.route
        or request.route != ("no-route",) * 4
    ):
        raise PermissionError("selected extraction project, adapter or route differs")
    expected_operations = AdapterOperationsV2.first_atomic_candidate(
        vocabulary=selected_chain.effect_vocabulary,
        target_table=selected_chain.effect_target_table,
        extractors=selected_chain.extractor_registry,
    )
    if (
        selected_chain.effect_operations != expected_operations
        or selected_chain.expected_effect_operations_digest != lock.effect_operations_digest
        or selected_chain.effect_operations.operations_digest != lock.effect_operations_digest
        or selected_chain.path_scope is None
    ):
        raise PermissionError("selected extraction catalogue or path scope is unavailable")
    if (
        semantics_proof.chain != chain_proof
        or selected_semantics.registry.generation_id != semantics_proof.registry_generation_id
        or selected_semantics.registry.registry_sha256 != semantics_proof.registry_sha256
        or selected_semantics.expected_registry_sha256 != semantics_proof.registry_sha256
    ):
        raise PermissionError("selected extraction registry proof differs")
    scope = derive_selected_path_scope_v2(
        registry_bytes=selected_semantics.registry.to_bytes(),
        monorepo_root=str(selected_semantics.monorepo_root),
        selected_project_id=lock.project_id,
        registry_generation_id=semantics_proof.registry_generation_id,
        registry_sha256=semantics_proof.registry_sha256,
    )
    if selected_chain.path_scope != scope:
        raise PermissionError("selected extraction path scope differs from current registry")
    extracted = extract_atomic_file_replace_for_scope_v2(request.payload, scope=scope)
    if action.effect != "local-file-write" or action.target != render_target_v2(
        extracted.target_ref, "filesystem-path"
    ):
        raise PermissionError("selected action differs from extracted operation part")
    part = ExtractedDispatchPartV2(
        0,
        0,
        ATOMIC_FILE_REPLACE_OPERATION_ID,
        "local-file-write",
        "filesystem-path",
        extracted.target_ref["form"],
        extracted.target_ref["value"],
        extracted.byte_count,
        extracted.operation_variant,
    )
    return SelectedDispatchExtractionV2(
        dispatch_request_digest(request),
        lock.lock_digest,
        lock.rule_projection_digest,
        semantics_proof.registry_generation_id,
        semantics_proof.registry_sha256,
        scope.path_scope_digest,
        selected_chain.effect_operations.operations_digest,
        (part,),
    )
