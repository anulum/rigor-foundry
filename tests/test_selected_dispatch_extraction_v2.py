# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected dispatch extraction tests
"""Exercise public extraction against real signed fixtures and filesystem targets."""

from __future__ import annotations

import errno
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_selected_clause_semantics_host_v2 import _state

from rigor_foundry.adapter_operations_v2 import AdapterOperationsV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.instruction_dispatch import DispatchRequest
from rigor_foundry.instruction_scope import ActionScope
from rigor_foundry.models import canonical_digest
from rigor_foundry.selected_clause_semantics_host_v2 import (
    HostSelectedClauseSemanticsStateV2,
    HostSelectedClauseSemanticsVerifierV2,
    SelectedClauseSemanticsProofV2,
)
from rigor_foundry.selected_dispatch_extraction_v2 import extract_selected_dispatch_request_v2
from rigor_foundry.selected_rule_chain_host_v2 import (
    HostSelectedRuleChainStateV2,
    SelectedRuleChainProofV2,
)
from rigor_foundry.signed_instruction_dispatch import dispatch_request_digest
from rigor_foundry.tier0_builtin.path_admission_v2 import PinnedPathScopeV2


@contextmanager
def _selection(
    root: Path,
) -> Iterator[
    tuple[
        DispatchRequest,
        HostSelectedRuleChainStateV2,
        SelectedRuleChainProofV2,
        HostSelectedClauseSemanticsStateV2,
        SelectedClauseSemanticsProofV2,
        Path,
    ]
]:
    """Retain actual signed fixture verifiers without operational host selection."""
    with _state(root, first_atomic=True) as initial:
        project = root / (
            "03_CODE/AGENTIC-COORDINATION-ASSURANCE-AND-CONTINUITY-SYSTEMS/"
            "repositories/RIGOR-FOUNDRY"
        )
        project.mkdir(parents=True)
        target = project / "report.txt"
        target.write_bytes(b"original target\n")
        with (
            HostSelectedClauseSemanticsVerifierV2(
                lambda: nullcontext(initial)
            ).verified_lease() as (semantics, semantics_proof),
            initial.chain.verified_lease() as (chain, chain_proof),
        ):
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
                "RIGOR-FOUNDRY/codex-fixture",
                "fixture-runtime",
                "RIGOR-FOUNDRY",
                "write-report",
                "local-file-write",
                f"path:{target}",
                "no-route",
                "no-route",
                "no-route",
                "no-route",
            )
            request = DispatchRequest(
                (action,), chain.current_adapters[0], *("no-route",) * 4, payload
            )
            yield request, chain, chain_proof, semantics, semantics_proof, target


def test_public_extraction_preserves_target_and_exact_selected_digests(tmp_path: Path) -> None:
    """Classify actual invocation bytes without preparing or changing the target."""
    with _selection(tmp_path) as (request, chain, proof, semantics, semantic_proof, target):
        original = target.read_bytes()
        before = target.stat(), original
        result = extract_selected_dispatch_request_v2(
            request,
            selected_chain=chain,
            chain_proof=proof,
            selected_semantics=semantics,
            semantics_proof=semantic_proof,
            observed_lock_digest=chain.lock.lock_digest,
            observed_projection_digest=chain.lock.rule_projection_digest,
        )
        assert (target.stat(), target.read_bytes()) == before
        assert result.request_digest == dispatch_request_digest(request)
        assert result.lock_digest == proof.lock_digest
        assert result.rule_projection_digest == proof.rule_projection_digest
        assert result.registry_generation_id == semantic_proof.registry_generation_id
        assert result.registry_sha256 == semantic_proof.registry_sha256
        assert chain.path_scope is not None
        assert result.path_scope_digest == chain.path_scope.path_scope_digest
        assert result.effect_operations_digest == chain.effect_operations.operations_digest
        assert result.operations_digest == canonical_digest(
            [
                {
                    "action_index": 0,
                    "operation_id": "local-file-write.atomic-replace",
                    "part_indices": [0],
                }
            ]
        )
        assert len(result.parts) == 1
        part = result.parts[0]
        assert (part.action_index, part.part_index, part.byte_count) == (0, 0, 7)
        assert part.operation_variant == "replace-or-create"
        assert part.effect_class == "local-file-write"
        assert part.target_kind == "filesystem-path"
        assert part.target_ref == {"form": "path", "value": str(target)}
        view = part.target_ref
        view["value"] = "/unrelated"
        assert part.target_ref["value"] == str(target)


@pytest.mark.parametrize(
    "fault",
    [
        "request",
        "actions-list",
        "empty-actions",
        "compound-actions",
        "action-type",
        "mutable-payload",
        "lock-format",
        "projection-format",
        "chain-type",
        "proof-type",
        "semantics-type",
        "semantics-proof-type",
        "expected-lock",
        "proof-lock",
        "proof-projection",
        "proof-acceptance",
        "proof-successors",
        "boot-lock",
        "boot-projection",
        "candidate-format",
        "project",
        "adapter",
        "action-route",
        "routed-operation",
        "catalogue",
        "expected-catalogue",
        "scope-missing",
        "semantic-chain",
        "registry-generation",
        "registry-digest",
        "expected-registry",
        "scope-registry",
        "effect",
        "target",
        "declared-count",
        "operation",
        "symlink",
    ],
)
def test_public_extraction_refuses_drift_without_target_effect(tmp_path: Path, fault: str) -> None:
    """Refuse altered public request or selection before target preparation."""
    with _selection(tmp_path) as (request, chain, proof, semantics, semantic_proof, target):
        before = target.read_bytes()
        observed_lock = chain.lock.lock_digest
        observed_projection = chain.lock.rule_projection_digest
        if fault == "request":
            request = cast(DispatchRequest, None)
        elif fault == "actions-list":
            request = replace(
                request, actions=cast(tuple[ActionScope, ...], list(request.actions))
            )
        elif fault == "empty-actions":
            request = replace(request, actions=())
        elif fault == "compound-actions":
            request = replace(request, actions=request.actions * 2)
        elif fault == "action-type":
            request = replace(request, actions=(cast(ActionScope, None),))
        elif fault == "mutable-payload":
            request = replace(request, payload=cast(bytes, bytearray(request.payload)))
        elif fault == "lock-format":
            observed_lock = "invalid"
        elif fault == "projection-format":
            observed_projection = "invalid"
        elif fault == "chain-type":
            chain = cast(HostSelectedRuleChainStateV2, None)
        elif fault == "proof-type":
            proof = cast(SelectedRuleChainProofV2, None)
        elif fault == "semantics-type":
            semantics = cast(HostSelectedClauseSemanticsStateV2, None)
        elif fault == "semantics-proof-type":
            semantic_proof = cast(SelectedClauseSemanticsProofV2, None)
        elif fault == "expected-lock":
            chain = replace(chain, expected_lock_digest="0" * 64)
        elif fault == "proof-lock":
            proof = replace(proof, lock_digest="0" * 64)
        elif fault == "proof-projection":
            proof = replace(proof, rule_projection_digest="0" * 64)
        elif fault == "proof-acceptance":
            proof = replace(proof, acceptance_digest="0" * 64)
        elif fault == "proof-successors":
            proof = replace(proof, successor_clause_digests=())
        elif fault == "boot-lock":
            observed_lock = "0" * 64
        elif fault == "boot-projection":
            observed_projection = "0" * 64
        elif fault == "candidate-format":
            proof = replace(proof, candidate_report_digest="invalid")
        elif fault == "project":
            request = replace(request, actions=(replace(request.actions[0], project="OTHER"),))
        elif fault == "adapter":
            request = replace(request, adapter=replace(request.adapter, adapter_id="unselected"))
        elif fault == "action-route":
            request = replace(request, actions=(replace(request.actions[0], provider="other"),))
        elif fault == "routed-operation":
            request = replace(
                request, provider="other", actions=(replace(request.actions[0], provider="other"),)
            )
        elif fault == "catalogue":
            chain = replace(
                chain,
                effect_operations=AdapterOperationsV2.empty(
                    vocabulary=chain.effect_vocabulary,
                    target_table=chain.effect_target_table,
                    extractors=ExtractorRegistryV2.empty(),
                ),
            )
        elif fault == "expected-catalogue":
            chain = replace(chain, expected_effect_operations_digest="0" * 64)
        elif fault == "scope-missing":
            chain = replace(chain, path_scope=None)
        elif fault == "semantic-chain":
            semantic_proof = replace(
                semantic_proof, chain=replace(proof, candidate_report_digest="0" * 64)
            )
        elif fault == "registry-generation":
            semantic_proof = replace(semantic_proof, registry_generation_id="other-generation")
        elif fault == "registry-digest":
            semantic_proof = replace(semantic_proof, registry_sha256="0" * 64)
        elif fault == "expected-registry":
            semantics = replace(semantics, expected_registry_sha256="0" * 64)
        elif fault == "scope-registry":
            chain = replace(
                chain,
                path_scope=replace(
                    cast(PinnedPathScopeV2, chain.path_scope), registry_sha256="0" * 64
                ),
            )
        elif fault == "effect":
            request = replace(request, actions=(replace(request.actions[0], effect="git-commit"),))
        elif fault == "target":
            request = replace(
                request,
                actions=(replace(request.actions[0], target=f"path:{target.parent / 'other'}"),),
            )
        elif fault == "declared-count":
            request = replace(
                request, payload=request.payload.replace(b'"byte_count":7', b'"byte_count":8')
            )
        elif fault == "operation":
            request = replace(
                request,
                payload=request.payload.replace(
                    b"local-file-write.atomic-replace", b"unknown.atomic-replace"
                ),
            )
        else:
            outside = tmp_path / "outside.txt"
            outside.write_bytes(before)
            target.unlink()
            target.symlink_to(outside)
        with pytest.raises((ValueError, PermissionError)) as refusal:
            extract_selected_dispatch_request_v2(
                request,
                selected_chain=chain,
                chain_proof=proof,
                selected_semantics=semantics,
                semantics_proof=semantic_proof,
                observed_lock_digest=observed_lock,
                observed_projection_digest=observed_projection,
            )
        cause: BaseException | None = refusal.value
        while cause is not None:
            if isinstance(cause, OSError):
                assert cause.errno != errno.ENOSYS, "unavailable syscall did not test this drift"
            cause = cause.__cause__
        assert target.read_bytes() == before
