# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed operation descriptor contracts
"""Describe the two candidate operations without registering executable code."""

from __future__ import annotations

from .audit_primitives import canonical_digest


def _extractor_descriptors() -> list[dict[str, object]]:
    """Return fresh closed inline contracts; names do not install their required owners."""
    output = {
        "record": "ExtractedPartV3",
        "collection": "complete-template-order",
        "authority": "none",
    }
    return [
        {
            "id": "builtin.extract.atomic-replace.v3",
            "input_contract": {
                "invocation": "AtomicFileReplaceInvocationV2",
                "scope": "PinnedPathScopeV2",
                "target": "descriptor-bound-canonical-path",
                "byte_count": "decoded-content-bytes",
                "variant": "replace-or-create",
            },
            "output_contract": dict(output),
        },
        {
            "id": "builtin.extract.native-profile-audit.v3",
            "input_contract": {
                "operation": "NativeAuditOperation",
                "binding": "NativeOperationBindingV3",
                "request": "DispatchRequest",
                "action_mapping": "exact-original-order-deduplicated",
                "allocation": "host-registered-resource-contract",
                "cleanup": "created-owned-child-only",
            },
            "output_contract": dict(output),
        },
    ]


def _operation_descriptors() -> list[dict[str, object]]:
    """Bind every fixed part and lifecycle requirement to its complete candidate descriptor."""
    atomic, native = _extractor_descriptors()
    templates = (
        ("preparation", "read", "filesystem-path"),
        ("preparation", "local-file-write", "filesystem-path"),
        ("cleanup", "local-file-write", "filesystem-path"),
        ("preparation", "compute-job", "compute-host"),
        ("version", "compute-job", "compute-host"),
        ("audit", "compute-job", "compute-host"),
        ("audit", "compute-job", "compute-host"),
    )
    atomic_id = "local-file-write.atomic-replace"
    native_id = "native-profile-audit"
    return [
        {
            "operation_id": atomic_id,
            "handler_id": "builtin.handler.atomic-file-replace.v2",
            "invocation_contract_digest": canonical_digest(atomic["input_contract"]),
            "parts": [
                {
                    "index": 0,
                    "stage": "preparation",
                    "effect_class": "local-file-write",
                    "target_kind": "filesystem-path",
                    "target_extractor_id": atomic["id"],
                    "route_extractor_id": None,
                    "byte_count_extractor_id": atomic["id"],
                    "variant_extractor_id": atomic["id"],
                }
            ],
            "atomicity": "atomic",
            "partial_states": [],
            "cancellation_contract_digest": canonical_digest(
                {
                    "operation_id": atomic_id,
                    "before_effect": "revalidate-held-authority-and-cancellation",
                    "after_effect": "report-actual-outcome-without-rollback-claim",
                }
            ),
        },
        {
            "operation_id": native_id,
            "handler_id": "builtin.handler.native-profile-audit.v3",
            "invocation_contract_digest": canonical_digest(native["input_contract"]),
            "parts": [
                {
                    "index": index,
                    "stage": stage,
                    "effect_class": effect_class,
                    "target_kind": target_kind,
                    "target_extractor_id": native["id"],
                    "route_extractor_id": native["id"],
                    "byte_count_extractor_id": native["id"],
                    "variant_extractor_id": native["id"],
                }
                for index, (stage, effect_class, target_kind) in enumerate(templates)
            ],
            "atomicity": "multipart",
            "partial_states": [
                "reserved",
                "preparation-started",
                "preparation-completed",
                "version-started",
                "version-completed",
                "audit-started",
                "audit-completed",
                "cleanup-started",
                "cleanup-completed",
                "refused",
                "failed",
                "cancelled",
                "in-doubt",
            ],
            "cancellation_contract_digest": canonical_digest(
                {
                    "operation_id": native_id,
                    "before_each_stage": "revalidate-held-authority-and-cancellation",
                    "started": "durable-journal-before-effects",
                    "completed": "durable-journal-after-termination-and-output-validation",
                    "cleanup": "separately-authorised-created-child-only",
                    "denied_cleanup": "retain-exact-custody-and-in-doubt",
                    "recovery": "no-automatic-replay",
                }
            ),
        },
    ]
