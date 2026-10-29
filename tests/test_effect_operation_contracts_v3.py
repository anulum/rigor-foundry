# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete inline operation contract tests
"""Check declared operation contracts through their actual public catalogue producers."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import cast

from test_effect_operations_v3 import catalogue
from test_policy_model_inputs import budget

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.tier0_builtin.atomic_file_replace_invocation import (
    ATOMIC_FILE_REPLACE_OPERATION_ID,
    ATOMIC_FILE_REPLACE_VARIANT,
    AtomicFileReplaceInvocationV2,
)


def test_atomic_descriptor_preserves_actual_original_invocation_contract(tmp_path: Path) -> None:
    """A real bounded original invocation retains its path/content/variant and one closed part."""
    value = catalogue()
    atomic = cast(list[dict[str, object]], value.to_dict(budget=budget())["operations"])[0]
    extractor = cast(
        list[dict[str, object]], value.extractors.to_dict(budget=budget())["extractors"]
    )[0]
    path = tmp_path / "target.txt"
    content = "exact ž\n".encode()
    invocation = AtomicFileReplaceInvocationV2.from_bytes(
        canonical_journal_json_v2(
            {
                "operation_id": ATOMIC_FILE_REPLACE_OPERATION_ID,
                "path": str(path),
                "content_b64": base64.b64encode(content).decode("ascii"),
                "declared": {
                    "target_ref": {"form": "path", "value": str(path)},
                    "byte_count": len(content),
                    "operation_variant": ATOMIC_FILE_REPLACE_VARIANT,
                },
            }
        )
    )
    assert invocation.path == str(path) and invocation.content == content
    assert invocation.declared_byte_count == len(content)
    assert invocation.declared_operation_variant == "replace-or-create"
    assert atomic["operation_id"] == ATOMIC_FILE_REPLACE_OPERATION_ID
    assert atomic["handler_id"] == "builtin.handler.atomic-file-replace.v2"
    assert atomic["invocation_contract_digest"] == canonical_digest(extractor["input_contract"])
    assert extractor["input_contract"] == {
        "invocation": "AtomicFileReplaceInvocationV2",
        "scope": "PinnedPathScopeV2",
        "target": "descriptor-bound-canonical-path",
        "byte_count": "decoded-content-bytes",
        "variant": "replace-or-create",
    }
    parts = cast(list[dict[str, object]], atomic["parts"])
    assert len(parts) == 1 and parts[0]["index"] == 0
    assert parts[0]["route_extractor_id"] is None
    assert atomic["atomicity"] == "atomic" and atomic["partial_states"] == []
    assert not path.exists()


def test_native_seven_parts_keep_stage_order_classification_and_separate_original_actions() -> (
    None
):
    """The descriptor retains every template instead of collapsing shared execute actions."""
    value = catalogue()
    native = cast(list[dict[str, object]], value.to_dict(budget=budget())["operations"])[1]
    extractor = cast(
        list[dict[str, object]], value.extractors.to_dict(budget=budget())["extractors"]
    )[1]
    parts = cast(list[dict[str, object]], native["parts"])
    assert [row["index"] for row in parts] == list(range(7))
    assert [row["stage"] for row in parts] == [
        "preparation",
        "preparation",
        "cleanup",
        "preparation",
        "version",
        "audit",
        "audit",
    ]
    assert [(row["effect_class"], row["target_kind"]) for row in parts] == [
        ("read", "filesystem-path"),
        ("local-file-write", "filesystem-path"),
        ("local-file-write", "filesystem-path"),
        ("compute-job", "compute-host"),
        ("compute-job", "compute-host"),
        ("compute-job", "compute-host"),
        ("compute-job", "compute-host"),
    ]
    assert all(
        value.target_table.allows(
            str(row["effect_class"]),
            str(row["target_kind"]),
            "path" if row["target_kind"] == "filesystem-path" else "endpoint",
        )
        for row in parts
    )
    assert native["operation_id"] == "native-profile-audit"
    assert native["atomicity"] == "multipart"
    assert native["invocation_contract_digest"] == canonical_digest(extractor["input_contract"])
    assert extractor["input_contract"] == {
        "operation": "NativeAuditOperation",
        "binding": "NativeOperationBindingV3",
        "request": "DispatchRequest",
        "action_mapping": "exact-original-order-deduplicated",
        "allocation": "host-registered-resource-contract",
        "cleanup": "created-owned-child-only",
    }
    assert extractor["output_contract"] == {
        "record": "ExtractedPartV3",
        "collection": "complete-template-order",
        "authority": "none",
    }
    assert all(
        set(row)
        == {
            "index",
            "stage",
            "effect_class",
            "target_kind",
            "target_extractor_id",
            "route_extractor_id",
            "byte_count_extractor_id",
            "variant_extractor_id",
        }
        for row in parts
    )
    assert all(row["target_extractor_id"] == extractor["id"] for row in parts)


def test_cancellation_descriptors_bind_required_lifecycle_without_claiming_implementation() -> (
    None
):
    """Both lifecycle preimages name their operation and the native one retains denied cleanup."""
    operations = cast(list[dict[str, object]], catalogue().to_dict(budget=budget())["operations"])
    atomic, native = operations
    assert all(
        set(row)
        == {
            "operation_id",
            "handler_id",
            "invocation_contract_digest",
            "parts",
            "atomicity",
            "partial_states",
            "cancellation_contract_digest",
        }
        for row in operations
    )
    assert atomic["cancellation_contract_digest"] == canonical_digest(
        {
            "operation_id": "local-file-write.atomic-replace",
            "before_effect": "revalidate-held-authority-and-cancellation",
            "after_effect": "report-actual-outcome-without-rollback-claim",
        }
    )
    assert native["cancellation_contract_digest"] == canonical_digest(
        {
            "operation_id": "native-profile-audit",
            "before_each_stage": "revalidate-held-authority-and-cancellation",
            "started": "durable-journal-before-effects",
            "completed": "durable-journal-after-termination-and-output-validation",
            "cleanup": "separately-authorised-created-child-only",
            "denied_cleanup": "retain-exact-custody-and-in-doubt",
            "recovery": "no-automatic-replay",
        }
    )
    assert native["partial_states"] == [
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
    ]
