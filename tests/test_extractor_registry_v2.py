# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — sealed v2 extractor registry tests
"""Check that unreviewed executable extractor identities cannot be selected."""

from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.models import canonical_digest


def test_empty_registry_is_canonical_and_digest_bound() -> None:
    """The effect-free bootstrap registry has canonical bytes and a stable digest."""
    registry = ExtractorRegistryV2.empty()
    assert registry.body_bytes == b'{"extractors":[],"schema":"rigor.extractor-registry.v2"}'
    assert registry.registry_digest == canonical_digest(
        {"schema": "rigor.extractor-registry.v2", "extractors": []}
    )
    assert ExtractorRegistryV2.from_bytes(registry.body_bytes) == registry


def test_first_atomic_candidate_is_closed_and_digest_bound() -> None:
    """Exactly three pinned built-ins form the candidate registry body."""
    registry = ExtractorRegistryV2.first_atomic_candidate()
    body = {
        "schema": "rigor.extractor-registry.v2",
        "extractors": [
            {
                "id": "builtin.extract.content-byte-count.v2",
                "output": "byte_count",
                "module": "rigor_foundry.tier0_builtin.extract_content_byte_count",
                "entrypoint": "extract",
                "forms": [],
            },
            {
                "id": "builtin.extract.fixed-variant-replace-or-create.v2",
                "output": "operation_variant",
                "module": "rigor_foundry.tier0_builtin.extract_fixed_variant",
                "entrypoint": "extract",
                "forms": [],
            },
            {
                "id": "builtin.extract.path-target.v2",
                "output": "target_ref",
                "module": "rigor_foundry.tier0_builtin.extract_path_target",
                "entrypoint": "extract",
                "forms": ["path"],
            },
        ],
    }
    assert registry.body_bytes == canonical_journal_json_v2(body)
    assert registry.registry_digest == canonical_digest(body)
    assert ExtractorRegistryV2.from_bytes(registry.body_bytes) == registry


def test_candidate_registry_rejects_changed_mapping() -> None:
    """Neither an alternate implementation nor a changed form can be selected."""
    registry = ExtractorRegistryV2.first_atomic_candidate()
    body = json.loads(registry.body_bytes)
    body["extractors"][0]["module"] = "rigor_foundry.unreviewed"
    with pytest.raises(ValueError, match="unreviewed"):
        ExtractorRegistryV2.from_bytes(canonical_journal_json_v2(body))
    body = json.loads(registry.body_bytes)
    body["extractors"][2]["forms"] = ["remote"]
    with pytest.raises(ValueError, match="unreviewed"):
        ExtractorRegistryV2.from_bytes(canonical_journal_json_v2(body))


def test_candidate_entries_import_and_return_declared_output(tmp_path: Path) -> None:
    """Each sealed module and entrypoint returns its declared output and form."""
    target = tmp_path / "target.txt"
    body = {
        "operation_id": "local-file-write.atomic-replace",
        "path": str(target),
        "content_b64": "eA==",
        "declared": {
            "target_ref": {"form": "path", "value": str(target)},
            "byte_count": 1,
            "operation_variant": "replace-or-create",
        },
    }
    payload = canonical_journal_json_v2(body)
    registry = json.loads(ExtractorRegistryV2.first_atomic_candidate().body_bytes)
    results: dict[str, object] = {}
    for entry in registry["extractors"]:
        module = import_module(entry["module"])
        extractor = getattr(module, entry["entrypoint"])
        if entry["output"] == "target_ref":
            result = extractor(
                payload, canonicalize_path=lambda path: {"form": "path", "value": path}
            )
            assert result["form"] in entry["forms"]
        else:
            result = extractor(payload)
            assert entry["forms"] == []
        results[entry["output"]] = result
    assert results == {
        "target_ref": {"form": "path", "value": str(target)},
        "byte_count": 1,
        "operation_variant": "replace-or-create",
    }


@pytest.mark.parametrize(
    "body",
    [
        {"schema": "rigor.extractor-registry.v2", "extractors": [], "extra": 0},
        {"schema": "rigor.extractor-registry.v2", "extractors": [{"id": "builtin.extract.x.v2"}]},
        {"schema": "rigor.extractor-registry.v3", "extractors": []},
    ],
)
def test_unreviewed_registry_bodies_refuse(body: dict[str, object]) -> None:
    """An extra field, changed version or executable entry has no authority."""
    with pytest.raises(ValueError):
        ExtractorRegistryV2.from_bytes(canonical_journal_json_v2(body))


def test_noncanonical_and_nonbytes_registry_refuse() -> None:
    """The registry parser does not normalise a forged byte representation."""
    with pytest.raises(ValueError):
        ExtractorRegistryV2.from_bytes(
            b'{"schema":"rigor.extractor-registry.v2", "extractors":[]}'
        )
    with pytest.raises(ValueError):
        ExtractorRegistryV2.from_bytes(
            b'{"schema":"rigor.extractor-registry.v2","extractors":[],"extractors":[]}'
        )
    with pytest.raises(ValueError):
        ExtractorRegistryV2.from_bytes(cast(bytes, "{}"))
