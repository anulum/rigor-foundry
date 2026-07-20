# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA P1 storage integrity tests
"""Exercise P1 append-only replay, monotonicity, and retained-source tamper checks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_cra_inventory import cyclonedx
from test_cra_osv import write_inputs
from test_cra_p1_cli import NOW, osv_output, repository

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.cra_inventory import (
    ComponentInventory,
    InventoryComponent,
    InventoryDriftEvidence,
    RepositoryBinding,
    SourceToolEvidence,
)
from rigor_foundry.cra_osv import ImportedOsvAwareness, OsvAwarenessEvidence, import_osv_awareness
from rigor_foundry.cra_p1_store import CraP1Store
from rigor_foundry.cra_protocol import json_text
from rigor_foundry.cra_sbom import parse_sbom
from rigor_foundry.git_inventory import load_git_inventory


def inventory_for(
    store: CraP1Store,
    payload: bytes,
    *,
    captured_at: str = NOW,
    components: tuple[InventoryComponent, ...] | None = None,
) -> ComponentInventory:
    """Build one inventory against the store's real Git repository."""
    return ComponentInventory.build(
        product_key="PRODUCT-1",
        sbom_format="cyclonedx-1.5",
        sbom_sha256=hashlib.sha256(payload).hexdigest(),
        source_tool=SourceToolEvidence.build(
            name="generator", version="1", evidence_ref="build:1"
        ),
        captured_at=captured_at,
        top_level_components=components or parse_sbom(payload, "cyclonedx-1.5"),
        covers_top_level_only=True,
        tree_binding=RepositoryBinding.from_inventory(
            load_git_inventory(store.base.repository_root)
        ),
    )


def imported_osv(tmp_path: Path) -> ImportedOsvAwareness:
    """Return one verified OSV import through real files."""
    result_path, output_path = write_inputs(tmp_path, osv_output())
    return import_osv_awareness(
        adapter_result_path=result_path,
        output_path=output_path,
        external_id="OSV-TEST-1",
        package_name="urllib3",
        imported_at=NOW,
    )


def test_inventory_replay_is_idempotent_and_advances_monotonically(tmp_path: Path) -> None:
    """Exact crash replay is accepted and a later capture becomes the current record."""
    repo = repository(tmp_path)
    store = CraP1Store.open(repo.root)
    first_payload = cyclonedx()
    first = inventory_for(store, first_payload)
    path = store.append_inventory(first, first_payload.decode())
    assert store.append_inventory(first, first_payload.decode()) == path

    second_payload = cyclonedx().replace(b'"2.0"', b'"2.1"')
    second = inventory_for(store, second_payload, captured_at="2026-07-20T11:00:00Z")
    store.append_inventory(second, second_payload.decode())
    assert store.inventories("PRODUCT-1") == (first, second)
    assert store.current_inventory("PRODUCT-1") == second


def test_inventory_append_rejects_wrong_bytes_components_and_unknown_drift(tmp_path: Path) -> None:
    """A record cannot detach from its SBOM bytes, components, or product history."""
    repo = repository(tmp_path)
    store = CraP1Store.open(repo.root)
    payload = cyclonedx()
    inventory = inventory_for(store, payload)
    with pytest.raises(ValueError, match="bytes do not match"):
        store.append_inventory(inventory, "{}")
    wrong_components = (InventoryComponent.build(name="other", version="1", purl=None),)
    inconsistent = inventory_for(store, payload, components=wrong_components)
    with pytest.raises(ValueError, match="components do not match"):
        store.append_inventory(inconsistent, payload.decode())
    with pytest.raises(ValueError, match="no verified component inventory"):
        store.current_inventory("PRODUCT-1")

    drift = InventoryDriftEvidence.build(
        inventory,
        inventory.tree_binding,
        observed_at="2026-07-20T10:01:00Z",
    )
    drift_data = {**drift.to_dict(), "inventory_digest": "0" * 64}
    drift_body = {key: value for key, value in drift_data.items() if key != "drift_digest"}
    drift_data["drift_digest"] = canonical_digest(drift_body)
    with pytest.raises(ValueError, match="unknown component inventory"):
        store.append_drift(InventoryDriftEvidence.from_dict(drift_data))


def test_inventory_replay_detects_duplicate_times_and_component_record_tamper(
    tmp_path: Path,
) -> None:
    """Conflicting append-only inventory history fails before current state is selected."""
    repo = repository(tmp_path)
    store = CraP1Store.open(repo.root)
    payload = cyclonedx()
    first = inventory_for(store, payload)
    store.append_inventory(first, payload.decode())
    changed_components = (InventoryComponent.build(name="fabricated", version="9", purl=None),)
    second = inventory_for(store, payload, components=changed_components)
    directory = store.base.storage_root / "inventories" / "PRODUCT-1"
    (directory / f"{second.inventory_digest}.json").write_text(second.to_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate capture timestamps"):
        store.inventories("PRODUCT-1")

    (directory / f"{first.inventory_digest}.json").unlink()
    with pytest.raises(ValueError, match="components do not match"):
        store.inventories("PRODUCT-1")


def test_osv_store_rejects_noncanonical_and_detached_sources(tmp_path: Path) -> None:
    """Adapter and output bytes must remain exact before awareness is appended."""
    repo = repository(tmp_path)
    store = CraP1Store.open(repo.root)
    imported = imported_osv(tmp_path / "osv")
    with pytest.raises(ValueError, match="not canonical"):
        store.append_osv_awareness(
            replace(imported, adapter_result_text=imported.adapter_result_text + " ")
        )

    changed = imported.evidence.to_dict()
    changed["adapter_result_digest"] = "f" * 64
    body = {key: value for key, value in changed.items() if key != "awareness_digest"}
    changed["awareness_digest"] = canonical_digest(body)
    detached = replace(imported, evidence=OsvAwarenessEvidence.from_dict(changed))
    with pytest.raises(ValueError, match="adapter result bytes do not match"):
        store.append_osv_awareness(detached)

    with pytest.raises(ValueError, match="output bytes do not match"):
        store.append_osv_awareness(replace(imported, output_text=imported.output_text + " "))


def test_osv_replay_detects_unknown_digest_and_both_source_tampers(tmp_path: Path) -> None:
    """Every awareness read replays canonical adapter bytes and exact output digest."""
    repo = repository(tmp_path)
    store = CraP1Store.open(repo.root)
    imported = imported_osv(tmp_path / "osv")
    store.append_osv_awareness(imported)
    digest = imported.evidence.awareness_digest
    assert store.awareness(digest) == imported.evidence
    with pytest.raises(ValueError, match="does not select"):
        store.awareness("0" * 64)

    adapter_path = (
        store.base.storage_root
        / "adapter-results"
        / f"{imported.evidence.adapter_result_digest}.json"
    )
    adapter_path.write_text(imported.adapter_result_text + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="not canonical"):
        store.awareness(digest)

    adapter_path.write_text(imported.adapter_result_text, encoding="utf-8")
    output_path = (
        store.base.storage_root / "osv-outputs" / f"{imported.evidence.adapter_output_sha256}.json"
    )
    output_path.write_text(imported.output_text + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="output does not match"):
        store.awareness(digest)


def test_osv_replay_rejects_canonical_but_wrong_adapter_record(tmp_path: Path) -> None:
    """A canonical alternate adapter record cannot occupy an existing content address."""
    repo = repository(tmp_path)
    store = CraP1Store.open(repo.root)
    imported = imported_osv(tmp_path / "osv")
    store.append_osv_awareness(imported)
    adapter_path = (
        store.base.storage_root
        / "adapter-results"
        / f"{imported.evidence.adapter_result_digest}.json"
    )
    value = json.loads(imported.adapter_result_text)
    value["name"] = "different-osv-adapter"
    adapter_path.write_text(json_text(value), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match awareness"):
        store.awareness(imported.evidence.awareness_digest)
