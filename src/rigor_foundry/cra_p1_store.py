# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA P1 append-only evidence storage
"""Persist imported SBOM inventories, drift records, and exact OSV evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .adapters import AdapterResult
from .audit_primitives import canonical_digest
from .cra_inventory import ComponentInventory, InventoryDriftEvidence
from .cra_osv import ImportedOsvAwareness, OsvAwarenessEvidence
from .cra_protocol import json_text
from .cra_sbom import parse_sbom
from .cra_store import (
    CraRepository,
    _mkdirs,
    _parse_records,
    _read_text,
    _write_once_or_verify,
)
from .internal_storage import exclusive_lock


@dataclass(frozen=True)
class CraP1Store:
    """Extend one validated P0 store with isolated P1 evidence namespaces."""

    base: CraRepository

    @classmethod
    def open(cls, repository_root: Path) -> CraP1Store:
        """Open an existing bootstrapped CRA store."""
        return cls(CraRepository.open(repository_root))

    def append_inventory(self, inventory: ComponentInventory, sbom_text: str) -> Path:
        """Persist exact imported SBOM bytes before their inventory record."""
        with exclusive_lock(self.base._lock_path):
            inventory = ComponentInventory.from_dict(inventory.to_dict())
            self.base.current_registration(inventory.product_key)
            encoded = sbom_text.encode("utf-8")
            if hashlib.sha256(encoded).hexdigest() != inventory.sbom_sha256:
                raise ValueError("SBOM bytes do not match component inventory")
            components = parse_sbom(encoded, inventory.sbom_format)
            if tuple(sorted(components)) != inventory.top_level_components:
                raise ValueError("SBOM components do not match component inventory")
            existing = self.inventories(inventory.product_key)
            if existing:
                if inventory in existing:
                    return (
                        self.base.storage_root
                        / "inventories"
                        / inventory.product_key
                        / f"{inventory.inventory_digest}.json"
                    )
                if inventory.captured_at <= existing[-1].captured_at:
                    raise ValueError("new component inventory must have a later captured_at")
            sbom_directory = _mkdirs(self.base.storage_root, Path("sboms"))
            _write_once_or_verify(
                sbom_directory / f"{inventory.sbom_sha256}.json",
                sbom_text,
            )
            directory = _mkdirs(
                self.base.storage_root,
                Path("inventories") / inventory.product_key,
            )
            path = directory / f"{inventory.inventory_digest}.json"
            _write_once_or_verify(path, inventory.to_json())
            return path

    def inventories(self, product_key: str) -> tuple[ComponentInventory, ...]:
        """Return verified inventories in strict capture order."""
        self.base.current_registration(product_key)
        records = _parse_records(
            self.base.storage_root / "inventories" / product_key,
            ComponentInventory.from_dict,
            "inventory_digest",
        )
        ordered = tuple(sorted(records, key=lambda item: item.captured_at))
        timestamps = tuple(item.captured_at for item in ordered)
        if len(timestamps) != len(set(timestamps)):
            raise ValueError("component inventories contain duplicate capture timestamps")
        for record in ordered:
            source = _read_text(self.base.storage_root / "sboms" / f"{record.sbom_sha256}.json")
            encoded = source.encode("utf-8")
            if hashlib.sha256(encoded).hexdigest() != record.sbom_sha256:
                raise ValueError("stored SBOM digest does not match its bytes")
            if (
                tuple(sorted(parse_sbom(encoded, record.sbom_format)))
                != record.top_level_components
            ):
                raise ValueError("stored SBOM components do not match inventory")
        return ordered

    def current_inventory(self, product_key: str) -> ComponentInventory:
        """Return the latest verified inventory for one product."""
        records = self.inventories(product_key)
        if not records:
            raise ValueError("product has no verified component inventory")
        return records[-1]

    def append_drift(self, drift: InventoryDriftEvidence) -> Path:
        """Persist one immutable repository-drift observation."""
        with exclusive_lock(self.base._lock_path):
            drift = InventoryDriftEvidence.from_dict(drift.to_dict())
            inventories = self.inventories(drift.product_key)
            if drift.inventory_digest not in {item.inventory_digest for item in inventories}:
                raise ValueError("drift record names an unknown component inventory")
            directory = _mkdirs(
                self.base.storage_root,
                Path("inventory-drift") / drift.product_key,
            )
            path = directory / f"{drift.drift_digest}.json"
            _write_once_or_verify(path, drift.to_json())
            return path

    def append_osv_awareness(self, imported: ImportedOsvAwareness) -> Path:
        """Persist exact adapter inputs before one derived awareness record."""
        with exclusive_lock(self.base._lock_path):
            evidence = OsvAwarenessEvidence.from_dict(imported.evidence.to_dict())
            adapter_value = json.loads(imported.adapter_result_text)
            adapter = AdapterResult.from_dict(adapter_value)
            if imported.adapter_result_text != json_text(adapter.to_dict()):
                raise ValueError("adapter result bytes are not canonical")
            if canonical_digest(adapter.to_dict()) != evidence.adapter_result_digest:
                raise ValueError("adapter result bytes do not match awareness evidence")
            output_bytes = imported.output_text.encode("utf-8")
            if hashlib.sha256(output_bytes).hexdigest() != evidence.adapter_output_sha256:
                raise ValueError("OSV output bytes do not match awareness evidence")
            adapter_directory = _mkdirs(self.base.storage_root, Path("adapter-results"))
            output_directory = _mkdirs(self.base.storage_root, Path("osv-outputs"))
            awareness_directory = _mkdirs(self.base.storage_root, Path("osv-awareness"))
            _write_once_or_verify(
                adapter_directory / f"{evidence.adapter_result_digest}.json",
                imported.adapter_result_text,
            )
            _write_once_or_verify(
                output_directory / f"{evidence.adapter_output_sha256}.json",
                imported.output_text,
            )
            path = awareness_directory / f"{evidence.awareness_digest}.json"
            _write_once_or_verify(path, evidence.to_json())
            return path

    def awareness(self, digest: str) -> OsvAwarenessEvidence:
        """Load one verified awareness record and both retained exact sources."""
        records = _parse_records(
            self.base.storage_root / "osv-awareness",
            OsvAwarenessEvidence.from_dict,
            "awareness_digest",
        )
        matches = tuple(item for item in records if item.awareness_digest == digest)
        if len(matches) != 1:
            raise ValueError("OSV awareness digest does not select one record")
        evidence = matches[0]
        adapter_text = _read_text(
            self.base.storage_root / "adapter-results" / f"{evidence.adapter_result_digest}.json"
        )
        adapter = AdapterResult.from_dict(json.loads(adapter_text))
        if adapter_text != json_text(adapter.to_dict()):
            raise ValueError("stored adapter result bytes are not canonical")
        if canonical_digest(adapter.to_dict()) != evidence.adapter_result_digest:
            raise ValueError("stored adapter result does not match awareness evidence")
        output_text = _read_text(
            self.base.storage_root / "osv-outputs" / f"{evidence.adapter_output_sha256}.json"
        )
        if (
            hashlib.sha256(output_text.encode("utf-8")).hexdigest()
            != evidence.adapter_output_sha256
        ):
            raise ValueError("stored OSV output does not match awareness evidence")
        return evidence
