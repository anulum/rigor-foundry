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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from .adapters import AdapterResult
from .audit_primitives import canonical_digest
from .cra_inventory import ComponentInventory, InventoryDriftEvidence
from .cra_osv import (
    MAX_ADAPTER_RESULT_BYTES,
    MAX_OSV_OUTPUT_BYTES,
    ImportedOsvAwareness,
    OsvAwarenessEvidence,
)
from .cra_protocol import json_text
from .cra_sbom import MAX_SBOM_BYTES, parse_sbom, read_import_file
from .cra_store import (
    CraRepository,
    _mkdirs,
    _safe_directory,
    _write_once_or_verify,
)
from .internal_storage import exclusive_lock

MAX_P1_RECORD_BYTES = 32 * 1024 * 1024


class _P1Record(Protocol):
    """Describe one canonical content-addressed P1 JSON record."""

    def to_json(self) -> str:
        """Return canonical JSON text."""


_Record = TypeVar("_Record", bound=_P1Record)


def _p1_records(
    directory: Path,
    parser: Callable[[object], _Record],
    digest_name: str,
) -> tuple[_Record, ...]:
    """Replay larger P1 records through the same stable-file boundary as imports."""
    if not directory.exists():
        return ()
    _safe_directory(directory, label="CRA P1 record directory")
    records: list[_Record] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.suffix != ".json":
            raise ValueError(f"unexpected CRA P1 storage entry: {path}")
        payload, _ = read_import_file(
            path,
            maximum_bytes=MAX_P1_RECORD_BYTES,
            label="CRA P1 record",
        )
        try:
            text = payload.decode("utf-8")
            value = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"CRA P1 record is not valid JSON: {path}") from exc
        record = parser(value)
        if path.stem != getattr(record, digest_name, None):
            raise ValueError(f"CRA P1 filename does not match embedded digest: {path}")
        if text != record.to_json():
            raise ValueError(f"CRA P1 record bytes are not canonical: {path}")
        records.append(record)
    return tuple(records)


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
        records = _p1_records(
            self.base.storage_root / "inventories" / product_key,
            ComponentInventory.from_dict,
            "inventory_digest",
        )
        ordered = tuple(sorted(records, key=lambda item: item.captured_at))
        timestamps = tuple(item.captured_at for item in ordered)
        if len(timestamps) != len(set(timestamps)):
            raise ValueError("component inventories contain duplicate capture timestamps")
        for record in ordered:
            encoded, observed_digest = read_import_file(
                self.base.storage_root / "sboms" / f"{record.sbom_sha256}.json",
                maximum_bytes=MAX_SBOM_BYTES,
                label="stored SBOM",
            )
            if observed_digest != record.sbom_sha256:
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
        records = _p1_records(
            self.base.storage_root / "osv-awareness",
            OsvAwarenessEvidence.from_dict,
            "awareness_digest",
        )
        matches = tuple(item for item in records if item.awareness_digest == digest)
        if len(matches) != 1:
            raise ValueError("OSV awareness digest does not select one record")
        evidence = matches[0]
        adapter_payload, _ = read_import_file(
            self.base.storage_root / "adapter-results" / f"{evidence.adapter_result_digest}.json",
            maximum_bytes=MAX_ADAPTER_RESULT_BYTES,
            label="stored OSV adapter result",
        )
        adapter_text = adapter_payload.decode("utf-8")
        adapter = AdapterResult.from_dict(json.loads(adapter_text))
        if adapter_text != json_text(adapter.to_dict()):
            raise ValueError("stored adapter result bytes are not canonical")
        if canonical_digest(adapter.to_dict()) != evidence.adapter_result_digest:
            raise ValueError("stored adapter result does not match awareness evidence")
        _output_payload, output_digest = read_import_file(
            self.base.storage_root / "osv-outputs" / f"{evidence.adapter_output_sha256}.json",
            maximum_bytes=MAX_OSV_OUTPUT_BYTES,
            label="stored OSV output",
        )
        if output_digest != evidence.adapter_output_sha256:
            raise ValueError("stored OSV output does not match awareness evidence")
        return evidence
