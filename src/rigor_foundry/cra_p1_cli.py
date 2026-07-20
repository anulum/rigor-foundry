# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA P1 command-line workflow
"""Wire imported SBOM inventories and exact OSV awareness into the offline CLI."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from .cra_inventory import (
    ComponentInventory,
    InventoryDriftEvidence,
    RepositoryBinding,
    SbomFormat,
    SourceToolEvidence,
)
from .cra_osv import import_osv_awareness
from .cra_p1_store import CraP1Store
from .cra_protocol import json_text
from .cra_sbom import MAX_SBOM_BYTES, parse_sbom, read_import_file
from .git_inventory import load_git_inventory


def _source_tool(value: str, evidence_ref: str) -> SourceToolEvidence:
    """Parse one explicit NAME@VERSION declaration without guessing a version."""
    name, separator, version = value.rpartition("@")
    if not separator or not name or not version:
        raise ValueError("--source-tool must use NAME@VERSION")
    return SourceToolEvidence.build(name=name, version=version, evidence_ref=evidence_ref)


def _sbom_import(args: argparse.Namespace) -> int:
    """Import exact SBOM bytes into one append-only component inventory."""
    store = CraP1Store.open(args.root)
    store.base.current_registration(args.product_key)
    payload, digest = read_import_file(
        args.file,
        maximum_bytes=MAX_SBOM_BYTES,
        label="SBOM",
    )
    sbom_format = cast(SbomFormat, args.format)
    components = parse_sbom(payload, sbom_format)
    inventory = ComponentInventory.build(
        product_key=args.product_key,
        sbom_format=sbom_format,
        sbom_sha256=digest,
        source_tool=_source_tool(args.source_tool, args.source_evidence),
        captured_at=args.captured_at,
        top_level_components=components,
        covers_top_level_only=args.coverage == "top-level-only",
        tree_binding=RepositoryBinding.from_inventory(load_git_inventory(args.root)),
    )
    path = store.append_inventory(inventory, payload.decode("utf-8"))
    print(f"stored imported component inventory {inventory.inventory_digest} at {path}")
    return 0


def _sbom_status(args: argparse.Namespace) -> int:
    """Persist and print one exact current repository drift observation."""
    store = CraP1Store.open(args.root)
    inventory = store.current_inventory(args.product_key)
    drift = InventoryDriftEvidence.build(
        inventory,
        RepositoryBinding.from_inventory(load_git_inventory(args.root)),
        observed_at=args.observed_at,
    )
    store.append_drift(drift)
    print(json_text({"inventory": inventory.to_dict(), "drift": drift.to_dict()}), end="")
    return 1 if drift.drifted else 0


def add_osv_register_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the all-or-none exact OSV evidence bundle to ``vuln-register``."""
    parser.add_argument("--osv-adapter-result", type=Path)
    parser.add_argument("--osv-output", type=Path)
    parser.add_argument("--osv-id")
    parser.add_argument("--osv-package")
    parser.add_argument("--osv-imported-at")


def bind_osv_awareness(
    args: argparse.Namespace,
    *,
    recorded_at: str,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Return explicit awareness fields, importing OSV evidence when requested."""
    values = (
        args.osv_adapter_result,
        args.osv_output,
        args.osv_id,
        args.osv_package,
    )
    if not any(value is not None for value in values):
        if args.aware_evidence is None:
            raise ValueError("--aware-evidence or a complete OSV evidence bundle is required")
        return args.aware_evidence, tuple(args.external_id), tuple(args.component)
    if not all(value is not None for value in values):
        raise ValueError("all OSV evidence options must be supplied together")
    if args.aware_evidence is not None:
        raise ValueError("--aware-evidence and the OSV evidence bundle are mutually exclusive")
    if args.track != "vulnerability":
        raise ValueError("OSV awareness evidence is valid only for the vulnerability track")
    imported = import_osv_awareness(
        adapter_result_path=cast(Path, args.osv_adapter_result),
        output_path=cast(Path, args.osv_output),
        external_id=cast(str, args.osv_id),
        package_name=cast(str, args.osv_package),
        imported_at=args.osv_imported_at or recorded_at,
    )
    CraP1Store.open(args.root).append_osv_awareness(imported)
    evidence = imported.evidence
    external_ids = tuple(dict.fromkeys((*args.external_id, evidence.external_id)))
    components = tuple(dict.fromkeys((*args.component, evidence.component_ref)))
    return f"osv-awareness:{evidence.awareness_digest}", external_ids, components


def add_cra_p1_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the independently landable CRA P1 command surface."""
    sbom_import = subparsers.add_parser(
        "sbom-import",
        help="Import a bounded SBOM into offline content-addressed CRA evidence.",
    )
    sbom_import.add_argument("--root", type=Path, required=True)
    sbom_import.add_argument("--product-key", required=True)
    sbom_import.add_argument("--file", type=Path, required=True)
    sbom_import.add_argument(
        "--format",
        choices=("cyclonedx-1.5", "cyclonedx-1.6", "spdx-2.3"),
        required=True,
    )
    sbom_import.add_argument("--source-tool", required=True)
    sbom_import.add_argument("--source-evidence", required=True)
    sbom_import.add_argument(
        "--coverage",
        choices=("top-level-only", "declared-complete"),
        required=True,
        help="Operator declaration; RIGOR-FOUNDRY does not infer SBOM completeness.",
    )
    sbom_import.add_argument("--captured-at", required=True)
    sbom_import.set_defaults(handler=_sbom_import)

    sbom_status = subparsers.add_parser(
        "sbom-status",
        help="Record exact Git drift from the latest imported component inventory.",
    )
    sbom_status.add_argument("--root", type=Path, required=True)
    sbom_status.add_argument("--product-key", required=True)
    sbom_status.add_argument("--observed-at", required=True)
    sbom_status.set_defaults(handler=_sbom_status)
