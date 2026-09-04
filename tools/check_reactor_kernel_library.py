# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Reactor kernel-library cross-repository guard
"""Verify immutable Reactor kernel pins against real local Git objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

MAP_SCHEMA: Final = "1.1.0"
KERNEL_PROJECT: Final = "SCPN-REACTOR-KERNELS"
KERNEL_DISTRIBUTION: Final = "scpn-reactor-kernels"
KERNEL_BOUNDARY: Final = (
    "Shared physics, geometry, numerics, CAD, and meshing kernels; non-device "
    "library with zero SPO configuration assignments and no solver, control, "
    "safety, or machine-protection authority."
)
KERNEL_DOMAIN: Final = "shared_physics_geometry_and_numerics_kernels"
PIN_FIELDS: Final = frozenset(
    {"distribution", "version", "source_commit", "inventory_sha256", "kernels"}
)
REVERSE_FIELDS: Final = frozenset({"project", "version", "source_commit", "inventory_sha256"})
COMMIT_OBJECT: Final = re.compile(r"^[0-9a-f]{40}$")
HEX_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER: Final = re.compile(r"^[a-z][a-z0-9_]*$")
PEP440_VERSION: Final = re.compile(
    r"^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}"
    r"(?:(?:a|b|rc)(?:0|[1-9]\d*))?"
    r"(?:\.post(?:0|[1-9]\d*))?"
    r"(?:\.dev(?:0|[1-9]\d*))?"
    r"(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$"
)
DEPENDENCY_PIN: Final = re.compile(
    r"scpn-reactor-kernels(?:-native|\[[^\]]+\])?\s*@\s*"
    r"git\+https://github\.com/anulum/scpn-reactor-kernels\.git@([0-9a-f]+)"
)
VERSION_ASSIGNMENT: Final = re.compile(
    rb"^__version__(?:\s*:\s*[^=]+)?\s*=\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)


def _load_object(path: Path) -> dict[str, Any]:
    """Load one JSON object or raise a bounded value error."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: root must be an object")
    return value


def _git_bytes(repo: Path, commit: str, path: str) -> bytes:
    """Read one file from an exact commit after proving commit-object type."""
    object_type = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-t", commit],
        check=False,
        capture_output=True,
        text=True,
    )
    if object_type.returncode != 0 or object_type.stdout.strip() != "commit":
        raise ValueError("source_commit does not resolve to a commit object")
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{path}"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ValueError(f"{path} is absent at source_commit")
    return result.stdout


def _map_projects(machine_map: dict[str, Any], findings: list[str]) -> list[str]:
    """Validate the map topology and return the exact planned-device list."""
    if machine_map.get("schema_version") != MAP_SCHEMA:
        findings.append("map: schema_version must be 1.1.0")
    planned = machine_map.get("planned_repositories")
    existing = machine_map.get("existing_repositories")
    shared = machine_map.get("shared_library_projects")
    assignments = machine_map.get("configuration_assignments")
    if not isinstance(planned, list) or any(
        not isinstance(item, str) or not item for item in planned
    ):
        findings.append("map: planned_repositories must be non-empty strings")
        planned = []
    if not isinstance(existing, list):
        findings.append("map: existing_repositories must be a list")
        existing = []
    if shared != {KERNEL_PROJECT: KERNEL_BOUNDARY}:
        findings.append("map: exact shared-library boundary is missing")
        shared = {} if not isinstance(shared, dict) else shared
    devices = [*planned, *existing]
    if len(devices) != len(set(devices)):
        findings.append("map: device repository classes overlap")
    if set(devices) & set(shared):
        findings.append("map: shared library is also classified as a device")
    if not isinstance(assignments, dict):
        findings.append("map: configuration_assignments must be an object")
    elif any(owner in shared for owner in assignments.values()):
        findings.append("map: shared library owns a configuration")
    return planned


def _pin_findings(
    project: str, manifest: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate a device pin and its exact shared-domain owner exclusion."""
    findings: list[str] = []
    exclusions = manifest.get("excluded_domains")
    owner_rows = (
        [row for row in exclusions if isinstance(row, dict) and row.get("domain") == KERNEL_DOMAIN]
        if isinstance(exclusions, list)
        else []
    )
    if "kernel_library" not in manifest:
        if owner_rows:
            findings.append(f"{project}: owner exclusion exists without a pin")
        return None, findings
    pin = manifest["kernel_library"]
    if not isinstance(pin, dict):
        return None, [f"{project}: kernel_library must be an object"]
    if set(pin) != PIN_FIELDS:
        findings.append(f"{project}: kernel_library fields are not closed")
    if pin.get("distribution") != KERNEL_DISTRIBUTION:
        findings.append(f"{project}: kernel distribution mismatch")
    version = pin.get("version")
    if not isinstance(version, str) or PEP440_VERSION.fullmatch(version) is None:
        findings.append(f"{project}: invalid kernel version")
    commit = pin.get("source_commit")
    if not isinstance(commit, str) or COMMIT_OBJECT.fullmatch(commit) is None:
        findings.append(f"{project}: malformed source_commit")
    digest = pin.get("inventory_sha256")
    if not isinstance(digest, str) or HEX_DIGEST.fullmatch(digest) is None:
        findings.append(f"{project}: malformed inventory_sha256")
    kernels = pin.get("kernels")
    if (
        not isinstance(kernels, list)
        or not kernels
        or any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in kernels)
        or kernels != sorted(set(kernels))
    ):
        findings.append(f"{project}: kernels must be non-empty, unique and sorted")
    if owner_rows != [{"domain": KERNEL_DOMAIN, "owner": KERNEL_PROJECT}]:
        findings.append(f"{project}: exact KERNELS owner exclusion is missing")
    return pin, findings


def _dependency_commits(repo: Path) -> list[str]:
    """Collect every declared Python/native KERNELS source pin."""
    paths = [repo / "pyproject.toml"]
    workflows = repo / ".github" / "workflows"
    if workflows.is_dir():
        paths.extend(sorted(workflows.glob("*.yml")))
        paths.extend(sorted(workflows.glob("*.yaml")))
    commits: list[str] = []
    for path in paths:
        if path.is_file():
            commits.extend(DEPENDENCY_PIN.findall(path.read_text(encoding="utf-8")))
    return commits


def _distribution_version(
    kernels_repo: Path, commit: str, pyproject: dict[str, Any]
) -> str | None:
    """Resolve a static or setuptools dynamic distribution version."""
    project = pyproject.get("project")
    if not isinstance(project, dict):
        return None
    version = project.get("version")
    if isinstance(version, str):
        return version
    dynamic = pyproject.get("tool")
    if not isinstance(dynamic, dict):
        return None
    try:
        attr = dynamic["setuptools"]["dynamic"]["version"]["attr"]
    except (KeyError, TypeError):
        return None
    if not isinstance(attr, str) or "." not in attr:
        return None
    module = attr.rsplit(".", maxsplit=1)[0].replace(".", "/")
    try:
        source = _git_bytes(kernels_repo, commit, f"src/{module}/__init__.py")
    except ValueError:
        return None
    match = VERSION_ASSIGNMENT.search(source)
    return match.group(1).decode("utf-8") if match is not None else None


def _verify_pin(project: str, repo: Path, kernels_repo: Path, pin: dict[str, Any]) -> list[str]:
    """Resolve and verify one structurally valid immutable consumer pin."""
    findings: list[str] = []
    commit = pin.get("source_commit")
    digest = pin.get("inventory_sha256")
    if not isinstance(commit, str) or COMMIT_OBJECT.fullmatch(commit) is None:
        return findings
    try:
        inventory_bytes = _git_bytes(kernels_repo, commit, "kernel-inventory.json")
        pyproject_bytes = _git_bytes(kernels_repo, commit, "pyproject.toml")
    except ValueError as exc:
        return [f"{project}: {exc}"]
    if hashlib.sha256(inventory_bytes).hexdigest() != digest:
        findings.append(f"{project}: pinned inventory digest mismatch")
    try:
        inventory = json.loads(inventory_bytes)
        pyproject = tomllib.loads(pyproject_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError):
        return [*findings, f"{project}: pinned KERNELS metadata is undecodable"]
    library = inventory.get("library") if isinstance(inventory, dict) else None
    if not isinstance(library, dict) or library.get("distribution") != KERNEL_DISTRIBUTION:
        findings.append(f"{project}: pinned inventory distribution mismatch")
    if _distribution_version(kernels_repo, commit, pyproject) != pin.get("version"):
        findings.append(f"{project}: pinned distribution version mismatch")
    inventory_kernels = inventory.get("kernels") if isinstance(inventory, dict) else None
    identifiers = (
        {
            item.get("identifier")
            for item in inventory_kernels
            if isinstance(item, dict) and isinstance(item.get("identifier"), str)
        }
        if isinstance(inventory_kernels, list)
        else set()
    )
    declared = pin.get("kernels")
    if isinstance(declared, list) and not set(declared).issubset(identifiers):
        findings.append(f"{project}: declared kernel absent from pinned inventory")
    dependency_commits = _dependency_commits(repo)
    if not dependency_commits:
        findings.append(f"{project}: no KERNELS dependency pin found")
    elif any(candidate != commit for candidate in dependency_commits):
        findings.append(f"{project}: dependency/workflow pin disagrees with manifest")
    return findings


def check_conformance(
    family_map: Path,
    kernels_repo: Path,
    reverse_inventory: Path,
    device_repos: Sequence[Path],
) -> list[str]:
    """Return all cross-repository conformance findings."""
    try:
        machine_map = _load_object(family_map)
        committed_reverse = _load_object(reverse_inventory)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"input: {exc}"]
    findings: list[str] = []
    planned = _map_projects(machine_map, findings)
    manifests: dict[str, tuple[Path, dict[str, Any]]] = {}
    for repo in device_repos:
        try:
            manifest = _load_object(repo / "reactor-domain.json")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            findings.append(f"{repo.name}: cannot load reactor-domain.json: {exc}")
            continue
        project = manifest.get("project")
        if not isinstance(project, str) or not project:
            findings.append(f"{repo.name}: manifest project is invalid")
            continue
        if project != repo.name:
            findings.append(f"{repo.name}: directory/project identity mismatch")
        if project in manifests:
            findings.append(f"{project}: duplicate device repository")
        manifests[project] = (repo, manifest)
    if set(manifests) != set(planned):
        findings.append("devices: explicit repository set does not equal planned map set")
    expected_rows: list[dict[str, Any]] = []
    for project in sorted(manifests):
        repo, manifest = manifests[project]
        pin, pin_errors = _pin_findings(project, manifest)
        findings.extend(pin_errors)
        if pin is None:
            continue
        if not pin_errors:
            findings.extend(_verify_pin(project, repo, kernels_repo, pin))
        expected_rows.append(
            {
                "project": project,
                "version": pin.get("version"),
                "source_commit": pin.get("source_commit"),
                "inventory_sha256": pin.get("inventory_sha256"),
            }
        )
    reverse_rows = committed_reverse.get("consumers")
    if not isinstance(reverse_rows, list):
        findings.append("reverse inventory: consumers must be a list")
    else:
        if any(not isinstance(row, dict) or set(row) != REVERSE_FIELDS for row in reverse_rows):
            findings.append("reverse inventory: consumer row fields are not closed")
        if reverse_rows != expected_rows:
            findings.append("reverse inventory: rows differ from device authorities")
    return findings


def build_parser() -> argparse.ArgumentParser:
    """Build the explicit, non-discovering command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family-map", type=Path, required=True)
    parser.add_argument("--kernels-repo", type=Path, required=True)
    parser.add_argument("--reverse-inventory", type=Path, required=True)
    parser.add_argument("--device-repo", action="append", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the on-demand cross-repository guard."""
    args = build_parser().parse_args(argv)
    findings = check_conformance(
        args.family_map,
        args.kernels_repo,
        args.reverse_inventory,
        args.device_repo,
    )
    if findings:
        print(f"reactor-kernel-library: FAIL findings={len(findings)}")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("reactor-kernel-library: PASS")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by the imported CLI
    raise SystemExit(main())
