# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Expiring dependency-waiver guard
"""Validate bounded security-tool dependency exceptions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from tools._repository import ROOT, redacted_guard_exit_code

WAIVER_PATH = Path(".github/dependency-waivers.json")
SECURITY_LOCK = Path("requirements/security.txt")
SECURITY_WORKFLOW = Path(".github/workflows/security.yml")
EXPECTED_COMMAND = "semgrep scan --error --config .semgrep.yml src tools"
MAX_WAIVER_LIFETIME = timedelta(days=30)
REQUIRED_FIELDS = frozenset(
    {
        "advisory_id",
        "aliases",
        "package",
        "version",
        "scope",
        "introduced_by",
        "affected_api",
        "allowed_command",
        "rationale",
        "mitigations",
        "reviewed_on",
        "expires_on",
        "advisory_url",
    }
)


@dataclass(frozen=True)
class WaiverSpec:
    """Immutable identity and reachability contract for one advisory."""

    aliases: tuple[str, ...]
    package: str
    affected_api: str
    advisory_url: str


WAIVER_SPECS = {
    "PYSEC-2026-2132": WaiverSpec(
        aliases=("CVE-2026-7246", "GHSA-47fr-3ffg-hgmw"),
        package="click",
        affected_api="click.edit",
        advisory_url=(
            "https://github.com/tsigouris007/security-advisories/security/advisories/"
            "GHSA-47fr-3ffg-hgmw"
        ),
    ),
    "CVE-2026-52869": WaiverSpec(
        aliases=("GHSA-jpw9-pfvf-9f58",),
        package="mcp",
        affected_api="authenticated stateful MCP HTTP server transports",
        advisory_url="https://github.com/advisories/GHSA-jpw9-pfvf-9f58",
    ),
    "CVE-2026-52870": WaiverSpec(
        aliases=("GHSA-hvrp-rf83-w775",),
        package="mcp",
        affected_api="experimental MCP server task handlers",
        advisory_url="https://github.com/advisories/GHSA-hvrp-rf83-w775",
    ),
    "CVE-2026-59950": WaiverSpec(
        aliases=("GHSA-vj7q-gjh5-988w",),
        package="mcp",
        affected_api="deprecated MCP WebSocket server transport",
        advisory_url="https://github.com/advisories/GHSA-vj7q-gjh5-988w",
    ),
}


def _locked_version(text: str, package: str) -> str | None:
    match = re.search(rf"^{re.escape(package)}==([^\s\\]+)", text, re.MULTILINE)
    return match.group(1) if match else None


def _parse_date(value: object, field: str, errors: list[str]) -> date | None:
    if not isinstance(value, str):
        errors.append(f"dependency waiver {field} must be an ISO date")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"dependency waiver {field} must be an ISO date")
        return None


def _load_document(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot read dependency waivers: {error}")
        return None
    if not isinstance(value, dict):
        errors.append("dependency-waiver document must be a JSON object")
        return None
    return value


def dependency_waiver_errors(root: Path = ROOT, *, today: date | None = None) -> list[str]:
    """Return failures for stale, widened, or unbound dependency waivers."""
    errors: list[str] = []
    document = _load_document(root / WAIVER_PATH, errors)
    if document is None:
        return errors
    if document.get("schema_version") != "1.0":
        errors.append("dependency-waiver schema_version must be '1.0'")
    waivers = document.get("waivers")
    if not isinstance(waivers, list) or not all(isinstance(item, dict) for item in waivers):
        errors.append("dependency-waiver set must be a list of objects")
        return errors

    lock_text = (root / SECURITY_LOCK).read_text(encoding="utf-8")
    locked_semgrep = _locked_version(lock_text, "semgrep")
    current = today or datetime.now(UTC).date()
    workflow = (root / SECURITY_WORKFLOW).read_text(encoding="utf-8")
    for fragment in ("python -m tools.check_dependency_waivers", EXPECTED_COMMAND):
        if fragment not in workflow:
            errors.append(f"security workflow is not bound to dependency waiver: {fragment}")

    advisory_ids = [waiver.get("advisory_id") for waiver in waivers]
    expected_ids = set(WAIVER_SPECS)
    actual_ids = {value for value in advisory_ids if isinstance(value, str)}
    if len(advisory_ids) != len(actual_ids):
        errors.append("dependency-waiver advisory IDs must be unique strings")
    if actual_ids != expected_ids:
        expected = ", ".join(sorted(expected_ids))
        errors.append(f"dependency-waiver set must contain exactly: {expected}")

    for waiver in waivers:
        advisory_id = waiver.get("advisory_id")
        if not isinstance(advisory_id, str) or advisory_id not in WAIVER_SPECS:
            continue
        spec = WAIVER_SPECS[advisory_id]
        missing = sorted(REQUIRED_FIELDS.difference(waiver))
        if missing:
            errors.append(
                f"dependency waiver {advisory_id} is missing fields: {', '.join(missing)}"
            )
        unexpected = sorted(set(waiver).difference(REQUIRED_FIELDS))
        if unexpected:
            errors.append(
                f"dependency waiver {advisory_id} has unexpected fields: {', '.join(unexpected)}"
            )
        expected_fields: dict[str, object] = {
            "aliases": list(spec.aliases),
            "package": spec.package,
            "scope": SECURITY_LOCK.as_posix(),
            "affected_api": spec.affected_api,
            "allowed_command": EXPECTED_COMMAND,
            "advisory_url": spec.advisory_url,
        }
        for field, required in expected_fields.items():
            if waiver.get(field) != required:
                errors.append(f"dependency waiver {advisory_id} {field} must be {required!r}")

        locked_package = _locked_version(lock_text, spec.package)
        if waiver.get("version") != locked_package:
            errors.append(
                f"dependency waiver {advisory_id} version does not match the security lock"
            )
        if waiver.get("introduced_by") != f"semgrep=={locked_semgrep}":
            errors.append(
                f"dependency waiver {advisory_id} introduced_by does not match the security lock"
            )

        reviewed = _parse_date(waiver.get("reviewed_on"), f"{advisory_id} reviewed_on", errors)
        expires = _parse_date(waiver.get("expires_on"), f"{advisory_id} expires_on", errors)
        if reviewed is not None and reviewed > current:
            errors.append(f"dependency waiver {advisory_id} review date is in the future")
        if expires is not None and expires <= current:
            errors.append(f"dependency waiver {advisory_id} is expired")
        if reviewed is not None and expires is not None:
            lifetime = expires - reviewed
            if lifetime <= timedelta(0) or lifetime > MAX_WAIVER_LIFETIME:
                errors.append(
                    f"dependency waiver {advisory_id} lifetime must be between 1 and 30 days"
                )

        rationale = waiver.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"dependency waiver {advisory_id} rationale must be non-empty")
        mitigations = waiver.get("mitigations")
        if (
            not isinstance(mitigations, list)
            or len(mitigations) < 3
            or not all(isinstance(item, str) and item.strip() for item in mitigations)
        ):
            errors.append(
                f"dependency waiver {advisory_id} must contain at least three "
                "non-empty mitigations"
            )

        ignore_fragment = f"--ignore-vuln {advisory_id}"
        if ignore_fragment not in workflow:
            errors.append(
                f"security workflow is not bound to dependency waiver: {ignore_fragment}"
            )
    return errors


def main() -> int:
    """Validate the dependency waiver and return a process exit code."""
    return redacted_guard_exit_code("Dependency-waiver guard", dependency_waiver_errors)


if __name__ == "__main__":
    raise SystemExit(main())
