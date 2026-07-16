# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Expiring dependency-waiver guard
"""Validate the one bounded security-tool dependency exception."""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from tools._repository import ROOT, redacted_guard_exit_code

WAIVER_PATH = Path(".github/dependency-waivers.json")
SECURITY_LOCK = Path("requirements/security.txt")
SECURITY_WORKFLOW = Path(".github/workflows/security.yml")
ADVISORY_ID = "PYSEC-2026-2132"
EXPECTED_PACKAGE = "click"
EXPECTED_AFFECTED_API = "click.edit"
EXPECTED_COMMAND = "semgrep scan --error --config .semgrep.yml src tools"
EXPECTED_ADVISORY_URL = (
    "https://github.com/tsigouris007/security-advisories/security/advisories/GHSA-47fr-3ffg-hgmw"
)
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
    if not isinstance(waivers, list) or len(waivers) != 1 or not isinstance(waivers[0], dict):
        errors.append(f"dependency-waiver set must contain exactly {ADVISORY_ID}")
        return errors
    waiver = waivers[0]
    missing = sorted(REQUIRED_FIELDS.difference(waiver))
    if missing:
        errors.append(f"dependency waiver is missing fields: {', '.join(missing)}")
    expected = {
        "advisory_id": ADVISORY_ID,
        "package": EXPECTED_PACKAGE,
        "scope": SECURITY_LOCK.as_posix(),
        "affected_api": EXPECTED_AFFECTED_API,
        "allowed_command": EXPECTED_COMMAND,
        "advisory_url": EXPECTED_ADVISORY_URL,
    }
    for field, required in expected.items():
        if waiver.get(field) != required:
            errors.append(f"dependency waiver {field} must be {required!r}")

    lock_text = (root / SECURITY_LOCK).read_text(encoding="utf-8")
    locked_click = _locked_version(lock_text, EXPECTED_PACKAGE)
    locked_semgrep = _locked_version(lock_text, "semgrep")
    if waiver.get("version") != locked_click:
        errors.append("dependency waiver version does not match the security lock")
    if waiver.get("introduced_by") != f"semgrep=={locked_semgrep}":
        errors.append("dependency waiver introduced_by does not match the security lock")

    reviewed = _parse_date(waiver.get("reviewed_on"), "reviewed_on", errors)
    expires = _parse_date(waiver.get("expires_on"), "expires_on", errors)
    current = today or datetime.now(UTC).date()
    if reviewed is not None and reviewed > current:
        errors.append("dependency waiver review date is in the future")
    if expires is not None and expires <= current:
        errors.append(f"dependency waiver {ADVISORY_ID} is expired")
    if reviewed is not None and expires is not None:
        lifetime = expires - reviewed
        if lifetime <= timedelta(0) or lifetime > MAX_WAIVER_LIFETIME:
            errors.append("dependency waiver lifetime must be between 1 and 30 days")

    rationale = waiver.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        errors.append("dependency waiver rationale must be non-empty")
    mitigations = waiver.get("mitigations")
    if (
        not isinstance(mitigations, list)
        or len(mitigations) < 3
        or not all(isinstance(item, str) and item.strip() for item in mitigations)
    ):
        errors.append("dependency waiver must contain at least three non-empty mitigations")

    workflow = (root / SECURITY_WORKFLOW).read_text(encoding="utf-8")
    required_fragments = (
        "python -m tools.check_dependency_waivers",
        f"--ignore-vuln {ADVISORY_ID}",
        EXPECTED_COMMAND,
    )
    for fragment in required_fragments:
        if fragment not in workflow:
            errors.append(f"security workflow is not bound to dependency waiver: {fragment}")
    return errors


def main() -> int:
    """Validate the dependency waiver and return a process exit code."""
    errors = dependency_waiver_errors()
    return redacted_guard_exit_code("Dependency-waiver guard", errors)


if __name__ == "__main__":
    raise SystemExit(main())
