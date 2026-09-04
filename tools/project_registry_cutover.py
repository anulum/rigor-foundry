# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry cutover operator
"""Validate or apply one explicit all-consumer project registry transaction."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from rigor_foundry.project_registry_cutover import (
    ProjectRegistryConsumerUpdate,
    ProjectRegistryCutoverPlan,
    apply_project_registry_cutover,
)
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.project_registry_views import ProjectRegistryConsumerOutput

_ABSENT = "ABSENT"


def build_parser() -> argparse.ArgumentParser:
    """Build the explicit cutover parser."""
    parser = argparse.ArgumentParser(
        description="Validate or apply one complete digest-bound project registry cutover."
    )
    parser.add_argument("monorepo", type=Path, help="exact monorepo root")
    parser.add_argument("registry", help="monorepo-relative canonical registry path")
    parser.add_argument("candidate", type=Path, help="canonical candidate registry JSON")
    parser.add_argument("transaction_root", type=Path, help="owner-only transaction directory")
    parser.add_argument(
        "--expected-current",
        required=True,
        help="current registry digest or ABSENT",
    )
    parser.add_argument(
        "--consumer-output",
        action="append",
        default=[],
        type=Path,
        help="canonical consumer output JSON; repeat once per declared consumer",
    )
    parser.add_argument(
        "--expected-consumer",
        action="append",
        default=[],
        help="CONSUMER_ID=DIGEST or CONSUMER_ID=ABSENT; repeat for every consumer",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform the transaction; omission validates the complete plan only",
    )
    return parser


def _optional_digest(value: str) -> str | None:
    return None if value == _ABSENT else value


def _expected_consumers(values: list[str]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for value in values:
        consumer_id, separator, digest = value.partition("=")
        if not separator or not consumer_id or not digest or consumer_id in result:
            raise ValueError("expected-consumer arguments must be unique ID=VALUE pairs")
        result[consumer_id] = _optional_digest(digest)
    return result


def _build_plan(arguments: argparse.Namespace) -> ProjectRegistryCutoverPlan:
    candidate = ProjectRegistry.from_bytes(arguments.candidate.read_bytes())
    expected = _expected_consumers(arguments.expected_consumer)
    outputs = tuple(
        ProjectRegistryConsumerOutput.from_bytes(path.read_bytes())
        for path in arguments.consumer_output
    )
    if len({output.consumer_id for output in outputs}) != len(outputs):
        raise ValueError("consumer-output identities must be unique")
    if set(expected) != {output.consumer_id for output in outputs}:
        raise ValueError("consumer outputs and expected digests must have identical identities")
    updates = tuple(
        ProjectRegistryConsumerUpdate.build(
            output,
            expected_sha256=expected[output.consumer_id],
        )
        for output in outputs
    )
    return ProjectRegistryCutoverPlan.build(
        candidate,
        expected_registry_sha256=_optional_digest(arguments.expected_current),
        updates=updates,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Validate or apply one plan while emitting only fixed status lines."""
    arguments = build_parser().parse_args(argv)
    try:
        plan = _build_plan(arguments)
        if arguments.apply:
            apply_project_registry_cutover(
                arguments.monorepo,
                arguments.registry,
                arguments.transaction_root,
                plan,
            )
    except (OSError, RuntimeError, ValueError):
        print("project-registry-cutover: FAIL")
        return 1
    outcome = "COMMITTED" if arguments.apply else "VALID"
    print(f"project-registry-cutover: {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
