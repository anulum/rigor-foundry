# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only project-memory activation plan check
"""Validate private activation proposal files without changing any live state."""

from __future__ import annotations

import argparse
from pathlib import Path

from rigor_foundry.project_memory_activation_plan import validate_project_memory_activation_plan
from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_MAX_INDEX_BYTES,
    PROJECT_MEMORY_MAX_MANIFEST_BYTES,
)
from rigor_foundry.project_memory_store import _read_private_file
from rigor_foundry.project_registry_cutover import (
    PROJECT_REGISTRY_MAX_TRANSACTION_BYTES,
    ProjectRegistryConsumerUpdate,
    ProjectRegistryCutoverPlan,
)
from rigor_foundry.project_registry_models import (
    PROJECT_REGISTRY_MAX_BYTES,
    PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
    PROJECT_REGISTRY_MAX_CONSUMERS,
    ProjectRegistry,
)
from rigor_foundry.project_registry_views import ProjectRegistryConsumerOutput


def main(argv: list[str] | None = None) -> int:
    """Check bounded owner-only input files and emit a content-free disposition.

    Parameters
    ----------
    argv:
        Explicit arguments, or None to read process arguments. There is no
        apply flag: this command cannot issue a live-admission decision.

    Returns
    -------
    int
        Zero for a consistent proposal, one for rejected input. Argument
        syntax failures use argparse's exit code two.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous_registry", type=Path)
    parser.add_argument("candidate_registry", type=Path)
    parser.add_argument("memory_manifest", type=Path)
    parser.add_argument("bootstrap_manifest", type=Path)
    parser.add_argument("bootstrap_index", type=Path)
    parser.add_argument("--previous-output", type=Path, action="append", default=[])
    parser.add_argument("--candidate-output", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    remaining = PROJECT_REGISTRY_MAX_TRANSACTION_BYTES

    def read(path: Path, *, label: str, maximum: int) -> bytes:
        nonlocal remaining
        payload = _read_private_file(path, label=label, maximum=min(maximum, remaining))
        remaining -= len(payload)
        return payload

    try:
        if (
            max(len(args.previous_output), len(args.candidate_output))
            > PROJECT_REGISTRY_MAX_CONSUMERS
        ):
            raise ValueError("consumer input count exceeds bound")
        previous = ProjectRegistry.from_bytes(
            read(
                args.previous_registry,
                label="previous registry",
                maximum=PROJECT_REGISTRY_MAX_BYTES,
            )
        )
        candidate = ProjectRegistry.from_bytes(
            read(
                args.candidate_registry,
                label="candidate registry",
                maximum=PROJECT_REGISTRY_MAX_BYTES,
            )
        )
        memory = ProjectMemoryManifest.from_bytes(
            read(
                args.memory_manifest,
                label="memory proposal",
                maximum=PROJECT_MEMORY_MAX_MANIFEST_BYTES,
            )
        )
        previous_outputs = tuple(
            ProjectRegistryConsumerOutput.from_bytes(
                read(path, label="previous consumer", maximum=PROJECT_REGISTRY_MAX_CONSUMER_BYTES)
            )
            for path in args.previous_output
        )
        candidate_outputs = tuple(
            ProjectRegistryConsumerOutput.from_bytes(
                read(path, label="candidate consumer", maximum=PROJECT_REGISTRY_MAX_CONSUMER_BYTES)
            )
            for path in args.candidate_output
        )
        expected = {output.consumer_id: output.output_sha256 for output in previous_outputs}
        cutover = ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=previous.registry_sha256,
            updates=tuple(
                ProjectRegistryConsumerUpdate.build(
                    output, expected_sha256=expected.get(output.consumer_id)
                )
                for output in candidate_outputs
            ),
        )
        validate_project_memory_activation_plan(
            previous,
            previous_outputs,
            cutover,
            memory,
            bootstrap_manifest=read(
                args.bootstrap_manifest,
                label="bootstrap manifest",
                maximum=PROJECT_MEMORY_MAX_MANIFEST_BYTES,
            ),
            bootstrap_index=read(
                args.bootstrap_index,
                label="bootstrap index",
                maximum=PROJECT_MEMORY_MAX_INDEX_BYTES,
            ),
        )
    except (OSError, RuntimeError, ValueError):
        print("project-memory-activation-plan: FAIL")
        return 1
    print("project-memory-activation-plan: VALIDATED_NOT_AUTHORISED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
