# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public registry process worker
"""Enter real registry load, cutover and recovery APIs under native observation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from project_registry_syscall_scheduler import arm_native_trace
from test_project_registry_cutover import REGISTRY_PATH, plan

from rigor_foundry.project_registry_cutover import (
    ProjectRegistryCutoverInvalid,
    apply_project_registry_cutover,
    load_project_registry_state,
)
from rigor_foundry.project_registry_models import ProjectRegistry
from rigor_foundry.project_registry_recovery import recover_project_registry_cutover
from rigor_foundry.project_registry_views import build_registry_consumer_outputs


def main() -> None:
    """Invoke the selected public operation on explicit test fixture inputs."""
    operation, root_text, transactions_text, candidate_text = sys.argv[1:]
    root, transactions = Path(root_text), Path(transactions_text)
    candidate = ProjectRegistry.from_bytes(Path(candidate_text).read_bytes())
    previous_path = root / REGISTRY_PATH
    prior_outputs = (
        build_registry_consumer_outputs(ProjectRegistry.from_bytes(previous_path.read_bytes()), {})
        if operation == "apply" and previous_path.exists()
        else ()
    )
    cutover = plan(candidate, previous_outputs=prior_outputs)
    arm_native_trace()
    try:
        if operation == "load":
            result = load_project_registry_state(root, REGISTRY_PATH)
            outcome = result.registry_sha256
        elif operation == "apply":
            outcome = apply_project_registry_cutover(
                root, REGISTRY_PATH, transactions, cutover
            ).outcome
        elif operation == "recover":
            outcome = recover_project_registry_cutover(
                root,
                REGISTRY_PATH,
                transactions,
                candidate.generation_id,
                candidate.registry_sha256,
            ).outcome
        else:
            raise ValueError("unsupported public registry worker operation")
    except ProjectRegistryCutoverInvalid as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}))
    else:
        print(json.dumps({"accepted": True, "outcome": outcome}))


if __name__ == "__main__":
    main()
