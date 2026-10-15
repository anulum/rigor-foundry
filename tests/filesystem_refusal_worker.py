# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public filesystem refusal process worker
"""Enter public bootstrap or Git operations under owned native syscall observation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from project_registry_syscall_scheduler import arm_native_trace

from rigor_foundry.bootstrap import bootstrap_repository
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy


def main() -> None:
    """Run one explicit fixture operation and report its actual public outcome.

    Raises
    ------
    OSError, RuntimeError
        Native tracing cannot start for this owned Linux x86-64 worker.
    """
    operation, root_text = sys.argv[1:]
    root = Path(root_text)
    policy = GitTrustPolicy(trusted_roots=(str(root / "tools"),))
    runner = GitRunner(policy) if operation == "git-pinning" else None
    arm_native_trace()
    try:
        if operation == "bootstrap":
            result = bootstrap_repository(
                root,
                policy_path=Path("config/policy.json"),
                todo_path=Path("private-todo/TODO.md"),
                review_ledger_path=Path("private-ledger/reviews.json"),
                source_roots=(Path("src"),),
                test_roots=(Path("tests"),),
            )
            outcome = result.policy_digest
        elif operation == "git-hashing":
            outcome = GitRunner(policy).provenance.executable_digest
        elif operation == "git-pinning" and runner is not None:
            outcome = runner.run(root, "--version").stdout.decode("utf-8").strip()
        else:
            raise ValueError("unsupported filesystem worker operation")
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}))
    else:
        print(json.dumps({"accepted": True, "outcome": outcome}))


if __name__ == "__main__":
    main()
