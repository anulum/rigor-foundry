# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Git executable lifetime worker
"""Run public executable discovery while the parent schedules owned-file changes."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from project_registry_syscall_scheduler import arm_native_trace

from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy


def main() -> None:
    """Report constructor acceptance and descriptor settlement after native tracing."""
    executable = Path(sys.argv[1])
    policy = GitTrustPolicy(executable=str(executable), trusted_roots=(str(executable.parent),))
    before = set(os.listdir("/proc/self/fd"))
    arm_native_trace()
    try:
        runner = GitRunner(policy)
    except RuntimeError as exc:
        outcome: dict[str, object] = {"accepted": False, "error": str(exc)}
    else:
        outcome = {"accepted": True, "version": runner.provenance.version}
    outcome["descriptors_restored"] = set(os.listdir("/proc/self/fd")) == before
    print(json.dumps(outcome))


if __name__ == "__main__":
    main()
