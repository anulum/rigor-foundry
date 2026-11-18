# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Adopter preflight command
"""Wire adopter prerequisites to the installed command."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import asdict
from functools import partial
from pathlib import Path

from .adopter_doctor import diagnose_adopter
from .git_provenance import GitTrustPolicy


def _run(
    args: argparse.Namespace, *, git_policy: Callable[[argparse.Namespace], GitTrustPolicy]
) -> int:
    """Print machine-readable observations and gate unresolved required checks."""
    checks = diagnose_adopter(args.root, args.policy, git_policy(args))
    print(json.dumps({"checks": [asdict(check) for check in checks]}, indent=2))
    return int(any(check.required and check.status != "ready" for check in checks))


def add_doctor_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    add_git_arguments: Callable[[argparse.ArgumentParser], None],
    git_policy: Callable[[argparse.Namespace], GitTrustPolicy],
) -> None:
    """Register the read-only adoption command with the shared Git controls."""
    doctor = subparsers.add_parser(
        "doctor", help="Check repository and runtime prerequisites for an audit."
    )
    doctor.add_argument("--root", type=Path, required=True)
    doctor.add_argument("--policy", type=Path)
    add_git_arguments(doctor)
    doctor.set_defaults(handler=partial(_run, git_policy=git_policy))
