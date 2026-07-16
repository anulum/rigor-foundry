# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Resource-bounded preflight orchestration
"""Run production gates while leaving the exhaustive test suite to CI."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from tools._repository import ROOT


@dataclass(frozen=True)
class PreflightStep:
    """One explicit command and its hard wall-clock budget."""

    argv: tuple[str, ...]
    timeout_seconds: int


def preflight_commands(*, fast: bool) -> tuple[PreflightStep, ...]:
    """Return the explicit, shell-free preflight command contract."""
    python = sys.executable
    commands = [
        PreflightStep((python, "-m", "tools.audit"), 180),
        PreflightStep((python, "-m", "ruff", "check", "src", "tests", "tools"), 180),
        PreflightStep(
            (python, "-m", "ruff", "format", "--check", "src", "tests", "tools"),
            180,
        ),
        PreflightStep(
            (python, "-m", "mypy", "--strict", "src/rigor_foundry", "tools"),
            300,
        ),
        PreflightStep(
            (
                python,
                "-m",
                "bandit",
                "-q",
                "-c",
                "pyproject.toml",
                "-r",
                "src/rigor_foundry",
                "tools",
            ),
            300,
        ),
        PreflightStep((python, "-m", "reuse", "lint"), 180),
    ]
    if not fast:
        commands.extend(
            [
                PreflightStep((python, "-m", "mkdocs", "build", "--strict"), 180),
                PreflightStep((python, "-m", "build", "--no-isolation"), 300),
                PreflightStep((python, "-m", "twine", "check", "dist/*"), 180),
            ]
        )
    return tuple(commands)


def run_preflight_steps(steps: tuple[PreflightStep, ...], root: Path) -> int:
    """Run explicit preflight steps and stop on the first failure.

    Parameters
    ----------
    steps:
        Shell-free commands with positive wall-clock budgets.
    root:
        Existing repository root used as every command's working directory.
    """
    for step in steps:
        command = step.argv
        if command[-1] == "dist/*":
            distributions = tuple(str(path) for path in sorted((root / "dist").glob("*")))
            command = (*command[:-1], *distributions)
            if not distributions:
                print("preflight: distribution build produced no files", file=sys.stderr)
                return 1
        print(f"preflight: {' '.join(command[1:])}")
        try:
            result = subprocess.run(
                command,
                cwd=root,
                check=False,
                timeout=step.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            print(
                f"preflight: command exceeded {step.timeout_seconds}s wall-clock budget",
                file=sys.stderr,
            )
            return 124
        if result.returncode:
            return result.returncode
    return 0


def run_preflight(root: Path = ROOT, *, fast: bool = False) -> int:
    """Run the repository preflight contract.

    Parameters
    ----------
    root:
        Existing repository root.
    fast:
        Omit documentation and distribution builds when true.
    """
    return run_preflight_steps(preflight_commands(fast=fast), root)


def main() -> int:
    """Run preflight gates sequentially and stop on the first failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast", action="store_true", help="skip docs and distribution builds")
    arguments = parser.parse_args()
    returncode = run_preflight(fast=arguments.fast)
    if returncode:
        return returncode
    print("Preflight passed; exhaustive tests remain a CI-only gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
