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
from tempfile import TemporaryDirectory

from tools._repository import ROOT


@dataclass(frozen=True)
class PreflightStep:
    """One explicit command and its hard wall-clock budget."""

    argv: tuple[str, ...]
    timeout_seconds: int
    distribution_outputs: tuple[Path, ...] = ()


def preflight_commands(
    *, fast: bool, distribution_directory: Path = Path("dist")
) -> tuple[PreflightStep, ...]:
    """Return the explicit, shell-free preflight command contract.

    Parameters
    ----------
    fast:
        Omit documentation and distribution builds when true.
    distribution_directory:
        Output directory supplied to the build and artifact checks.

    Returns
    -------
    tuple[PreflightStep, ...]
        Ordered gate commands, each using the current interpreter and a finite
        wall-clock budget. Static Python gates include every maintained root.
    """
    python = sys.executable
    python_roots = ("src", "tools", "tests", "fuzz", "benchmarks")
    commands = [
        PreflightStep((python, "-m", "tools.check_descriptive_production_naming"), 60),
        PreflightStep((python, "-m", "tools.audit"), 180),
        PreflightStep((python, "-m", "ruff", "check", *python_roots), 180),
        PreflightStep(
            (python, "-m", "ruff", "format", "--check", *python_roots),
            180,
        ),
        PreflightStep(
            (python, "-m", "mypy", "--strict", *python_roots),
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
                PreflightStep(
                    (
                        python,
                        "-m",
                        "build",
                        "--no-isolation",
                        "--outdir",
                        str(distribution_directory),
                    ),
                    300,
                ),
                PreflightStep(
                    (python, "-m", "tools.check_distribution_metadata"),
                    180,
                    (distribution_directory / "*.whl",),
                ),
                PreflightStep(
                    (python, "-m", "twine", "check"),
                    180,
                    (distribution_directory / "*.whl", distribution_directory / "*.tar.gz"),
                ),
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
        for pattern in step.distribution_outputs:
            distributions = tuple(
                path for path in (root / pattern.parent).glob(pattern.name) if path.is_file()
            )
            if len(distributions) != 1:
                print(
                    f"preflight: expected exactly one distribution matching {pattern.name}",
                    file=sys.stderr,
                )
                return 1
            command = (*command, str(distributions[0]))
        print(f"preflight: {' '.join(command[1:])}", flush=True)
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
        except FileNotFoundError:
            print("preflight: command or repository directory is unavailable", file=sys.stderr)
            return 127
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
    if fast:
        return run_preflight_steps(preflight_commands(fast=True), root)
    with TemporaryDirectory(prefix="rigor-foundry-preflight-") as distribution_directory:
        commands = preflight_commands(
            fast=False, distribution_directory=Path(distribution_directory)
        )
        return run_preflight_steps(commands, root)


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
