# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Resource-bounded preflight tests
"""Verify local preflight never embeds the exhaustive test suite."""

import shutil
import sys
import time
from pathlib import Path

import pytest

from rigor_foundry.version import __version__
from tools._repository import ROOT
from tools.preflight import PreflightStep, preflight_commands, run_preflight_steps


def test_local_preflight_never_embeds_the_exhaustive_test_suite() -> None:
    """Full tests remain an explicit remote or owner-authorised operation."""
    for fast in (False, True):
        steps = preflight_commands(fast=fast)
        rendered = "\n".join(" ".join(step.argv) for step in steps)
        assert sys.executable in rendered
        assert "pytest" not in rendered
        assert all(step.timeout_seconds > 0 for step in steps)


def test_fast_preflight_omits_distribution_and_documentation_builds() -> None:
    """The pre-push path remains bounded without weakening static gates."""
    rendered = "\n".join(" ".join(step.argv) for step in preflight_commands(fast=True))
    assert "mkdocs" not in rendered
    assert " build " not in rendered
    assert "tools.check_descriptive_production_naming" in rendered
    assert "tools.audit" in rendered


def test_preflight_stops_when_an_executable_is_unavailable(tmp_path: Path) -> None:
    """A missing executable prevents later preflight commands from running."""
    marker = tmp_path / "later-step.txt"
    missing = PreflightStep((str(tmp_path / "missing-executable"),), 10)
    later = PreflightStep(
        (sys.executable, "-c", "from pathlib import Path; Path('later-step.txt').touch()"), 10
    )
    assert run_preflight_steps((missing, later), tmp_path) == 127
    assert not marker.exists()


@pytest.mark.parametrize("valid_metadata", [True, False])
def test_preflight_validates_the_current_built_distribution_pair(
    tmp_path: Path, valid_metadata: bool
) -> None:
    """Use the actual build and metadata CLI without reading a prior dist directory."""
    for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE"):
        shutil.copyfile(ROOT / name, tmp_path / name)
    shutil.copytree(ROOT / "src", tmp_path / "src", ignore=shutil.ignore_patterns("__pycache__"))
    tools = tmp_path / "tools"
    tools.mkdir()
    shutil.copyfile(
        ROOT / "tools/check_distribution_metadata.py", tools / "check_distribution_metadata.py"
    )
    readme = tmp_path / "README.md"
    if not valid_metadata:
        install = f'python -m pip install "rigor-foundry=={__version__}"'
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                install, "Refer to the installation guide."
            ),
            encoding="utf-8",
        )
    previous = tmp_path / "dist"
    previous.mkdir()
    old_artifact = previous / "previous-build.whl"
    old_artifact.write_bytes(b"retained output")
    fresh = tmp_path / "preflight"
    packaging = preflight_commands(fast=False, distribution_directory=fresh)[-3:]
    assert run_preflight_steps(packaging[:2], tmp_path) == (0 if valid_metadata else 1)
    assert old_artifact.read_bytes() == b"retained output"
    verify_members = PreflightStep(
        (
            sys.executable,
            "-c",
            "import sys, tarfile, zipfile; "
            "assert zipfile.is_zipfile(sys.argv[1]) and tarfile.is_tarfile(sys.argv[2])",
        ),
        10,
        packaging[-1].distribution_outputs,
    )
    assert run_preflight_steps((verify_members,), tmp_path) == 0
    (sdist,) = fresh.glob("*.tar.gz")
    sdist.unlink()
    assert run_preflight_steps(packaging[-1:], tmp_path) == 1


def test_preflight_terminates_a_command_that_exceeds_its_budget(tmp_path: Path) -> None:
    """A stalled gate cannot hang the bounded local preflight indefinitely."""
    step = PreflightStep(
        (sys.executable, "-c", "import time; time.sleep(10)"),
        timeout_seconds=1,
    )
    started = time.monotonic()
    assert run_preflight_steps((step,), tmp_path) == 124
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("invalid_root", ["src", "tools", "tests", "fuzz", "benchmarks", None])
def test_typing_preflight_checks_every_maintained_python_root(
    tmp_path: Path, invalid_root: str | None
) -> None:
    """The real compiler refuses a type defect in each root and accepts valid input.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory containing all five maintained Python roots.
    invalid_root : str or None
        Maintained root containing a type error, or None for valid input.
    """
    for number, root in enumerate(("src", "tools", "tests", "fuzz", "benchmarks")):
        directory = tmp_path / root
        directory.mkdir()
        value = '"wrong type"' if root == invalid_root else "1"
        (directory / f"typed_owner_{number}.py").write_text(
            f'"""Declare one value checked by the real typing gate."""\nvalue: int = {value}\n',
            encoding="utf-8",
        )
    typing_step = next(step for step in preflight_commands(fast=True) if "mypy" in step.argv)
    assert run_preflight_steps((typing_step,), tmp_path) == (0 if invalid_root is None else 1)
