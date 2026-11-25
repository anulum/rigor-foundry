# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the package imports where sealed memory files do not exist
"""Prove the package and its CLI import without ``fcntl`` or seals, and the channel refuses closed.

The import witnesses run in a fresh interpreter, because a module-level ``import fcntl`` has
already run in this one before any test could remove it. Each witness fails on a package that
reads ``fcntl`` or a seal constant at import. Both preludes work on every platform: one makes
``fcntl`` unimportable, as on Windows, and the other installs an empty stand-in without any
seal name, as on macOS or an interpreter built without the seals.
"""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from rigor_foundry.sarif_import_channel import SecondOutputChannel
from rigor_foundry.sarif_import_document import SarifImportRefused

ROOT = Path(__file__).resolve().parents[1]
WITHOUT_FCNTL = "import sys\nsys.modules['fcntl'] = None\n"
WITHOUT_SEALS = "import sys, types\nsys.modules['fcntl'] = types.ModuleType('fcntl')\n"
IMPORT_AND_OPEN = (
    "import rigor_foundry, rigor_foundry.cli, rigor_foundry.sarif_import_cli\n"
    "from rigor_foundry.sarif_import_channel import SecondOutputChannel\n"
    "from rigor_foundry.sarif_import_document import SarifImportRefused\n"
    "try:\n"
    "    SecondOutputChannel()\n"
    "except SarifImportRefused as refused:\n"
    "    print(refused.reason, refused)\n"
)


def _fresh_interpreter(prelude: str) -> subprocess.CompletedProcess[str]:
    """Import the package and open a channel in a new interpreter after ``prelude`` ran."""
    source = str(ROOT / "src")
    path = os.pathsep.join(item for item in (source, os.environ.get("PYTHONPATH", "")) if item)
    return subprocess.run(
        [sys.executable, "-c", prelude + IMPORT_AND_OPEN],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env={**os.environ, "PYTHONPATH": path},
    )


@pytest.mark.parametrize(
    ("prelude", "detail"),
    [
        (WITHOUT_FCNTL, "the platform has no fcntl to seal a second output"),
        (WITHOUT_SEALS, "the interpreter has no memory file seals"),
    ],
)
def test_the_package_and_cli_import_and_the_channel_refuses_closed(
    prelude: str, detail: str
) -> None:
    """Without ``fcntl``, as on Windows, or without the seals, as on macOS, the package imports.

    Parameters
    ----------
    prelude : str
        Code that removes ``fcntl`` or its seal constants before the package is imported.
    detail : str
        Text the channel's refusal must contain.
    """
    done = _fresh_interpreter(prelude)
    assert done.returncode == 0, done.stderr
    assert (
        done.stdout.startswith("channel-unavailable channel-unavailable: ")
        and detail in done.stdout
    )


def test_a_missing_fcntl_refuses_the_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    """A platform whose ``fcntl`` cannot be imported refuses the channel before any file.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Makes ``import fcntl`` fail in this interpreter for this test.
    """
    monkeypatch.setitem(sys.modules, "fcntl", None)
    with pytest.raises(SarifImportRefused, match="no fcntl to seal") as refused:
        SecondOutputChannel()
    assert refused.value.reason == "channel-unavailable"


@pytest.mark.parametrize(
    "missing",
    ["F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"],
)
def test_a_control_module_without_one_seal_name_refuses_the_channel(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    """Every seal constant and seal operation is required, one at a time.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Installs a control module that lacks exactly one name.
    missing : str
        The name the control module lacks.
    """
    names = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_WRITE",
        "F_SEAL_GROW",
        "F_SEAL_SHRINK",
        "F_SEAL_SEAL",
    )
    control = types.ModuleType("fcntl")
    for value, name in enumerate(names, start=1):
        if name != missing:
            setattr(control, name, value)
    monkeypatch.setitem(sys.modules, "fcntl", control)
    with pytest.raises(SarifImportRefused, match="no memory file seals") as refused:
        SecondOutputChannel()
    assert refused.value.reason == "channel-unavailable"


@pytest.mark.parametrize("missing", ["memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING"])
def test_a_platform_without_sealable_memory_files_refuses_the_channel(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    """With the seals but without memory files or their flags, the channel is refused.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Installs complete seal names and removes one memory file name from ``os``.
    missing : str
        The ``os`` name removed.
    """
    control = types.ModuleType("fcntl")
    for value, name in enumerate(
        (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        ),
        start=1,
    ):
        setattr(control, name, value)
    monkeypatch.setitem(sys.modules, "fcntl", control)
    monkeypatch.delattr(os, missing, raising=False)
    with pytest.raises(SarifImportRefused, match="no sealable anonymous memory files") as refused:
        SecondOutputChannel()
    assert refused.value.reason == "channel-unavailable"


@pytest.mark.parametrize("control", [None, types.ModuleType("fcntl")])
def test_a_refused_channel_never_creates_a_memory_file(
    monkeypatch: pytest.MonkeyPatch, control: types.ModuleType | None
) -> None:
    """The seals are resolved before any file exists, so a refusal leaks no descriptor.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Removes ``fcntl`` or its seal names, and records every memory file creation.
    control : types.ModuleType | None
        No ``fcntl`` at all, or one without any seal name.
    """
    created: list[str] = []

    def recorder(name: str, flags: int = 0) -> int:
        created.append(name)
        return -1

    monkeypatch.setitem(sys.modules, "fcntl", control)
    monkeypatch.setattr(os, "memfd_create", recorder, raising=False)
    with pytest.raises(SarifImportRefused) as refused:
        SecondOutputChannel()
    assert refused.value.reason == "channel-unavailable" and created == []
