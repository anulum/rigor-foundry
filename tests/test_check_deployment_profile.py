# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deployment profile command tests
"""Exercise profile validation at the actual process and private-file boundaries."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_deployment_profile import encode_profile, profile_document

from rigor_foundry.deployment_profile import DeploymentProfile
from tools.check_deployment_profile import main


@pytest.mark.parametrize("layout", ["03_CODE/SCIENCE", "06_WEBMASTER", "workspace/science"])
def test_cli_validates_real_private_profile_without_modification(
    tmp_path: Path, layout: str
) -> None:
    payload = encode_profile(profile_document(layout))
    profile = DeploymentProfile.from_bytes(payload)
    path = tmp_path / "profile.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    command = [
        sys.executable,
        "-m",
        "tools.check_deployment_profile",
        str(path),
        "--sha256",
        profile.profile_sha256,
        "--group",
        "SCIENCE",
        "--project",
        "PROJECT",
    ]
    success = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert success.returncode == 0 and success.stderr == ""
    assert success.stdout == "deployment-profile: VALIDATED_NOT_AUTHORISED\n"
    assert path.read_bytes() == payload
    command[command.index("--sha256") + 1] = "0" * 64
    refusal = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert refusal.returncode == 1 and refusal.stderr == ""
    assert refusal.stdout == "deployment-profile: FAIL\n"
    assert path.read_bytes() == payload


@pytest.mark.parametrize("change", ["mode", "symlink", "hardlink", "fifo", "missing", "malformed"])
def test_cli_refuses_unsafe_private_input(tmp_path: Path, change: str) -> None:
    payload = encode_profile(profile_document())
    path = tmp_path / "profile.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    digest = DeploymentProfile.from_bytes(payload).profile_sha256
    if change == "mode":
        path.chmod(0o644)
    elif change == "symlink":
        retained = tmp_path / "retained.json"
        path.rename(retained)
        path.symlink_to(retained)
    elif change == "hardlink":
        os.link(path, tmp_path / "other.json")
    elif change == "malformed":
        path.write_bytes(b"{}")
    else:
        path.unlink()
        if change == "fifo":
            os.mkfifo(path, 0o600)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.check_deployment_profile",
            str(path),
            "--sha256",
            digest,
            "--group",
            "SCIENCE",
            "--project",
            "PROJECT",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert result.stdout == "deployment-profile: FAIL\n"


def test_embedded_cli_uses_the_same_private_file_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = encode_profile(profile_document())
    path = tmp_path / "profile.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    digest = DeploymentProfile.from_bytes(payload).profile_sha256
    assert main([str(path), "--sha256", digest, "--group", "SCIENCE", "--project", "PROJECT"]) == 0
    assert capsys.readouterr().out == "deployment-profile: VALIDATED_NOT_AUTHORISED\n"


def test_public_parser_normalises_excessive_nesting_in_a_real_process() -> None:
    """An isolated default runtime rejects nested input through the documented error type."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from rigor_foundry.deployment_profile import DeploymentProfile
try:
    DeploymentProfile.from_bytes(b'[' * 10000 + b'0' + b']' * 10000)
except ValueError as error:
    assert str(error) == 'profile nesting exceeds parser capacity'
    print('refused')
else:
    raise SystemExit('unexpected acceptance')
""",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and result.stderr == ""
    assert result.stdout == "refused\n"
