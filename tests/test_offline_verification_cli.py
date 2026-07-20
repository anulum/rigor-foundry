# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification CLI tests
"""Exercise the installed-style CLI boundary with real protocol files."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from offline_verification_fixtures import EVALUATED_AT, trust_policy, verification_bundle

from rigor_foundry.cli import main
from rigor_foundry.offline_verification_models import EvidenceEntry, VerificationBundle
from rigor_foundry.offline_verification_report import OfflineVerificationReport

VERIFICATION_OWNERS = (
    "offline_verification.py",
    "offline_verification_cli.py",
    "offline_verification_models.py",
    "offline_verification_report.py",
    "verification_policy.py",
)
NETWORK_MODULES = {"aiohttp", "http", "httpx", "requests", "socket", "urllib"}


def write_inputs(tmp_path: Path, bundle: VerificationBundle | None = None) -> tuple[Path, Path]:
    """Write one real bundle and caller-selected trust policy."""
    bundle_path = tmp_path / "bundle.json"
    policy_path = tmp_path / "trust-policy.json"
    bundle_path.write_text(
        json.dumps((bundle or verification_bundle()).to_dict()),
        encoding="utf-8",
    )
    policy_path.write_text(json.dumps(trust_policy().to_dict()), encoding="utf-8")
    return bundle_path, policy_path


def command(bundle: Path, policy: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    """Run the actual module CLI in a separate Python process."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "rigor_foundry",
            "verify",
            "--bundle",
            str(bundle),
            "--trust-policy",
            str(policy),
            "--at",
            EVALUATED_AT,
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_real_cli_verifies_to_stdout_without_network_configuration(tmp_path: Path) -> None:
    """A fresh subprocess verifies all four evidence kinds using only local files."""
    bundle, policy = write_inputs(tmp_path)
    result = command(bundle, policy)
    assert result.returncode == 0, result.stderr
    report = OfflineVerificationReport.from_dict(json.loads(result.stdout))
    assert report.status == "verified"
    assert len(report.results) == 4
    assert result.stderr == ""


def test_verification_owners_have_no_network_import_surface() -> None:
    """The complete M3 production lane contains no network client dependency."""
    source_root = Path("src/rigor_foundry")
    imported: set[str] = set()
    for owner in VERIFICATION_OWNERS:
        tree = ast.parse((source_root / owner).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".", 1)[0])
    assert imported.isdisjoint(NETWORK_MODULES)


def test_real_cli_writes_exclusive_output_and_returns_one_for_unavailable(tmp_path: Path) -> None:
    """Output is immutable and explicit missing evidence remains a nonzero result."""
    missing = EvidenceEntry.unavailable(
        "missing",
        "audit-report",
        expected_digest="a" * 64,
        reason="archive not supplied",
    )
    bundle, policy = write_inputs(tmp_path, VerificationBundle.build((missing,)))
    output = tmp_path / "verification.json"
    result = command(bundle, policy, "--output", str(output))
    assert result.returncode == 1, result.stderr
    assert result.stdout == ""
    assert (
        OfflineVerificationReport.from_dict(json.loads(output.read_text(encoding="utf-8"))).status
        == "unavailable"
    )

    repeated = command(bundle, policy, "--output", str(output))
    assert repeated.returncode == 2
    assert "output path already exists" in repeated.stderr


@pytest.mark.parametrize("surface", ("bundle", "policy"))
def test_real_cli_rejects_symlink_and_hardlink_input_aliases(
    tmp_path: Path,
    surface: str,
) -> None:
    """Mutable path aliases cannot cross the verifier's file boundary."""
    bundle, policy = write_inputs(tmp_path)
    selected = bundle if surface == "bundle" else policy
    symlink = tmp_path / f"{surface}-symlink.json"
    symlink.symlink_to(selected)
    arguments = (symlink, policy) if surface == "bundle" else (bundle, symlink)
    result = command(*arguments)
    assert result.returncode == 2
    assert "cannot read" in result.stderr

    hardlink = tmp_path / f"{surface}-hardlink.json"
    os.link(selected, hardlink)
    arguments = (hardlink, policy) if surface == "bundle" else (bundle, hardlink)
    result = command(*arguments)
    assert result.returncode == 2
    assert "single-link regular file" in result.stderr


def test_real_cli_rejects_malformed_and_oversized_documents(tmp_path: Path) -> None:
    """Malformed UTF-8/JSON and oversized input fail before verification."""
    bundle, policy = write_inputs(tmp_path)
    bundle.write_bytes(b"\x00\xff")
    malformed = command(bundle, policy)
    assert malformed.returncode == 2
    assert "cannot read verification bundle" in malformed.stderr

    bundle.unlink()
    bundle.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    oversized = command(bundle, policy)
    assert oversized.returncode == 2
    assert "exceeds 16777216 bytes" in oversized.stderr


def test_cli_reports_platform_without_nofollow_as_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public command fails closed when safe open semantics are unavailable."""
    bundle, policy = write_inputs(tmp_path)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    code = main(
        [
            "verify",
            "--bundle",
            str(bundle),
            "--trust-policy",
            str(policy),
            "--at",
            EVALUATED_AT,
        ]
    )
    assert code == 2
    assert "requires O_NOFOLLOW" in capsys.readouterr().err


def test_cli_rejects_input_identity_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A path mutation observed across the bounded read fails closed."""
    bundle, policy = write_inputs(tmp_path)
    real_fstat = os.fstat
    calls = 0

    def drifting_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            current = real_fstat(descriptor)
            os.utime(bundle, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))
        return real_fstat(descriptor)

    monkeypatch.setattr(os, "fstat", drifting_fstat)
    code = main(
        [
            "verify",
            "--bundle",
            str(bundle),
            "--trust-policy",
            str(policy),
            "--at",
            EVALUATED_AT,
        ]
    )
    assert code == 2
    assert "changed while it was read" in capsys.readouterr().err
