# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Git inventory protocol refusal tests
"""Exercise scanner refusals at the public trusted-executable boundary."""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main

_REVISION = "rev-parse HEAD HEAD^{tree} --show-object-format"
_INDEX = "ls-files --stage -z"
_STATUS = "status --porcelain=v1 -z --untracked-files=no"
_OID = b"1" * 40
_ENTRY = b"100644 " + _OID + b" 0\t"
_FORMAT = b"\n" + _OID + b"\n"
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX executable-contract fixture")


def _trusted_program(home: Path, repo: GitRepository, body: str) -> Path:
    """Create a trusted executable that otherwise delegates to installed Git."""
    home.mkdir()
    launcher = home / "git"
    launcher.write_text(
        f'#!/bin/sh\n{body}\nexec {shlex.quote(repo.git)} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    return launcher


def _trust_arguments(launcher: Path) -> list[str]:
    """Select the absolute executable through the public CLI."""
    return ["--git-trust-root", str(launcher.parent), "--git-executable", str(launcher)]


@pytest.mark.parametrize(
    ("command", "reply", "diagnostic"),
    [
        (_REVISION, _OID + b"\n", "invalid revision record"),
        (_REVISION, _FORMAT + b"sha1\n", "empty HEAD"),
        (_REVISION, _OID + _FORMAT + b"unrecognised\n", "unsupported object format"),
        (_INDEX, b"incomplete\0", "malformed staged entry"),
        (_INDEX, b"100000 " + _OID + b" 0\tmodule.py\0", "unsupported mode"),
        (_INDEX, b"100644 invalid 0\tmodule.py\0", "invalid object id"),
        (_INDEX, (_ENTRY + b"module.py\0") * 2, "duplicate tracked paths"),
        (_INDEX, _ENTRY + b"/undeliverable.py\0", "tracked path escapes repository root"),
        (_INDEX, _ENTRY + b"\0", "malformed staged entry"),
        (_INDEX, _ENTRY + b".\0", "tracked path is empty"),
        (_STATUS, b"x\0", "malformed record"),
        (_STATUS, b"R  module.py\0", "rename record is incomplete"),
    ],
)
def test_scan_refuses_trusted_executable_protocol_fault_and_recovers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    reply: bytes,
    diagnostic: str,
) -> None:
    """The installed scanner refuses one faulty response and rereads real Git."""
    repo = GitRepository.create(tmp_path / "repository")
    module = repo.write_text("module.py", "VALUE = 1\n")
    head = repo.commit()
    index = repo.root / ".git/index"
    original_index = index.read_bytes()
    octets = "".join(f"\\{byte:03o}" for byte in reply)
    launcher = _trusted_program(
        tmp_path / "tools",
        repo,
        f'case "$*" in *" {command}") printf "%b" "{octets}"; exit 0;; esac',
    )
    output = tmp_path / "audit.json"
    args = ["scan", "--root", str(repo.root), "--json-out", str(output)]
    assert main([*args, *_trust_arguments(launcher)]) == 2
    refused = capsys.readouterr()
    assert diagnostic in refused.err
    assert not output.exists()
    assert index.read_bytes() == original_index
    assert module.read_text(encoding="utf-8") == "VALUE = 1\n"
    assert main(args) == 0
    assert head in output.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("command", "replacement", "diagnostic"),
    [
        ("rev-parse --show-toplevel", "plain_file", "repository root is not a directory"),
        (_INDEX, "symbolic_link", "cannot open tracked parent"),
    ],
)
def test_scan_refuses_live_root_replacement_after_real_git(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    replacement: str,
    diagnostic: str,
) -> None:
    """Replace the real worktree path after Git reads it, then restore and rescan."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text("module.py", "VALUE = 1\n")
    head = repo.commit()
    moved = tmp_path / "displaced"
    source = shlex.quote(str(repo.root))
    target = shlex.quote(str(moved))
    move, link = shutil.which("mv"), shutil.which("ln")
    assert move is not None and link is not None
    replace_root = (
        f'printf "%s" "replacement" > {source}'
        if replacement == "plain_file"
        else f"{shlex.quote(link)} -s {target} {source}"
    )
    launcher = _trusted_program(
        tmp_path / "tools",
        repo,
        f'case "$*" in *" {command}")\n'
        f'  {shlex.quote(repo.git)} "$@" || exit "$?"\n'
        f"  {shlex.quote(move)} {source} {target} && {replace_root}\n"
        "  exit $?;; esac",
    )
    output = tmp_path / "audit.json"
    args = ["scan", "--root", str(repo.root), "--json-out", str(output)]
    assert main([*args, *_trust_arguments(launcher)]) == 2
    assert diagnostic in capsys.readouterr().err
    assert not output.exists()
    assert (moved / "module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    repo.root.unlink()
    moved.rename(repo.root)
    assert main(args) == 0
    assert head in output.read_text(encoding="utf-8")
