# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native sandbox provenance tests
"""Verify fail-closed Bubblewrap compatibility and package provenance."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.sandbox_provenance import (
    BubblewrapCompatibilityPolicy,
    BubblewrapProvenance,
    inspect_bubblewrap,
)


def _write_executable(path: Path, body: str) -> Path:
    """Write one executable test tool."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _fake_policy(
    tmp_path: Path,
    *,
    version: str = "0.9.0",
    help_options: str = "--disable-userns --unshare-user",
    version_output: bytes | None = None,
    version_stderr: bytes = b"",
    version_exit: int = 0,
    owner_outputs: tuple[bytes, bytes] | None = None,
    record_outputs: tuple[bytes, bytes] | None = None,
    replace_bwrap_on_help: bool = False,
) -> BubblewrapCompatibilityPolicy:
    """Create stateful real Bubblewrap and dpkg-query process fixtures."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    bwrap_path = tmp_path / "bwrap"
    observed_version = version_output or f"bubblewrap {version}\n".encode()
    replacement = (
        f"open({str(bwrap_path)!r}, 'ab').write(b'# replaced\\\\n')"
        if replace_bwrap_on_help
        else "None"
    )
    bwrap = _write_executable(
        bwrap_path,
        "#!/usr/bin/python3\n"
        "import os\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        f"    os.write(1, {observed_version!r})\n"
        f"    os.write(2, {version_stderr!r})\n"
        f"    raise SystemExit({version_exit})\n"
        "if sys.argv[1:] == ['--help']:\n"
        f"    {replacement}\n"
        f"    os.write(1, {(help_options + chr(10)).encode()!r})\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(64)\n",
    )
    owner_pair = owner_outputs or (
        f"bubblewrap: {bwrap}\n".encode(),
        f"bubblewrap: {bwrap}\n".encode(),
    )
    record_pair = record_outputs or (
        b"bubblewrap|0.9.0-1ubuntu0.1|amd64|install ok installed\n",
        b"bubblewrap|0.9.0-1ubuntu0.1|amd64|install ok installed\n",
    )
    owner_state = tmp_path / "owner-query-count"
    record_state = tmp_path / "record-query-count"
    query = _write_executable(
        tmp_path / "dpkg-query",
        "#!/usr/bin/python3\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"owner_outputs = {owner_pair!r}\n"
        f"record_outputs = {record_pair!r}\n"
        f"owner_state = Path({str(owner_state)!r})\n"
        f"record_state = Path({str(record_state)!r})\n"
        "def emit(state, outputs):\n"
        "    count = int(state.read_text()) if state.exists() else 0\n"
        "    state.write_text(str(count + 1))\n"
        "    os.write(1, outputs[min(count, len(outputs) - 1)])\n"
        "if sys.argv[1] == '--search':\n"
        "    emit(owner_state, owner_outputs)\n"
        "elif sys.argv[1] == '--show':\n"
        "    emit(record_state, record_outputs)\n"
        "else:\n"
        "    raise SystemExit(64)\n",
    )
    return BubblewrapCompatibilityPolicy(
        executable_path=str(bwrap),
        package_query_path=str(query),
        required_options=("--disable-userns", "--unshare-user"),
        required_owner_uid=os.getuid(),
    )


def test_real_bubblewrap_provenance_is_complete_and_round_trips() -> None:
    """The required host sandbox exposes inspectable package and feature identity."""
    provenance = inspect_bubblewrap()

    assert provenance.executable_path == "/usr/bin/bwrap"
    assert provenance.semantic_version.startswith("0.9.")
    assert provenance.package_provider == "dpkg"
    assert provenance.package_name == "bubblewrap"
    assert provenance.package_version
    assert provenance.package_architecture
    assert provenance.package_status == "install ok installed"
    assert len(provenance.executable_digest) == 64
    assert len(provenance.package_query_digest) == 64
    assert len(provenance.capability_digest) == 64
    assert BubblewrapProvenance.from_dict(provenance.to_dict()) == provenance
    assert (
        BubblewrapCompatibilityPolicy.from_dict(provenance.policy.to_dict()) == provenance.policy
    )


def test_real_capability_identity_is_independent_of_descriptor_allocation() -> None:
    """Unrelated live descriptors cannot alter the canonical Bubblewrap help identity."""
    baseline = inspect_bubblewrap()
    descriptors = [os.open("/dev/null", os.O_RDONLY) for _ in range(7)]
    try:
        shifted = inspect_bubblewrap()
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    assert shifted == baseline


def test_fake_package_provenance_is_bound_to_policy_and_capabilities(tmp_path: Path) -> None:
    """A deterministic package fixture produces one fully bound identity."""
    policy = _fake_policy(tmp_path)
    provenance = inspect_bubblewrap(policy)

    assert provenance.policy == policy
    assert provenance.policy_digest == policy.policy_digest
    assert provenance.semantic_version == "0.9.0"
    assert provenance.package_version == "0.9.0-1ubuntu0.1"
    assert BubblewrapProvenance.from_dict(provenance.to_dict()) == provenance


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (lambda: BubblewrapCompatibilityPolicy(package_provider="rpm"), "provider must be dpkg"),
        (lambda: BubblewrapCompatibilityPolicy(package_name="other"), "name must be bubblewrap"),
        (
            lambda: BubblewrapCompatibilityPolicy(minimum_version="1.0.0"),
            "interval must be non-empty",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(minimum_version="0.9.0-alpha"),
            "stable three-part semantic version",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(
                required_options=("--unshare-user", "--unshare-user")
            ),
            "sorted and unique",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(required_options=("short",)),
            "long option names",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(
                required_package_status="deinstall ok config-files"
            ),
            "must be install ok installed",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(required_owner_uid=-1),
            "non-negative integer",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(required_owner_uid=cast(int, "0")),
            "non-negative integer",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(forbidden_mode_bits=0o10000),
            "valid mode mask",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(forbidden_mode_bits=cast(int, "022")),
            "valid mode mask",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(require_single_link=cast(bool, 1)),
            "must be Boolean",
        ),
        (
            lambda: BubblewrapCompatibilityPolicy(executable_path="relative/bwrap"),
            "canonical absolute",
        ),
    ],
)
def test_policy_rejects_ambiguous_or_weakened_contracts(
    factory: Callable[[], BubblewrapCompatibilityPolicy],
    message: str,
) -> None:
    """Policy construction rejects unsupported providers, paths, modes, and ranges."""
    with pytest.raises(ValueError, match=message):
        factory()


def test_policy_parser_rejects_schema_shape_and_non_boolean_fields(tmp_path: Path) -> None:
    """Persisted policy parsing rejects missing, extra, and ambiguous fields."""
    policy = _fake_policy(tmp_path)
    invalid_schema = policy.to_dict()
    invalid_schema["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="unsupported Bubblewrap policy schema"):
        BubblewrapCompatibilityPolicy.from_dict(invalid_schema)

    invalid_boolean = policy.to_dict()
    invalid_boolean["require_single_link"] = 1
    with pytest.raises(ValueError, match="must be Boolean"):
        BubblewrapCompatibilityPolicy.from_dict(invalid_boolean)

    missing = policy.to_dict()
    del missing["package_name"]
    with pytest.raises(ValueError, match="missing=package_name"):
        BubblewrapCompatibilityPolicy.from_dict(missing)

    extra = policy.to_dict()
    extra["implicit_default"] = True
    with pytest.raises(ValueError, match="extra=implicit_default"):
        BubblewrapCompatibilityPolicy.from_dict(extra)


def test_inspection_rejects_unsupported_version_and_missing_feature(tmp_path: Path) -> None:
    """Version and required-option compatibility failures remain explicit errors."""
    old_policy = _fake_policy(tmp_path / "old", version="0.8.9")
    with pytest.raises(ValueError, match="outside compatibility policy"):
        inspect_bubblewrap(old_policy)

    missing_policy = _fake_policy(tmp_path / "missing", help_options="--unshare-user")
    with pytest.raises(RuntimeError, match="compatibility option is unavailable"):
        inspect_bubblewrap(missing_policy)


def test_inspection_rejects_symlink_hardlink_and_unsafe_mode(tmp_path: Path) -> None:
    """Trusted executable metadata rejects path aliasing and writable launchers."""
    policy = _fake_policy(tmp_path / "base")
    target = Path(policy.executable_path)
    symlink = tmp_path / "bwrap-link"
    symlink.symlink_to(target)
    with pytest.raises(RuntimeError, match="unavailable"):
        inspect_bubblewrap(replace(policy, executable_path=str(symlink)))

    hardlink = tmp_path / "bwrap-hardlink"
    hardlink.hardlink_to(target)
    with pytest.raises(RuntimeError, match="must have one link"):
        inspect_bubblewrap(policy)
    hardlink.unlink()

    query = Path(policy.package_query_path)
    query.chmod(0o777)
    with pytest.raises(RuntimeError, match="unsafe mode bits"):
        inspect_bubblewrap(policy)


def test_inspection_rejects_intermediate_symlink_and_elevated_id_mode(tmp_path: Path) -> None:
    """No-follow component walks and mode policy cover parent links and set-ID bits."""
    real_parent = tmp_path / "real"
    policy = _fake_policy(real_parent)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    linked_policy = replace(
        policy,
        executable_path=str(linked_parent / "bwrap"),
        package_query_path=str(linked_parent / "dpkg-query"),
    )
    with pytest.raises(RuntimeError, match="unavailable"):
        inspect_bubblewrap(linked_policy)

    Path(policy.executable_path).chmod(0o4755)
    with pytest.raises(RuntimeError, match="unsafe mode bits"):
        inspect_bubblewrap(policy)


def test_snapshot_rejects_non_regular_wrong_owner_and_non_executable(tmp_path: Path) -> None:
    """Launcher snapshots enforce file type, owner, and executable-mode policy."""
    policy = _fake_policy(tmp_path / "base")
    with pytest.raises(RuntimeError, match="not a regular file"):
        inspect_bubblewrap(replace(policy, executable_path=str(tmp_path)))

    with pytest.raises(RuntimeError, match="untrusted owner"):
        inspect_bubblewrap(replace(policy, required_owner_uid=os.getuid() + 1))

    executable = Path(policy.executable_path)
    executable.chmod(0o644)
    with pytest.raises(RuntimeError, match="not owner-executable"):
        inspect_bubblewrap(policy)


def test_single_link_requirement_can_be_explicitly_relaxed(tmp_path: Path) -> None:
    """The complete policy records and honours an explicit multi-link allowance."""
    policy = _fake_policy(tmp_path)
    alias = tmp_path / "bwrap-alias"
    alias.hardlink_to(Path(policy.executable_path))

    provenance = inspect_bubblewrap(replace(policy, require_single_link=False))

    assert not provenance.policy.require_single_link
    assert provenance.executable_digest


def test_inspection_detects_executable_replacement_during_metadata_queries(
    tmp_path: Path,
) -> None:
    """A launcher changed after observation cannot produce attested provenance."""
    policy = _fake_policy(tmp_path, replace_bwrap_on_help=True)
    with pytest.raises(RuntimeError, match="changed during inspection"):
        inspect_bubblewrap(policy)


@pytest.mark.parametrize(
    ("version_output", "version_stderr", "version_exit", "message"),
    [
        (b"bubblewrap 0.9.0\n", b"", 3, "returned failure"),
        (b"bubblewrap 0.9.0\n", b"warning\n", 0, "wrote to stderr"),
        (b"\xff", b"", 0, "was not UTF-8"),
        (b"x" * 9000, b"", 0, "exceeded output limit"),
        (b"", b"x" * 9000, 0, "exceeded output limit"),
    ],
)
def test_inspection_rejects_real_metadata_process_failures(
    tmp_path: Path,
    version_output: bytes,
    version_stderr: bytes,
    version_exit: int,
    message: str,
) -> None:
    """Public inspection normalises exit, encoding, stderr, and output failures."""
    policy = _fake_policy(
        tmp_path,
        version_output=version_output,
        version_stderr=version_stderr,
        version_exit=version_exit,
    )
    with pytest.raises(RuntimeError, match=message):
        inspect_bubblewrap(policy)


def test_provenance_parser_rejects_unknown_fields_and_identity_tampering(
    tmp_path: Path,
) -> None:
    """Offline parsing rejects schema drift and altered package evidence."""
    provenance = inspect_bubblewrap(_fake_policy(tmp_path))
    extra = provenance.to_dict()
    extra["undeclared"] = True
    with pytest.raises(ValueError, match="extra=undeclared"):
        BubblewrapProvenance.from_dict(extra)

    changed = provenance.to_dict()
    changed["package_version"] = "0.9.0-attack"
    with pytest.raises(ValueError, match="identity digest"):
        BubblewrapProvenance.from_dict(changed)

    changed_policy = provenance.to_dict()
    policy = dict(cast(dict[str, object], changed_policy["policy"]))
    policy["minimum_version"] = "0.9.1"
    changed_policy["policy"] = policy
    with pytest.raises(ValueError, match="policy digest"):
        BubblewrapProvenance.from_dict(changed_policy)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "2.0", "unsupported Bubblewrap provenance schema"),
        ("executable_path", "/opt/bwrap", "path does not match policy"),
        ("package_provider", "other", "provider does not match policy"),
        ("package_query_path", "/opt/dpkg-query", "query path does not match policy"),
        ("package_name", "other", "name does not match policy"),
        ("package_status", "deinstall ok config-files", "not installed"),
        ("package_architecture", "bad/arch", "architecture is invalid"),
        ("package_version", "bad/version", "package version is invalid"),
        ("semantic_version", "0.8.9", "outside compatibility policy"),
    ],
)
def test_provenance_parser_rejects_policy_inconsistent_observations(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    """Offline evidence cannot contradict its embedded compatibility policy."""
    document = inspect_bubblewrap(_fake_policy(tmp_path)).to_dict()
    document[field] = value
    with pytest.raises(ValueError, match=message):
        BubblewrapProvenance.from_dict(document)


@pytest.mark.parametrize(
    ("outputs", "message"),
    [
        (
            (
                "bubblewrap: {path}\n",
                "bubblewrap|0.9.0-1|amd64|install ok installed\n",
                "bubblewrap 0.9\n",
                "--disable-userns --unshare-user\n",
            ),
            "semantic version",
        ),
        (
            (
                "bubblewrap: {path}\n",
                "bubblewrap|0.9.0-1|amd64|install ok installed\n",
                "other 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "version response is invalid",
        ),
        (
            (
                "two\nowners\n",
                "bubblewrap|0.9.0-1|amd64|install ok installed\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "ownership response is invalid",
        ),
        (
            (
                "other: {path}\n",
                "bubblewrap|0.9.0-1|amd64|install ok installed\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "lacks the required dpkg association",
        ),
        (
            (
                "bubblewrap: {path}\n",
                "broken\nrecord\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "package record response is invalid",
        ),
        (
            (
                "bubblewrap: {path}\n",
                "broken|record\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "package record response is invalid",
        ),
        (
            (
                "bubblewrap: {path}\n",
                "other|0.9.0-1|amd64|install ok installed\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "unexpected package name",
        ),
        (
            (
                "bubblewrap: {path}\n",
                "bubblewrap||amd64|install ok installed\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "invalid version or architecture",
        ),
        (
            (
                "bubblewrap: {path}\n",
                "bubblewrap|0.9.0-1|amd64|deinstall ok config-files\n",
                "bubblewrap 0.9.0\n",
                "--disable-userns --unshare-user\n",
            ),
            "not installed in the required state",
        ),
    ],
)
def test_inspection_rejects_malformed_command_responses(
    tmp_path: Path,
    outputs: tuple[str, str, str, str],
    message: str,
) -> None:
    """Malformed version, ownership, and package records fail closed."""
    bwrap_path = tmp_path / "bwrap"
    owner, record, version, help_output = (output.format(path=bwrap_path) for output in outputs)
    policy = _fake_policy(
        tmp_path,
        version_output=version.encode(),
        help_options=help_output.rstrip("\n"),
        owner_outputs=(owner.encode(), owner.encode()),
        record_outputs=(record.encode(), record.encode()),
    )
    with pytest.raises((RuntimeError, ValueError), match=message):
        inspect_bubblewrap(policy)


@pytest.mark.parametrize(
    ("change_owner", "message"),
    [
        (True, "ownership changed during inspection"),
        (False, "record changed during inspection"),
    ],
)
def test_inspection_rejects_package_database_changes(
    tmp_path: Path,
    change_owner: bool,
    message: str,
) -> None:
    """Package ownership and metadata must remain stable across inspection."""
    bwrap_path = tmp_path / "bwrap"
    owner = f"bubblewrap: {bwrap_path}\n"
    record = "bubblewrap|0.9.0-1|amd64|install ok installed\n"
    owner_after = "other: /other\n" if change_owner else owner
    record_after = record if change_owner else "bubblewrap|0.9.0-2|amd64|install ok installed\n"
    policy = _fake_policy(
        tmp_path,
        owner_outputs=(owner.encode(), owner_after.encode()),
        record_outputs=(record.encode(), record_after.encode()),
    )
    with pytest.raises(RuntimeError, match=message):
        inspect_bubblewrap(policy)
