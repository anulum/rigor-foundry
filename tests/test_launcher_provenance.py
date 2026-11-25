# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — resource-limit launcher provenance tests on the real host launcher
"""Verify the attestation of the real util-linux ``prlimit`` launcher and every refusal."""

from __future__ import annotations

import dataclasses
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import pytest

from rigor_foundry.launcher_provenance import (
    PrlimitCompatibilityPolicy,
    canonical_help,
    inspect_prlimit,
    package_identity,
    prlimit_version,
)

POLICY = PrlimitCompatibilityPolicy()
LAUNCHER_REASON = "the host has no dpkg-managed util-linux prlimit"
Decision = Literal["run", "skip", "fail"]


def launcher_decision(environment: Mapping[str, str], platform: str, present: bool) -> Decision:
    """Decide whether the real-launcher tests run, skip or fail on this host.

    Parameters
    ----------
    environment : Mapping[str, str]
        The process environment.
    platform : str
        The ``sys.platform`` value.
    present : bool
        Whether the policy's launcher and package query are regular files.

    Returns
    -------
    Decision
        ``run`` when the launcher is present. ``fail`` on a Linux CI host without it, so a
        runner that loses ``prlimit`` cannot turn every real-launcher test into a silent skip.
        ``skip`` otherwise: off Linux no dpkg-managed util-linux exists, and a local Linux
        host may lack the package.
    """
    if present:
        return "run"
    hosted = environment.get("GITHUB_ACTIONS") == "true" or environment.get("CI", "").lower() in {
        "1",
        "true",
    }
    return "fail" if hosted and platform == "linux" else "skip"


def require_real_launcher(decision: Decision) -> None:
    """Skip or fail the calling test as the decision requires, or let it run.

    Parameters
    ----------
    decision : Decision
        The outcome of ``launcher_decision`` for this host.
    """
    if decision == "fail":
        pytest.fail(f"Linux CI requires the real launcher, but {LAUNCHER_REASON}")
    if decision == "skip":
        pytest.skip(LAUNCHER_REASON)


def admit_real_launcher(
    environment: Mapping[str, str], platform: str, policy: PrlimitCompatibilityPolicy
) -> None:
    """Admit a real-launcher test on this host, or skip or fail it.

    Parameters
    ----------
    environment : Mapping[str, str]
        The process environment.
    platform : str
        The ``sys.platform`` value.
    policy : PrlimitCompatibilityPolicy
        The policy naming the launcher and the package query.
    """
    present = Path(policy.executable_path).is_file() and Path(policy.package_query_path).is_file()
    require_real_launcher(launcher_decision(environment, platform, present))


@pytest.fixture
def real_launcher() -> None:
    """Admit the calling test only on a host with the real launcher, failing in Linux CI."""
    admit_real_launcher(os.environ, sys.platform, POLICY)


OWNER = "util-linux: /usr/bin/prlimit\n"
RECORD = "util-linux|2.39.3-9ubuntu6.6|amd64|install ok installed\n"


@pytest.mark.usefixtures("real_launcher")
def test_the_real_launcher_is_attested_within_the_policy() -> None:
    """The host's prlimit is root-owned, dpkg-associated, in the interval and has --fsize."""
    provenance = inspect_prlimit()
    record = provenance.to_dict()
    assert record["policy_digest"] == POLICY.policy_digest
    assert prlimit_version(f"prlimit from util-linux {provenance.semantic_version}\n", POLICY)
    assert record["package_version"] == provenance.package_version != ""
    assert len(provenance.identity_digest) == 64 == len(provenance.capability_digest)
    assert inspect_prlimit().identity_digest == provenance.identity_digest


@pytest.mark.usefixtures("real_launcher")
def test_a_policy_naming_an_absent_option_refuses_the_real_launcher() -> None:
    """A feature the launcher does not offer refuses the inspection."""
    with pytest.raises(RuntimeError, match="required prlimit option is unavailable"):
        inspect_prlimit(
            dataclasses.replace(POLICY, required_options=("--fsize", "--no-such-limit"))
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"package_name": "procps"}, "must be util-linux"),
        ({"minimum_version": "3.0.0"}, "interval must be non-empty"),
        ({"required_options": ()}, "sorted and unique"),
        ({"required_options": ("--fsize", "--fsize")}, "sorted and unique"),
        ({"required_options": ("--nproc", "--fsize")}, "sorted and unique"),
        ({"required_options": ("-f",)}, "long option names"),
        ({"required_owner_uid": -1}, "owner and mode mask must be valid"),
        ({"required_owner_uid": True}, "owner and mode mask must be valid"),
        ({"require_single_link": 1}, "single-link policy must be Boolean"),
        ({"forbidden_mode_bits": 0o10000}, "owner and mode mask must be valid"),
        ({"executable_path": "usr/bin/prlimit"}, "canonical absolute"),
    ],
)
def test_an_ambiguous_policy_is_refused(changes: dict[str, Any], message: str) -> None:
    """Another package, an empty interval, unsorted options, a non-root owner or a relative path.

    Parameters
    ----------
    changes : dict[str, Any]
        The changed policy fields.
    message : str
        Text the refusal must contain.
    """
    with pytest.raises(ValueError, match=message):
        dataclasses.replace(POLICY, **changes)


def test_the_version_response_names_util_linux_within_the_interval() -> None:
    """A descriptor-number or program-name response passes; anything else is refused."""
    assert prlimit_version("4 from util-linux 2.39.3\n", POLICY) == "2.39.3"
    assert prlimit_version("prlimit from util-linux 2.37.0\n", POLICY) == "2.37.0"
    for output, message in (
        ("4 from util-linux 2.39.3\nextra\n", "response is invalid"),
        ("bwrap from util-linux 2.39.3\n", "response is invalid"),
        ("", "response is invalid"),
        ("4 from util-linux 2.40\n", "not a stable release"),
        ("4 from util-linux 2.36.9\n", "outside the supported interval"),
        ("4 from util-linux 3.0.0\n", "outside the supported interval"),
    ):
        with pytest.raises(RuntimeError, match=message):
            prlimit_version(output, POLICY)


def test_the_help_text_names_the_program_instead_of_its_descriptor() -> None:
    """Usage lines that name a descriptor number are rewritten; other lines are kept."""
    observed = (
        "\nUsage:\n 4 [options] [--<resource>=<limit>] COMMAND\n -f, --fsize  maximum size\n"
    )
    assert canonical_help(observed) == (
        "\nUsage:\n prlimit [options] [--<resource>=<limit>] COMMAND\n -f, --fsize  maximum size\n"
    )
    assert "--fsize" in canonical_help(observed).split()


def test_the_package_must_own_the_path_and_be_installed_exactly() -> None:
    """The dpkg association, the record shape, the version form and the status are all required."""
    assert package_identity(OWNER, RECORD, POLICY) == ("2.39.3-9ubuntu6.6", "amd64")
    assert package_identity(OWNER, "util-linux:amd64|2.39.3|amd64|install ok installed\n", POLICY)
    for owner, record, message in (
        ("procps: /usr/bin/prlimit\n", RECORD, "dpkg association"),
        (OWNER + OWNER, RECORD, "dpkg association"),
        (OWNER, "util-linux|2.39.3|amd64\n", "record is invalid"),
        (OWNER, RECORD + RECORD, "record is invalid"),
        (OWNER, "procps|2.39.3|amd64|install ok installed\n", "record is invalid"),
        (
            OWNER,
            "util-linux|2.39 3|amd64|install ok installed\n",
            "invalid version or architecture",
        ),
        (
            OWNER,
            "util-linux|2.39.3|amd64|deinstall ok config-files\n",
            "not installed in the required state",
        ),
    ):
        with pytest.raises(RuntimeError, match=message):
            package_identity(owner, record, POLICY)


def _fake_launcher(
    root: Path,
    *,
    replace_on_help: bool,
    second_owner: str | None = None,
    second_record: str | None = None,
) -> PrlimitCompatibilityPolicy:
    """Write real launcher and dpkg-query processes owned by the test user, and their policy."""
    root.mkdir(parents=True, exist_ok=True)
    launcher, query = root / "prlimit", root / "dpkg-query"
    replacement = (
        f"open({str(launcher)!r}, 'ab').write(b'# replaced\\n')" if replace_on_help else "None"
    )
    launcher.write_text(
        "#!/usr/bin/python3\nimport os, sys\n"
        "if sys.argv[1:] == ['--version']:\n    os.write(1, b'4 from util-linux 2.39.3\\n')\n"
        f"elif sys.argv[1:] == ['--help']:\n    {replacement}\n    os.write(1, b' -f, --fsize  maximum size\\n')\n"
        "else:\n    raise SystemExit(64)\n",
        encoding="utf-8",
    )
    state = root / "query-count"
    owners = (
        f"util-linux: {launcher}\n".encode(),
        (second_owner or f"util-linux: {launcher}\n").encode(),
    )
    records = (
        b"util-linux|2.39.3-1|amd64|install ok installed\n",
        (second_record or "util-linux|2.39.3-1|amd64|install ok installed\n").encode(),
    )
    query.write_text(
        "#!/usr/bin/python3\nimport os, sys\nfrom pathlib import Path\n"
        f"state = Path({str(state)!r})\n"
        "count = int(state.read_text()) if state.exists() else 0\n"
        "state.write_text(str(count + 1))\n"
        f"answers = {owners!r} if sys.argv[1] == '--search' else {records!r}\n"
        "os.write(1, answers[0 if count < 2 else 1])\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    query.chmod(0o755)
    return dataclasses.replace(
        POLICY,
        executable_path=str(launcher),
        package_query_path=str(query),
        required_owner_uid=os.getuid(),
    )


def test_real_fixture_processes_are_attested_and_a_replacement_is_refused(tmp_path: Path) -> None:
    """Launcher and query processes pass the inspection; a launcher changed on --help does not.

    Parameters
    ----------
    tmp_path : Path
        Owned launcher fixture allocation.
    """
    provenance = inspect_prlimit(_fake_launcher(tmp_path / "steady", replace_on_help=False))
    assert (provenance.semantic_version, provenance.package_version) == ("2.39.3", "2.39.3-1")
    with pytest.raises(RuntimeError, match="changed during inspection"):
        inspect_prlimit(_fake_launcher(tmp_path / "replaced", replace_on_help=True))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        (
            {"second_owner": "util-linux: /usr/bin/other\n"},
            "package ownership changed during inspection",
        ),
        (
            {"second_record": "util-linux|2.40.0-1|amd64|install ok installed\n"},
            "package record changed during inspection",
        ),
    ],
)
def test_a_package_database_change_during_inspection_is_refused(
    tmp_path: Path, changes: dict[str, str], message: str
) -> None:
    """The ownership and the record are queried again after the help check and must be equal.

    Parameters
    ----------
    tmp_path : Path
        Owned launcher fixture allocation.
    changes : dict[str, str]
        The query's second answer for one of the two queries.
    message : str
        Text the refusal must contain.
    """
    with pytest.raises(RuntimeError, match=message):
        inspect_prlimit(_fake_launcher(tmp_path / "changing", replace_on_help=False, **changes))


@pytest.mark.parametrize(
    ("environment", "platform", "present", "expected"),
    [
        ({}, "linux", True, "run"),
        ({"GITHUB_ACTIONS": "true"}, "linux", True, "run"),
        ({}, "linux", False, "skip"),
        ({"GITHUB_ACTIONS": "false", "CI": "false"}, "linux", False, "skip"),
        ({"GITHUB_ACTIONS": "true"}, "linux", False, "fail"),
        ({"CI": "true"}, "linux", False, "fail"),
        ({"CI": "1"}, "linux", False, "fail"),
        ({"GITHUB_ACTIONS": "true", "CI": "true"}, "win32", False, "skip"),
        ({"CI": "true"}, "darwin", False, "skip"),
    ],
)
def test_a_missing_launcher_fails_in_linux_ci_and_skips_elsewhere(
    environment: dict[str, str], platform: str, present: bool, expected: Decision
) -> None:
    """Only a Linux CI host without the launcher fails; a present launcher always runs.

    Parameters
    ----------
    environment : dict[str, str]
        The process environment.
    platform : str
        The ``sys.platform`` value.
    present : bool
        Whether the launcher and package query exist.
    expected : Decision
        The required decision.
    """
    assert launcher_decision(environment, platform, present) == expected


def test_the_decision_skips_or_fails_the_calling_test() -> None:
    """A fail decision fails with its reason, a skip decision skips, and run does neither."""
    with pytest.raises(pytest.fail.Exception, match="Linux CI requires the real launcher"):
        require_real_launcher("fail")
    with pytest.raises(pytest.skip.Exception, match="dpkg-managed util-linux prlimit"):
        require_real_launcher("skip")
    require_real_launcher("run")


def test_a_host_without_the_launcher_fails_in_linux_ci_and_skips_locally(tmp_path: Path) -> None:
    """A policy naming absent files fails the test under Linux CI and skips it elsewhere.

    Parameters
    ----------
    tmp_path : Path
        Owned allocation for absent and present launcher files.
    """
    absent = dataclasses.replace(
        POLICY,
        executable_path=str(tmp_path / "absent" / "prlimit"),
        package_query_path=str(tmp_path / "absent" / "dpkg-query"),
    )
    with pytest.raises(pytest.fail.Exception, match="Linux CI requires the real launcher"):
        admit_real_launcher({"GITHUB_ACTIONS": "true"}, "linux", absent)
    with pytest.raises(pytest.skip.Exception, match="dpkg-managed util-linux prlimit"):
        admit_real_launcher({}, "linux", absent)
    (tmp_path / "prlimit").write_bytes(b"")
    (tmp_path / "dpkg-query").write_bytes(b"")
    present = dataclasses.replace(
        POLICY,
        executable_path=str(tmp_path / "prlimit"),
        package_query_path=str(tmp_path / "dpkg-query"),
    )
    admit_real_launcher({"GITHUB_ACTIONS": "true"}, "linux", present)
