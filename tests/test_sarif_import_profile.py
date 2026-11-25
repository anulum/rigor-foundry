# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — import-only adapter profile tests
"""Verify the import-only profile, its command, and that no native audit reader can name it."""

from __future__ import annotations

from pathlib import Path

import pytest

from rigor_foundry.adapter_profiles import PROFILE_EVIDENCE_SCHEMA_VERSION, profile_by_name
from rigor_foundry.polyglot_capability_matrix import NATIVE_ADAPTER_PROFILES
from rigor_foundry.sarif_import_profile import (
    IMPORT_PROFILES,
    SECOND_OUTPUT_PLACEHOLDER,
    import_profile_by_name,
)

ROOT = Path(__file__).resolve().parents[1]
NAME = "semgrep-local-sarif-import-v1"
BUILT_IN_DIGESTS = {
    "osv-lockfile-offline-json-v1": "122e982e5effe31be8c56f6deba5b145f9f309d8510ba4fc35608f9001314445",
    "semgrep-local-json-v1": "05eaa7fb0174b80e38c40ed06150b750d413ae272d076d2d7762cbaffe9f2947",
    "trivy-repository-json-v1": "d21275b444d3c831d99f702c010a4a4d3479d45938b1844c779530abe1f7a6af",
}
IMPORT_DIGEST = "4eb40b5a4edfe242ae401773e5ff543082a52f135841dad9784d809538fbbb1c"
READERS = (
    "src/rigor_foundry/adapter_profiles.py",
    "src/rigor_foundry/polyglot_capability_matrix.py",
    "src/rigor_foundry/adapter_catalogue.py",
    "src/rigor_foundry/policy_diagnostic_rows.py",
    "src/rigor_foundry/policy_models.py",
    "benchmarks/adapter_profiles.py",
    "tests/native_dispatch_support.py",
)


def test_the_built_in_profiles_and_their_evidence_schema_are_unchanged() -> None:
    """The three execution profiles keep their exact digests and evidence schema 1.0."""
    for name, digest in BUILT_IN_DIGESTS.items():
        assert profile_by_name(name).profile_digest == digest
    assert PROFILE_EVIDENCE_SCHEMA_VERSION == "1.0"


def test_the_import_profile_is_the_semgrep_json_run_plus_one_second_output() -> None:
    """Its command is the base command for relative targets, then one descriptor argument."""
    profile = import_profile_by_name(NAME)
    assert profile is IMPORT_PROFILES[NAME] and profile.base is profile_by_name(
        "semgrep-local-json-v1"
    )
    assert profile.profile_digest == IMPORT_DIGEST and profile.producer_id == "semgrep"
    arguments = profile.command_arguments("/workspace/rules.yaml", (".", "src/app"), "/dev/fd/7")
    assert arguments == (
        *profile.base.command_arguments("/workspace/rules.yaml", (".", "src/app")),
        "--sarif-output=/dev/fd/7",
    )
    assert SECOND_OUTPUT_PLACEHOLDER == "/dev/fd/<FD>"
    assert (
        profile.command_arguments("/w/r.yaml", ("src",), "/dev/fd/9")[-1]
        == "--sarif-output=/dev/fd/9"
    )


@pytest.mark.parametrize(
    "target", ["/workspace/src", "../src", "src/../x", "src\\app", "src/", ""]
)
def test_an_absolute_climbing_or_unnormalised_target_is_refused(target: str) -> None:
    """Only canonical relative targets reach the sandboxed command.

    Parameters
    ----------
    target : str
        A target the sandbox would not resolve against its own root.
    """
    with pytest.raises(ValueError, match="canonical relative path"):
        import_profile_by_name(NAME).command_arguments("/workspace/r.yaml", (target,), "/dev/fd/7")


@pytest.mark.parametrize(
    "path", ["/tmp/out.sarif", "/dev/fd/x", "/dev/fd/07", "/dev/fd/", "/proc/self/fd/7"]
)
def test_the_second_output_must_be_one_inherited_descriptor(path: str) -> None:
    """A file path, a non-number or a padded number is refused as the second output.

    Parameters
    ----------
    path : str
        A refused second output path.
    """
    with pytest.raises(ValueError, match="one inherited descriptor path"):
        import_profile_by_name(NAME).command_arguments("/workspace/r.yaml", ("src",), path)


@pytest.mark.parametrize("value", ["semgrep-local-json-v1", "trivy-repository-json-v1", 7, ""])
def test_only_a_declared_import_profile_is_returned(value: object) -> None:
    """The built-in execution profiles are not import profiles, and nothing else is.

    Parameters
    ----------
    value : object
        A name that is not a declared import profile.
    """
    with pytest.raises(ValueError, match="import profile is not declared"):
        import_profile_by_name(value)


def test_no_native_audit_reader_can_name_the_import_profile() -> None:
    """native_audits resolves names through profile_by_name, which refuses the import profile."""
    with pytest.raises(ValueError, match="profile is unsupported"):
        profile_by_name(NAME)
    assert NAME not in NATIVE_ADAPTER_PROFILES
    for reader in READERS:
        assert NAME not in (ROOT / reader).read_text(encoding="utf-8"), reader
    cra = sorted((ROOT / "src/rigor_foundry").glob("cra*.py"))
    assert cra and all(NAME not in path.read_text(encoding="utf-8") for path in cra)
