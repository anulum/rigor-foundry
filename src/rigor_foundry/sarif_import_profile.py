# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the import-only adapter profile that writes SARIF beside its JSON
"""Declare the import-only Semgrep profile: the JSON profile's run with a second SARIF output.

The profile is deliberately outside the built-in adapter profiles, so a policy's
``native_audits`` can never select it. Its command is the unchanged Semgrep JSON profile
command with relative targets, which the sandbox resolves against its own root, followed by
one ``--sarif-output`` argument naming an inherited descriptor. The JSON run stays the
execution authority; the SARIF is only bound to that same run.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Final, Literal

from .adapter_profiles import AdapterProfile, profile_by_name
from .audit_primitives import canonical_digest

SECOND_OUTPUT_PLACEHOLDER: Final = "/dev/fd/<FD>"
_SECOND_OUTPUT_OPTION: Final = "--sarif-output="
ImportProfileName = Literal["semgrep-local-sarif-import-v1"]


def _relative_target(target: str) -> str:
    """Return one canonical relative target, which the sandbox resolves against its root."""
    path = PurePosixPath(target)
    if (
        not target
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in target
        or (path.as_posix() != target and target != ".")
    ):
        raise ValueError("an import profile target must be a canonical relative path")
    return target


@dataclass(frozen=True)
class ImportProfile:
    """One import-only profile: a built-in JSON profile run that also writes SARIF."""

    name: ImportProfileName
    base: AdapterProfile

    @property
    def profile_digest(self) -> str:
        """Return the digest of the name, the base profile and the added contract."""
        return canonical_digest(
            {
                "name": self.name,
                "base_profile": self.base.name,
                "base_profile_digest": self.base.profile_digest,
                "targets": "relative",
                "second_output": _SECOND_OUTPUT_OPTION + SECOND_OUTPUT_PLACEHOLDER,
            }
        )

    def command_arguments(
        self, configuration_path: str, target_paths: tuple[str, ...], second_output: str
    ) -> tuple[str, ...]:
        """Return the base command for relative targets, then the second output argument.

        Parameters
        ----------
        configuration_path : str
            The configuration path inside the sandbox.
        target_paths : tuple[str, ...]
            Canonical relative targets.
        second_output : str
            The ``/dev/fd/N`` path of the inherited second-output descriptor.

        Returns
        -------
        tuple[str, ...]
            The exact argument vector after the executable.

        Raises
        ------
        ValueError
            If a target is not canonical and relative, or the second output is not one
            inherited descriptor path.
        """
        targets = tuple(_relative_target(target) for target in target_paths)
        prefix, _, number = second_output.rpartition("/")
        if prefix != "/dev/fd" or not number.isdecimal() or number != str(int(number)):
            raise ValueError("the second output must be one inherited descriptor path")
        return (
            *self.base.command_arguments(configuration_path, targets),
            _SECOND_OUTPUT_OPTION + second_output,
        )


IMPORT_PROFILES: Final[Mapping[str, ImportProfile]] = MappingProxyType(
    {
        "semgrep-local-sarif-import-v1": ImportProfile(
            "semgrep-local-sarif-import-v1", profile_by_name("semgrep-local-json-v1")
        )
    }
)


def import_profile_by_name(value: object) -> ImportProfile:
    """Return one declared import-only profile.

    Parameters
    ----------
    value : object
        The profile name.

    Returns
    -------
    ImportProfile
        The declared profile.

    Raises
    ------
    ValueError
        If the name is not a declared import-only profile.
    """
    if not isinstance(value, str) or value not in IMPORT_PROFILES:
        raise ValueError("the import profile is not declared")
    return IMPORT_PROFILES[value]
