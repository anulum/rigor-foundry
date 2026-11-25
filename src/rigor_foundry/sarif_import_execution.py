# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — one run of an import-only profile behind the attested write bound
"""Run an import-only profile through the audited profile path and collect its second output.

The run is the built-in JSON profile run, with one more argument and one more inherited
descriptor, launched behind the attested ``prlimit`` with soft and hard file-size limits one
byte above the whole-file SARIF limit. Its own tool writes, temporary files included, are
bounded while it runs, so an over-large output fails the run instead of being cut. The SARIF
is read only when the JSON evidence is complete, and the evidence is returned only with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, final

from .adapter_profiles import AdapterProfileEvidence
from .adapters import _run_profile_adapter
from .git_provenance import GitTrustPolicy
from .launcher_provenance import PrlimitProvenance, _handle, inspect_prlimit
from .policy_models import AdapterSpec
from .sarif_import_channel import SecondOutputChannel
from .sarif_import_document import MAX_SARIF_BYTES, SarifImportRefused
from .sarif_import_profile import ImportProfile
from .trusted_executable import TrustedExecutable

LAUNCH_VECTOR_VERSION: Final = "rigor-foundry-prlimit-bwrap-v1"
FILE_SIZE_CAP: Final = MAX_SARIF_BYTES + 1


@final
class SecondOutputRun:
    """The second-output hook of one import-profile run."""

    def __init__(
        self,
        profile: ImportProfile,
        channel: SecondOutputChannel,
        launcher: TrustedExecutable,
    ) -> None:
        """Bind one profile, its channel and the attested launcher for one run.

        Parameters
        ----------
        profile : ImportProfile
            The import-only profile.
        channel : SecondOutputChannel
            The open second-output channel.
        launcher : TrustedExecutable
            The descriptor-bound, attested ``prlimit``.
        """
        self.profile = profile
        self.channel = channel
        self.launcher = launcher
        self.evidence: AdapterProfileEvidence | None = None
        self.stdout = b""
        self.stderr = b""
        self.sarif: bytes | None = None

    def command_arguments(
        self, configuration_path: str, target_paths: tuple[str, ...]
    ) -> tuple[str, ...]:
        """Return the import profile's arguments, with relative targets and the channel path.

        Parameters
        ----------
        configuration_path : str
            The configuration path inside the sandbox.
        target_paths : tuple[str, ...]
            The workspace's relative targets.

        Returns
        -------
        tuple[str, ...]
            The tool's arguments.
        """
        return self.profile.command_arguments(configuration_path, target_paths, self.channel.path)

    def wrap(
        self, launch: tuple[str, ...], descriptors: tuple[int, ...]
    ) -> tuple[tuple[str, ...], tuple[int, ...]]:
        """Put the sandbox launch behind the attested write bound, and pass the channel.

        Parameters
        ----------
        launch : tuple[str, ...]
            The unchanged Bubblewrap launch vector.
        descriptors : tuple[int, ...]
            The descriptors that launch inherits.

        Returns
        -------
        tuple[tuple[str, ...], tuple[int, ...]]
            The bounded launch vector and its descriptors.
        """
        bound = f"--fsize={FILE_SIZE_CAP}:{FILE_SIZE_CAP}"
        return (
            (self.launcher.execution_path, bound, "--", *launch),
            (*descriptors, self.launcher.descriptor, self.channel.descriptor),
        )

    def complete(self, evidence: AdapterProfileEvidence, stdout: bytes, stderr: bytes) -> None:
        """Keep the run's evidence and output, and read the SARIF only after a complete run.

        Parameters
        ----------
        evidence : AdapterProfileEvidence
            The base JSON profile evidence.
        stdout : bytes
            The run's standard output.
        stderr : bytes
            The run's standard error.
        """
        self.evidence, self.stdout, self.stderr = evidence, stdout, stderr
        if evidence.complete:
            self.sarif = self.channel.read()


@dataclass(frozen=True)
class ImportRun:
    """The outcome of one complete import-profile run: its JSON evidence and both outputs."""

    profile: ImportProfile
    evidence: AdapterProfileEvidence
    stdout: bytes
    stderr: bytes
    sarif: bytes
    launcher: PrlimitProvenance
    tracked_content_digest: str

    @property
    def launch_vector(self) -> dict[str, object]:
        """Return the identity of the bounded launch that produced the outputs."""
        return {
            "version": LAUNCH_VECTOR_VERSION,
            "launcher_identity": self.launcher.identity_digest,
            "file_size_cap": FILE_SIZE_CAP,
        }


def run_import_profile(
    repository: Path,
    profile: ImportProfile,
    *,
    configuration_path: str,
    target_paths: tuple[str, ...],
    timeout_seconds: int,
    expected_tracked_content_digest: str,
    git_trust_policy: GitTrustPolicy | None = None,
) -> ImportRun:
    """Run one import-only profile on a repository's exact tracked content.

    Parameters
    ----------
    repository : Path
        The Git checkout to scan.
    profile : ImportProfile
        The import-only profile.
    configuration_path : str
        The tracked configuration file.
    target_paths : tuple[str, ...]
        The tracked targets.
    timeout_seconds : int
        The run's timeout.
    expected_tracked_content_digest : str
        The tracked content digest of the inventory the SARIF will be anchored against. The
        run refuses any other tracked content, so a checkout that moves between that
        inventory and the run cannot anchor another content's findings.
    git_trust_policy : GitTrustPolicy | None
        The Git trust contract for the tracked workspace.

    Returns
    -------
    ImportRun
        The complete run.

    Raises
    ------
    SarifImportRefused
        With ``incomplete-evidence`` unless the JSON run is complete, or ``launcher-changed``
        if the attested launcher changed during the run.
    RuntimeError
        If the checkout's tracked content is not the expected content.
    """
    spec = AdapterSpec.from_dict(
        {
            "name": profile.name,
            "profile": profile.base.name,
            "configuration_path": configuration_path,
            "target_paths": list(target_paths),
            "timeout_seconds": timeout_seconds,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )
    attested = inspect_prlimit()
    with (
        _handle(Path(attested.policy.executable_path), attested.policy) as launcher,
        SecondOutputChannel() as channel,
    ):
        if launcher.snapshot.digest != attested.executable_digest:
            raise SarifImportRefused("launcher-changed", "the launcher is not the attested one")
        run = SecondOutputRun(profile, channel, launcher)
        _run_profile_adapter(
            repository,
            spec,
            git_trust_policy=git_trust_policy,
            expected_tracked_content_digest=expected_tracked_content_digest,
            second_output=run,
        )
    if inspect_prlimit(attested.policy).identity_digest != attested.identity_digest:
        raise SarifImportRefused("launcher-changed", "the launcher changed during the run")
    if run.evidence is None or run.sarif is None:
        raise SarifImportRefused("incomplete-evidence", "only a complete run has a second output")
    return ImportRun(
        profile,
        run.evidence,
        run.stdout,
        run.stderr,
        run.sarif,
        attested,
        expected_tracked_content_digest,
    )
