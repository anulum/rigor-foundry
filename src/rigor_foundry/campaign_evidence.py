# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — campaign runtime and native-adapter evidence
"""Define runtime and native-adapter evidence retained by campaign records."""

from __future__ import annotations

import hashlib
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

from .adapters import ADAPTER_RESULT_SCHEMA_VERSION, AdapterResult
from .models import canonical_digest, require_mapping, require_string
from .sandbox_provenance import BubblewrapProvenance

_TOOLCHAIN_FIELDS = frozenset(
    {
        "python_implementation",
        "python_version",
        "platform",
        "executable_digest",
        "identity_digest",
    }
)


def _file_digest(path: Path) -> str:
    """Return SHA-256 for one runtime executable without loading it at once."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeError(f"cannot hash runtime executable: {path}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class ToolchainIdentity:
    """Runtime identity used to detect cross-agent input divergence."""

    python_implementation: str
    python_version: str
    platform: str
    executable_digest: str
    identity_digest: str

    @classmethod
    def current(cls) -> ToolchainIdentity:
        """Capture the active Python runtime and platform identity."""
        fields = {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "executable_digest": _file_digest(Path(sys.executable).resolve(strict=True)),
        }
        return cls(**fields, identity_digest=canonical_digest(fields))

    def to_dict(self) -> dict[str, str]:
        """Serialise the runtime identity."""
        return {
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
            "platform": self.platform,
            "executable_digest": self.executable_digest,
            "identity_digest": self.identity_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ToolchainIdentity:
        """Parse and integrity-check a runtime identity."""
        data = require_mapping(value, "toolchain")
        if frozenset(data) != _TOOLCHAIN_FIELDS:
            raise ValueError("toolchain identity fields do not match schema")
        fields = {
            "python_implementation": require_string(
                data.get("python_implementation"),
                "toolchain.python_implementation",
            ),
            "python_version": require_string(
                data.get("python_version"),
                "toolchain.python_version",
            ),
            "platform": require_string(data.get("platform"), "toolchain.platform"),
            "executable_digest": require_string(
                data.get("executable_digest"),
                "toolchain.executable_digest",
            ),
        }
        identity = cls(
            **fields,
            identity_digest=require_string(
                data.get("identity_digest"),
                "toolchain.identity_digest",
            ),
        )
        if identity.identity_digest != canonical_digest(fields):
            raise ValueError("toolchain identity digest does not match its content")
        return identity


@dataclass(frozen=True)
class AdapterEvidence:
    """Bounded native-adapter evidence retained in one run attestation."""

    name: str
    required: bool
    returncode: int
    timed_out: bool
    output_digest: str
    output_bytes: int
    output_truncated: bool
    spec_digest: str
    executable_digest: str
    command_digest: str
    environment_digest: str
    sandbox_digest: str
    sandbox_provenance: BubblewrapProvenance
    passed: bool

    @classmethod
    def from_result(cls, result: AdapterResult) -> AdapterEvidence:
        """Capture stable evidence from an adapter execution result."""
        return cls(
            name=result.name,
            required=result.required,
            returncode=result.returncode,
            timed_out=result.timed_out,
            output_digest=result.output_digest,
            output_bytes=result.output_bytes,
            output_truncated=result.output_truncated,
            spec_digest=result.spec_digest,
            executable_digest=result.executable_digest,
            command_digest=result.command_digest,
            environment_digest=result.environment_digest,
            sandbox_digest=result.sandbox_digest,
            sandbox_provenance=result.sandbox_provenance,
            passed=result.passed,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one native-adapter evidence record."""
        return {
            "schema_version": ADAPTER_RESULT_SCHEMA_VERSION,
            "name": self.name,
            "required": self.required,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "output_digest": self.output_digest,
            "output_bytes": self.output_bytes,
            "output_truncated": self.output_truncated,
            "spec_digest": self.spec_digest,
            "executable_digest": self.executable_digest,
            "command_digest": self.command_digest,
            "environment_digest": self.environment_digest,
            "sandbox_digest": self.sandbox_digest,
            "sandbox_provenance": self.sandbox_provenance.to_dict(),
            "passed": self.passed,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> AdapterEvidence:
        """Parse one native-adapter evidence record."""
        result = AdapterResult.from_dict(value, index)
        return cls.from_result(result)
