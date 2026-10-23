# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete owner implementation observations
"""Observe complete package and interpreter inputs for a trusted host selection."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .audit_primitives import canonical_digest
from .git_inventory import open_directory_no_follow
from .model_primitives import require_digest
from .policy_read_budget import PolicyReadBudget1
from .policy_source_reads import read_policy_source_payloads


def _identity(path: Path) -> list[int]:
    """Retain exact source-object and stability fields without access-time noise."""
    value = path.lstat()
    return [
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    ]


def _inventory(root: Path, limits: PolicyReadBudget1) -> tuple[dict[str, Path], str]:
    """Enumerate every regular package input under explicit entry/file ceilings."""
    descriptor = open_directory_no_follow(root)
    os.close(descriptor)
    pending = [root]
    files: dict[str, Path] = {}
    identities: dict[str, object] = {".": _identity(root)}
    entries = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for item in children:
                entries += 1
                if entries > limits.max_references:
                    raise ValueError("implementation census exceeds the reference budget")
                path = Path(item.path)
                relative = path.relative_to(root).as_posix()
                if item.is_symlink():
                    raise ValueError("implementation inputs cannot be symlinks")
                if item.is_dir(follow_symlinks=False):
                    if item.name != "__pycache__":
                        pending.append(path)
                        identities[relative] = _identity(path)
                elif item.is_file(follow_symlinks=False):
                    files[relative] = path
                    identities[relative] = _identity(path)
                    if len(files) + 1 > limits.max_sources:
                        raise ValueError("implementation census exceeds the source budget")
                else:
                    raise ValueError("implementation input is not a regular file or directory")
    if "__init__.py" not in files:
        raise ValueError("implementation directory is not a complete Python package")
    return dict(sorted(files.items())), canonical_digest(
        {"root": str(root), "objects": identities}
    )


@dataclass(frozen=True)
class OwnerImplementationSnapshot:
    """Host-side observation, with no wire loader or installation authority.

    The content identity covers all package files and the actual interpreter
    bytes. The lifetime identity additionally retains observed object metadata.
    Whole-consumer engine/toolchain qualification remains a separate obligation.
    """

    implementation_digest: str
    opening_identity: str
    closing_identity: str

    def __post_init__(self) -> None:
        """Refuse inconsistent observations and malformed directly supplied identities."""
        require_digest(self.implementation_digest, "owner implementation digest")
        opening = require_digest(self.opening_identity, "implementation opening identity")
        if opening != require_digest(self.closing_identity, "implementation closing identity"):
            raise ValueError("implementation changed while being observed")

    @property
    def snapshot_digest(self) -> str:
        """Bind the content identity to its complete consistent source-object observation."""
        self.__post_init__()
        return canonical_digest(
            {
                "implementation_digest": self.implementation_digest,
                "source_identity": self.opening_identity,
            }
        )


def observe_owner_implementation(
    package_root: Path, *, budget: PolicyReadBudget1
) -> OwnerImplementationSnapshot:
    """Read a complete package/interpreter selection without granting deployment trust.

    This observer accepts a host-selected package directory. Fixed owners always
    call it for their own installed package, rather than accepting a request's
    code root or partial manifest. Symlink and unsupported inputs refuse. Every
    file is read through the existing bounded stable single-link source reader.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    root = package_root.absolute()
    interpreter = Path(sys.executable).resolve(strict=True)
    files, opening = _inventory(root, limits)
    interpreter_opening = _identity(interpreter)
    paths = {f"code-{index:06d}": path for index, path in enumerate(files.values())}
    paths["interpreter"] = interpreter
    payloads = read_policy_source_payloads(paths, budget=limits)
    _, closing = _inventory(root, limits)
    interpreter_closing = _identity(interpreter)
    content = canonical_digest(
        {
            "domain": "context-owner-package-and-interpreter",
            "runtime": {
                "version": sys.version,
                "implementation": sys.implementation.name,
                "cache_tag": sys.implementation.cache_tag,
            },
            "interpreter_sha256": hashlib.sha256(payloads["interpreter"]).hexdigest(),
            "files": [
                {
                    "relative_path": name,
                    "sha256": hashlib.sha256(payloads[f"code-{index:06d}"]).hexdigest(),
                }
                for index, name in enumerate(files)
            ],
        }
    )
    return OwnerImplementationSnapshot(
        content,
        canonical_digest({"package": opening, "interpreter": interpreter_opening}),
        canonical_digest({"package": closing, "interpreter": interpreter_closing}),
    )
