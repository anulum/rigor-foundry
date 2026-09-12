# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deployment profile
"""Validate explicit layout data without interpreting it as live authority."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

from .project_memory_primitives import (
    canonical_json_bytes,
    require_digest,
    require_exact_fields,
    require_identifier,
    require_mapping,
    require_string,
    strict_json,
)

DEPLOYMENT_PROFILE_SCHEMA_VERSION = "deployment-profile.v1"

DEPLOYMENT_PROFILE_MAX_BYTES = 65536


def _path(value: object) -> str:
    text = require_string(value, "profile path", maximum=1024)
    if any(
        part in {".", ".."} or re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None
        for part in text.split("/")
    ):
        raise ValueError("profile path is not canonical and relative")
    return text


def _objects(value: object, maximum: int) -> list[object]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError("profile collection count is out of bounds")
    return cast(list[object], value)


@dataclass(frozen=True)
class DeploymentProfile:
    """Immutable lexical layout; neither a registry nor an authorisation.

    Groups contain (identifier, root, repositories, memory index). Layers
    contain (kind, scope, relative path, append project identifier). Direct
    construction is revalidated by :meth:`parent_paths` before interpretation.
    """

    profile_id: str
    groups: tuple[tuple[str, str, str, str], ...]
    parent_layers: tuple[tuple[str, str, str, bool], ...]
    profile_sha256: str

    @classmethod
    def from_bytes(cls, payload: bytes) -> DeploymentProfile:
        """Parse a bounded, canonical, digest-bound deployment profile.

        Parameters
        ----------
        payload:
            At most 65536 bytes of exact canonical JSON with no trailing newline.

        Returns
        -------
        DeploymentProfile
            Validated layout data; the digest is not a signature or permission.

        Raises
        ------
        ValueError
            Invalid shape, version, paths, overlaps, canonical bytes or digest.
        """
        if not 1 <= len(payload) <= DEPLOYMENT_PROFILE_MAX_BYTES:
            raise ValueError("profile byte count is out of bounds")
        try:
            decoded = strict_json(payload)
        except RecursionError as exc:
            raise ValueError("profile nesting exceeds parser capacity") from exc
        data = require_mapping(decoded, "profile")
        require_exact_fields(
            data,
            frozenset(
                {
                    "schema_version",
                    "profile_id",
                    "groups",
                    "parent_layers",
                    "profile_sha256",
                }
            ),
            "profile",
        )
        if data["schema_version"] != DEPLOYMENT_PROFILE_SCHEMA_VERSION:
            raise ValueError("unsupported deployment profile")
        identifier = require_identifier(data["profile_id"], "profile_id")
        groups: list[tuple[str, str, str, str]] = []
        for value in _objects(data["groups"], 128):
            group = require_mapping(value, "group")
            require_exact_fields(
                group,
                frozenset(
                    {
                        "group_id",
                        "root_path",
                        "repositories_path",
                        "memory_index_path",
                    }
                ),
                "group",
            )
            group_id = require_identifier(group["group_id"], "group_id")
            root, repositories, memory = (
                _path(group[key])
                for key in ("root_path", "repositories_path", "memory_index_path")
            )
            if (
                not repositories.startswith(root + "/")
                or not memory.startswith(root + "/")
                or memory == repositories
                or memory.startswith(repositories + "/")
                or repositories.startswith(memory + "/")
            ):
                raise ValueError("group paths overlap or escape their root")
            groups.append((group_id, root, repositories, memory))
        identifiers = [group[0] for group in groups]
        if identifiers != sorted(set(identifiers)):
            raise ValueError("group identifiers must be sorted and unique")
        roots = sorted(group[1] for group in groups)
        if any(
            b == a or b.startswith(a + "/")
            for index, a in enumerate(roots)
            for b in roots[index + 1 :]
        ):
            raise ValueError("group roots overlap")
        layers: list[tuple[str, str, str, bool]] = []
        for value in _objects(data["parent_layers"], 32):
            layer = require_mapping(value, "parent layer")
            require_exact_fields(
                layer,
                frozenset(
                    {
                        "kind",
                        "scope",
                        "path",
                        "append_project_id",
                    }
                ),
                "parent layer",
            )
            kind = require_identifier(layer["kind"], "layer kind")
            scope = require_string(layer["scope"], "layer scope", maximum=32)
            append = layer["append_project_id"]
            if scope not in {"deployment", "group", "project"} or type(append) is not bool:
                raise ValueError("unsupported parent reference")
            if kind in {item[0] for item in layers}:
                raise ValueError("parent kinds must be unique")
            layers.append((kind, scope, _path(layer["path"]), append))
        digest = require_digest(data["profile_sha256"], "profile_sha256")
        unsigned = {key: value for key, value in data.items() if key != "profile_sha256"}
        if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != digest:
            raise ValueError("profile digest mismatch")
        profile = cls(identifier, tuple(groups), tuple(layers), digest)
        if profile.to_bytes() != payload:
            raise ValueError("profile bytes are not canonical")
        return profile

    def to_bytes(self) -> bytes:
        """Serialise without conferring validation on directly constructed objects.

        Returns
        -------
        bytes
            Canonical JSON carrying the stored digest, without recomputing it.

        Raises
        ------
        ValueError
            A constructed value is outside the canonical representation domain.
        """
        return canonical_json_bytes(
            {
                "schema_version": DEPLOYMENT_PROFILE_SCHEMA_VERSION,
                "profile_id": self.profile_id,
                "groups": [
                    dict(
                        zip(
                            ("group_id", "root_path", "repositories_path", "memory_index_path"),
                            group,
                            strict=True,
                        )
                    )
                    for group in self.groups
                ],
                "parent_layers": [
                    {"kind": kind, "scope": scope, "path": path, "append_project_id": append}
                    for kind, scope, path, append in self.parent_layers
                ],
                "profile_sha256": self.profile_sha256,
            }
        )

    def parent_paths(
        self,
        *,
        expected_sha256: str,
        group_id: str,
        project_id: str,
    ) -> tuple[tuple[str, str], ...]:
        """Derive lexical parent targets for an explicitly selected project.

        Parameters
        ----------
        expected_sha256:
            Profile digest pinned by the caller, not an authority token.
        group_id:
            Exact group declared in this profile.
        project_id:
            Portable project identifier appended to the declared member root.

        Returns
        -------
        tuple
            Ordered (layer kind, deployment-relative path) pairs.

        Raises
        ------
        ValueError
            Invalid profile, stale digest, unknown group or invalid project ID.

        Notes
        -----
        Does not read paths, certify membership, follow symlinks or load policy.
        Consumers must separately validate registry, filesystem and authority.
        """
        profile = self.from_bytes(self.to_bytes())
        if require_digest(expected_sha256, "expected_sha256") != profile.profile_sha256:
            raise ValueError("profile precondition differs")
        project_id = require_identifier(project_id, "project_id")
        selected = [group for group in profile.groups if group[0] == group_id]
        if len(selected) != 1:
            raise ValueError("profile group is unknown")
        _, root, repositories, _ = selected[0]
        bases = {
            "deployment": PurePosixPath("."),
            "group": PurePosixPath(root),
            "project": PurePosixPath(repositories) / project_id,
        }
        return tuple(
            (kind, str(bases[scope] / path / project_id if append else bases[scope] / path))
            for kind, scope, path, append in profile.parent_layers
        )
