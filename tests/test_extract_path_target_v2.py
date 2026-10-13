# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptor-backed path extractor tests
"""Derive an exact target through the real selected-scope canonicalizer."""

from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from rigor_foundry.tier0_builtin.extract_path_target import extract
from rigor_foundry.tier0_builtin.path_admission_v2 import (
    PinnedDirectoryV2,
    PinnedPathScopeV2,
    canonicalize_atomic_path_v2,
)


def test_real_scope_allows_creation_and_refuses_symlink_and_missing_parent(
    tmp_path: Path,
) -> None:
    """A selected directory admits an absent leaf, with no symlink traversal."""
    mono = tmp_path / "mono"
    project = mono / "project"
    project.mkdir(parents=True)
    project_pin = PinnedDirectoryV2(str(project))
    scope = PinnedPathScopeV2(
        PinnedDirectoryV2(str(mono)), project_pin, str(project), (project_pin,), ()
    )

    def payload(path: Path) -> bytes:
        """Encode a canonical invocation with matching caller declarations."""
        return json.dumps(
            {
                "operation_id": "local-file-write.atomic-replace",
                "path": str(path),
                "content_b64": "",
                "declared": {
                    "target_ref": {"form": "path", "value": str(path)},
                    "byte_count": 0,
                    "operation_variant": "replace-or-create",
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def canonicalize(path: str) -> object:
        """Use the actual public descriptor-backed admission API."""
        return canonicalize_atomic_path_v2(path, scope)

    target = project / "new.txt"
    assert extract(payload(target), canonicalize_path=canonicalize) == {
        "form": "path",
        "value": str(target),
    }
    assert not target.exists()
    with pytest.raises(FileNotFoundError) as missing:
        extract(payload(project / "absent" / "new.txt"), canonicalize_path=canonicalize)
    assert missing.value.errno == errno.ENOENT
    target.symlink_to(tmp_path / "outside.txt")
    with pytest.raises(PermissionError, match="not a regular file"):
        extract(payload(target), canonicalize_path=canonicalize)


def test_changed_canonicalizer_path_cannot_rebind_invocation() -> None:
    """A path observation for another request never substitutes for this one."""
    payload = json.dumps(
        {
            "operation_id": "local-file-write.atomic-replace",
            "path": "/srv/request.txt",
            "content_b64": "",
            "declared": {
                "target_ref": {"form": "path", "value": "/srv/request.txt"},
                "byte_count": 0,
                "operation_variant": "replace-or-create",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with pytest.raises(PermissionError, match="canonical path differs"):
        extract(payload, canonicalize_path=lambda _: {"form": "path", "value": "/srv/other.txt"})
