# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deployment profile tests
"""Exercise explicit layout profiles without live registry or private policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from rigor_foundry.deployment_profile import DeploymentProfile
from rigor_foundry.project_memory_primitives import canonical_json_bytes


def profile_document(root: str = "portfolios/SCIENCE") -> dict[str, object]:
    """Return declarative data for an actual alternate deployment layout."""
    return {
        "schema_version": "deployment-profile.v1",
        "profile_id": "local-layout",
        "groups": [
            {
                "group_id": "SCIENCE",
                "root_path": root,
                "repositories_path": root + "/members",
                "memory_index_path": root + "/memory/index.md",
            }
        ],
        "parent_layers": [
            {
                "kind": "rules",
                "scope": "deployment",
                "path": "policy/rules.md",
                "append_project_id": False,
            },
            {
                "kind": "group-notes",
                "scope": "group",
                "path": "memory/index.md",
                "append_project_id": False,
            },
            {
                "kind": "project-notes",
                "scope": "project",
                "path": "notes/index.md",
                "append_project_id": False,
            },
            {
                "kind": "sessions",
                "scope": "deployment",
                "path": "coordination/sessions",
                "append_project_id": True,
            },
        ],
    }


def encode_profile(document: dict[str, object]) -> bytes:
    """Bind a complete unsigned profile to its canonical content digest."""
    unsigned = {k: v for k, v in document.items() if k != "profile_sha256"}
    return canonical_json_bytes(
        {
            **unsigned,
            "profile_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
        }
    )


@pytest.mark.parametrize("root", ["03_CODE/SCIENCE", "06_WEBMASTER", "workspace/science"])
def test_profile_round_trip_and_explicit_parent_resolution(root: str) -> None:
    profile = DeploymentProfile.from_bytes(encode_profile(profile_document(root)))
    assert DeploymentProfile.from_bytes(profile.to_bytes()) == profile
    assert profile.parent_paths(
        expected_sha256=profile.profile_sha256,
        group_id="SCIENCE",
        project_id="PROJECT",
    ) == (
        ("rules", "policy/rules.md"),
        ("group-notes", root + "/memory/index.md"),
        ("project-notes", root + "/members/PROJECT/notes/index.md"),
        ("sessions", "coordination/sessions/PROJECT"),
    )


@pytest.mark.parametrize(
    "case",
    [
        "version",
        "extra",
        "missing",
        "groups-type",
        "groups-empty",
        "groups-count",
        "layers-type",
        "layers-empty",
        "layers-count",
        "unsorted",
        "duplicate",
        "nested",
        "nested-with-interposed-root",
        "same-root",
        "repositories-escape",
        "memory-escape",
        "memory-member",
        "memory-parent",
        "memory-equal",
        "layer-scope",
        "layer-bool",
        "layer-duplicate",
        "group-extra",
        "layer-extra",
    ],
)
def test_profile_rejects_ambiguous_or_unsupported_layout(case: str) -> None:
    document = profile_document()
    groups = [dict(group) for group in json.loads(json.dumps(document))["groups"]]
    layers = [dict(layer) for layer in json.loads(json.dumps(document))["parent_layers"]]
    document["groups"], document["parent_layers"] = groups, layers
    if case == "version":
        document["schema_version"] = "deployment-profile.v2"
    elif case == "extra":
        document["execute"] = "never"
    elif case == "missing":
        del document["profile_id"]
    elif case.startswith("groups-"):
        document["groups"] = {"groups-type": {}, "groups-empty": [], "groups-count": groups * 129}[
            case
        ]
    elif case.startswith("layers-"):
        document["parent_layers"] = {
            "layers-type": {},
            "layers-empty": [],
            "layers-count": layers * 9,
        }[case]
    elif case in {"unsorted", "duplicate", "nested", "same-root", "nested-with-interposed-root"}:
        other = dict(groups[0])
        other["group_id"] = "SCIENCE" if case == "duplicate" else "Z"
        if case in {"nested", "nested-with-interposed-root"}:
            root = str(groups[0]["root_path"]) + "/nested"
            other.update(
                root_path=root,
                repositories_path=root + "/members",
                memory_index_path=root + "/memory/index.md",
            )
        groups.append(other)
        if case == "unsorted":
            groups.reverse()
        if case == "nested-with-interposed-root":
            root = str(groups[0]["root_path"]) + "-interposed"
            groups.insert(
                1,
                {
                    "group_id": "T",
                    "root_path": root,
                    "repositories_path": root + "/members",
                    "memory_index_path": root + "/memory/index.md",
                },
            )
    elif case == "repositories-escape":
        groups[0]["repositories_path"] = "outside/members"
    elif case == "memory-escape":
        groups[0]["memory_index_path"] = "outside/index.md"
    elif case == "memory-member":
        groups[0]["memory_index_path"] = str(groups[0]["repositories_path"]) + "/index.md"
    elif case == "memory-parent":
        groups[0]["repositories_path"] = str(groups[0]["memory_index_path"]) + "/members"
    elif case == "memory-equal":
        groups[0]["memory_index_path"] = groups[0]["repositories_path"]
    elif case == "layer-scope":
        layers[0]["scope"] = "environment"
    elif case == "layer-bool":
        layers[0]["append_project_id"] = 1
    elif case == "layer-duplicate":
        layers.append(dict(layers[0]))
    elif case == "group-extra":
        groups[0]["permission"] = "write"
    else:
        layers[0]["command"] = "never"
    with pytest.raises(ValueError):
        DeploymentProfile.from_bytes(encode_profile(document))


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
        "https://host",
        "a/",
        ".",
        "a/$HOME",
        "a/" + "x" * 1024,
    ],
)
def test_profile_refuses_unsafe_lexical_paths(path: str) -> None:
    with pytest.raises(ValueError):
        DeploymentProfile.from_bytes(encode_profile(profile_document(path)))


def test_profile_requires_exact_canonical_bytes_and_matching_digest() -> None:
    encoded = encode_profile(profile_document())
    profile = DeploymentProfile.from_bytes(encoded)
    for data in (
        b"",
        b"x" * 65537,
        encoded + b"\n",
        encoded.replace(b"local-layout", b"other-layout"),
        b'{"schema_version":1,"schema_version":2}',
        b"[" * 2000 + b"0" + b"]" * 2000,
    ):
        with pytest.raises(ValueError):
            DeploymentProfile.from_bytes(data)
    for digest, group, project in [
        ("0" * 64, "SCIENCE", "PROJECT"),
        (profile.profile_sha256, "UNKNOWN", "PROJECT"),
        (profile.profile_sha256, "SCIENCE", "../OTHER"),
    ]:
        with pytest.raises(ValueError):
            profile.parent_paths(expected_sha256=digest, group_id=group, project_id=project)
    with pytest.raises(ValueError):
        replace(profile, profile_id="changed").parent_paths(
            expected_sha256=profile.profile_sha256,
            group_id="SCIENCE",
            project_id="PROJECT",
        )
    changed = profile_document("different/root")
    assert (
        DeploymentProfile.from_bytes(encode_profile(changed)).profile_sha256
        != profile.profile_sha256
    )


def test_profile_digest_vector_binds_layer_order() -> None:
    """Freeze a public fixture vector and bind its ordered layer interpretation."""
    document = profile_document()
    profile = DeploymentProfile.from_bytes(encode_profile(document))
    assert (
        profile.profile_sha256
        == "f3b2cba2e7037251b346462ebd3614f6fe146ca057ff9ce45ac432a978a5e029"
    )
    altered = json.loads(json.dumps(document))
    altered["parent_layers"].reverse()
    reordered = DeploymentProfile.from_bytes(encode_profile(altered))
    assert reordered.profile_sha256 != profile.profile_sha256
    with pytest.raises(ValueError, match="precondition differs"):
        reordered.parent_paths(
            expected_sha256=profile.profile_sha256, group_id="SCIENCE", project_id="PROJECT"
        )
