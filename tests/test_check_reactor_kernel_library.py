# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Reactor kernel-library guard tests
"""Exercise the cross-repository guard against real temporary Git objects."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tools.check_reactor_kernel_library import (
    KERNEL_BOUNDARY,
    KERNEL_DOMAIN,
    _dependency_commits,
    _distribution_version,
    _git_bytes,
    _load_object,
    _verify_pin,
    check_conformance,
    main,
)


def _write_json(path: Path, value: Any) -> None:
    """Write one deterministic JSON fixture."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    """Run one local Git fixture command."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path, list[Path], str]:
    """Build a valid two-device family around one immutable kernel commit."""
    kernels = tmp_path / "SCPN-REACTOR-KERNELS"
    kernels.mkdir()
    _git(kernels, "init", "-q")
    _git(kernels, "config", "user.email", "tests@example.invalid")
    _git(kernels, "config", "user.name", "RIGOR tests")
    inventory = {
        "library": {"distribution": "scpn-reactor-kernels"},
        "kernels": [{"identifier": "geometry_unit_circle"}],
        "consumers": [],
    }
    _write_json(kernels / "kernel-inventory.json", inventory)
    (kernels / "pyproject.toml").write_text(
        """[project]
name = "scpn-reactor-kernels"
dynamic = ["version"]
[tool.setuptools.dynamic]
version = { attr = "scpn_reactor_kernels.__version__" }
""",
        encoding="utf-8",
    )
    package = kernels / "src/scpn_reactor_kernels"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__: Final = "1.2.3"\n', encoding="utf-8")
    _git(kernels, "add", ".")
    _git(kernels, "commit", "-qm", "fixture")
    commit = _git(kernels, "rev-parse", "HEAD")
    digest = hashlib.sha256((kernels / "kernel-inventory.json").read_bytes()).hexdigest()

    consumer = tmp_path / "SCPN-A-CORE"
    consumer.mkdir()
    pin = {
        "distribution": "scpn-reactor-kernels",
        "version": "1.2.3",
        "source_commit": commit,
        "inventory_sha256": digest,
        "kernels": ["geometry_unit_circle"],
    }
    _write_json(
        consumer / "reactor-domain.json",
        {
            "project": consumer.name,
            "kernel_library": pin,
            "excluded_domains": [{"domain": KERNEL_DOMAIN, "owner": "SCPN-REACTOR-KERNELS"}],
        },
    )
    (consumer / "pyproject.toml").write_text(
        "[project]\nname='a'\ndependencies=["
        f"'scpn-reactor-kernels @ git+https://github.com/anulum/"
        f"scpn-reactor-kernels.git@{commit}'"
        "]\n",
        encoding="utf-8",
    )

    independent = tmp_path / "SCPN-B-CORE"
    independent.mkdir()
    _write_json(
        independent / "reactor-domain.json",
        {"project": independent.name, "excluded_domains": []},
    )
    planned = [consumer.name, independent.name]
    family_map = tmp_path / "family-map.json"
    _write_json(
        family_map,
        {
            "schema_version": "1.1.0",
            "planned_repositories": planned,
            "existing_repositories": [],
            "shared_library_projects": {"SCPN-REACTOR-KERNELS": KERNEL_BOUNDARY},
            "configuration_assignments": {"a": consumer.name, "b": independent.name},
        },
    )
    reverse = tmp_path / "reverse.json"
    _write_json(
        reverse,
        {
            "consumers": [
                {
                    "project": consumer.name,
                    "version": pin["version"],
                    "source_commit": commit,
                    "inventory_sha256": digest,
                }
            ]
        },
    )
    return family_map, kernels, reverse, [consumer, independent], commit


def test_real_git_object_and_cli_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A valid explicit family resolves the exact committed inventory."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    assert check_conformance(family_map, kernels, reverse, devices) == []
    argv = [
        "--family-map",
        str(family_map),
        "--kernels-repo",
        str(kernels),
        "--reverse-inventory",
        str(reverse),
    ]
    for device in devices:
        argv.extend(("--device-repo", str(device)))
    assert main(argv) == 0
    assert capsys.readouterr().out == "reactor-kernel-library: PASS\n"


def test_git_resolution_ignores_untrusted_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolve real committed pins without executing a PATH-shadowing Git command."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    untrusted = tmp_path / "untrusted-bin"
    untrusted.mkdir()
    shadow = untrusted / "git"
    shadow.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
    shadow.chmod(0o700)
    monkeypatch.setenv("PATH", str(untrusted))
    assert check_conformance(family_map, kernels, reverse, devices) == []
    manifest_path = devices[0] / "reactor-domain.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["kernel_library"]["source_commit"] = "f" * 40
    _write_json(manifest_path, manifest)
    assert any(
        "source_commit does not resolve" in finding
        for finding in check_conformance(family_map, kernels, reverse, devices)
    )


def test_input_and_map_failures_are_reported(tmp_path: Path) -> None:
    """Unreadable inputs and every shared-library topology defect fail closed."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    assert check_conformance(tmp_path / "missing", kernels, reverse, devices)
    machine_map = json.loads(family_map.read_text(encoding="utf-8"))
    cases: list[tuple[dict[str, Any], str]] = [
        ({**machine_map, "schema_version": "1.0.0"}, "schema_version"),
        ({**machine_map, "planned_repositories": "bad"}, "non-empty strings"),
        ({**machine_map, "planned_repositories": [""]}, "non-empty strings"),
        ({**machine_map, "existing_repositories": "bad"}, "must be a list"),
        ({**machine_map, "shared_library_projects": []}, "boundary is missing"),
        ({**machine_map, "shared_library_projects": {}}, "boundary is missing"),
        (
            {
                **machine_map,
                "planned_repositories": [*machine_map["planned_repositories"], "SCPN-A-CORE"],
            },
            "classes overlap",
        ),
        (
            {
                **machine_map,
                "planned_repositories": [
                    *machine_map["planned_repositories"],
                    "SCPN-REACTOR-KERNELS",
                ],
            },
            "classified as a device",
        ),
        ({**machine_map, "configuration_assignments": []}, "must be an object"),
        (
            {
                **machine_map,
                "configuration_assignments": {"x": "SCPN-REACTOR-KERNELS"},
            },
            "owns a configuration",
        ),
    ]
    for index, (payload, fragment) in enumerate(cases):
        path = tmp_path / f"map-{index}.json"
        _write_json(path, payload)
        assert any(
            fragment in finding for finding in check_conformance(path, kernels, reverse, devices)
        )


def test_device_identity_and_set_failures_are_reported(tmp_path: Path) -> None:
    """Explicit repositories cannot be omitted, duplicated, or misidentified."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    assert any(
        "does not equal" in finding
        for finding in check_conformance(family_map, kernels, reverse, devices[:1])
    )
    duplicate = tmp_path / "COPY"
    duplicate.mkdir()
    _write_json(
        duplicate / "reactor-domain.json",
        json.loads((devices[0] / "reactor-domain.json").read_text(encoding="utf-8")),
    )
    findings = check_conformance(family_map, kernels, reverse, [*devices, duplicate])
    assert any("directory/project identity mismatch" in item for item in findings)
    assert any("duplicate device repository" in item for item in findings)
    broken = tmp_path / "BROKEN"
    broken.mkdir()
    _write_json(broken / "reactor-domain.json", {"project": ""})
    assert any(
        "manifest project is invalid" in item
        for item in check_conformance(family_map, kernels, reverse, [*devices, broken])
    )
    missing = tmp_path / "MISSING"
    missing.mkdir()
    assert any(
        "cannot load reactor-domain.json" in item
        for item in check_conformance(family_map, kernels, reverse, [*devices, missing])
    )


def test_pin_structure_and_owner_failures_are_reported(tmp_path: Path) -> None:
    """Malformed pins and false owner exclusions never reach object resolution."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    manifest_path = devices[0] / "reactor-domain.json"
    baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
    pin = baseline["kernel_library"]
    cases: list[tuple[Any, str]] = [
        ("bad", "must be an object"),
        (None, "must be an object"),
        ({**pin, "extra": True}, "fields are not closed"),
        ({**pin, "distribution": "other"}, "distribution mismatch"),
        ({**pin, "version": "latest"}, "invalid kernel version"),
        ({**pin, "source_commit": "short"}, "malformed source_commit"),
        ({**pin, "inventory_sha256": "bad"}, "malformed inventory"),
        ({**pin, "kernels": []}, "must be non-empty"),
        ({**pin, "kernels": ["Bad-Name"]}, "must be non-empty"),
        ({**pin, "kernels": ["z", "a"]}, "must be non-empty"),
    ]
    for candidate, fragment in cases:
        payload = {**baseline, "kernel_library": candidate}
        _write_json(manifest_path, payload)
        assert any(
            fragment in finding
            for finding in check_conformance(family_map, kernels, reverse, devices)
        )
    payload = {**baseline, "excluded_domains": []}
    _write_json(manifest_path, payload)
    assert any(
        "owner exclusion is missing" in finding
        for finding in check_conformance(family_map, kernels, reverse, devices)
    )
    payload = {**baseline, "excluded_domains": "bad"}
    _write_json(manifest_path, payload)
    assert any(
        "owner exclusion is missing" in finding
        for finding in check_conformance(family_map, kernels, reverse, devices)
    )
    payload.pop("kernel_library")
    payload["excluded_domains"] = [{"domain": KERNEL_DOMAIN, "owner": "SCPN-REACTOR-KERNELS"}]
    _write_json(manifest_path, payload)
    assert any(
        "exclusion exists without a pin" in finding
        for finding in check_conformance(family_map, kernels, reverse, devices)
    )


def test_object_dependency_and_reverse_failures_are_reported(tmp_path: Path) -> None:
    """Real object, digest, kernel, dependency and reverse drift are detected."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    manifest_path = devices[0] / "reactor-domain.json"
    baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
    pin = baseline["kernel_library"]

    bad_commit = {**pin, "source_commit": "f" * 40}
    _write_json(manifest_path, {**baseline, "kernel_library": bad_commit})
    assert any(
        "does not resolve" in item
        for item in check_conformance(family_map, kernels, reverse, devices)
    )

    bad_digest = {**pin, "inventory_sha256": "0" * 64}
    _write_json(manifest_path, {**baseline, "kernel_library": bad_digest})
    assert any(
        "digest mismatch" in item
        for item in check_conformance(family_map, kernels, reverse, devices)
    )

    bad_kernel = {**pin, "kernels": ["unknown_kernel"]}
    _write_json(manifest_path, {**baseline, "kernel_library": bad_kernel})
    assert any(
        "absent from pinned inventory" in item
        for item in check_conformance(family_map, kernels, reverse, devices)
    )

    _write_json(manifest_path, baseline)
    (devices[0] / "pyproject.toml").write_text("[project]\nname='a'\n", encoding="utf-8")
    assert any(
        "no KERNELS dependency" in item
        for item in check_conformance(family_map, kernels, reverse, devices)
    )
    (devices[0] / "pyproject.toml").write_text(
        "scpn-reactor-kernels-native @ git+https://github.com/anulum/"
        "scpn-reactor-kernels.git@" + "e" * 40,
        encoding="utf-8",
    )
    assert any(
        "disagrees with manifest" in item
        for item in check_conformance(family_map, kernels, reverse, devices)
    )

    _write_json(reverse, {"consumers": "bad"})
    assert any(
        "consumers must be a list" in item
        for item in check_conformance(family_map, kernels, reverse, devices)
    )
    _write_json(reverse, {"consumers": [{"project": "SCPN-A-CORE"}]})
    findings = check_conformance(family_map, kernels, reverse, devices)
    assert any("fields are not closed" in item for item in findings)
    assert any("rows differ" in item for item in findings)


def test_cli_failure_is_explicit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The command prints all bounded findings and exits nonzero."""
    family_map, kernels, reverse, devices, _ = _workspace(tmp_path)
    _write_json(reverse, {"consumers": []})
    argv = [
        "--family-map",
        str(family_map),
        "--kernels-repo",
        str(kernels),
        "--reverse-inventory",
        str(reverse),
    ]
    for device in devices:
        argv.extend(("--device-repo", str(device)))
    assert main(argv) == 1
    output = capsys.readouterr().out
    assert output.startswith("reactor-kernel-library: FAIL")
    assert "reverse inventory" in output


def test_low_level_git_and_version_edges(tmp_path: Path) -> None:
    """Bounded helpers fail closed on absent paths and malformed version metadata."""
    family_map, kernels, reverse, devices, commit = _workspace(tmp_path)
    del family_map, reverse
    non_object = tmp_path / "array.json"
    _write_json(non_object, [])
    with pytest.raises(ValueError, match="root must be an object"):
        _load_object(non_object)
    with pytest.raises(ValueError, match="absent at source_commit"):
        _git_bytes(kernels, commit, "absent.json")

    assert _distribution_version(kernels, commit, {"project": {"version": "2.0.0"}}) == "2.0.0"
    assert _distribution_version(kernels, commit, {"project": []}) is None
    assert _distribution_version(kernels, commit, {"project": {}}) is None
    assert _distribution_version(kernels, commit, {"project": {}, "tool": {}}) is None
    assert (
        _distribution_version(
            kernels,
            commit,
            {
                "project": {},
                "tool": {"setuptools": {"dynamic": {"version": {"attr": "invalid"}}}},
            },
        )
        is None
    )
    assert (
        _distribution_version(
            kernels,
            commit,
            {
                "project": {},
                "tool": {"setuptools": {"dynamic": {"version": {"attr": "absent.__version__"}}}},
            },
        )
        is None
    )

    workflow = devices[0] / ".github/workflows/pins.yaml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "scpn-reactor-kernels @ git+https://github.com/anulum/"
        f"scpn-reactor-kernels.git@{commit}\n",
        encoding="utf-8",
    )
    assert _dependency_commits(devices[0]).count(commit) == 2
    assert _verify_pin("SCPN-A-CORE", devices[0], kernels, {"source_commit": "bad"}) == []


def _commit_kernel_variant(
    kernels: Path,
    inventory: dict[str, Any] | bytes,
    pyproject: str,
    init_source: str = '__version__ = "1.2.3"\n',
) -> tuple[str, str]:
    """Commit one exact malformed or drifted kernel metadata variant."""
    inventory_path = kernels / "kernel-inventory.json"
    if isinstance(inventory, bytes):
        inventory_path.write_bytes(inventory)
    else:
        _write_json(inventory_path, inventory)
    (kernels / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    (kernels / "src/scpn_reactor_kernels/__init__.py").write_text(init_source, encoding="utf-8")
    _git(kernels, "add", ".")
    _git(kernels, "commit", "-qm", "variant")
    commit = _git(kernels, "rev-parse", "HEAD")
    return commit, hashlib.sha256(inventory_path.read_bytes()).hexdigest()


def test_pinned_metadata_decode_distribution_and_version_edges(tmp_path: Path) -> None:
    """Exact committed metadata remains decoded, identified and version-bound."""
    _, kernels, _, devices, _ = _workspace(tmp_path)
    device = devices[0]
    dynamic = """[project]
name = "scpn-reactor-kernels"
dynamic = ["version"]
[tool.setuptools.dynamic]
version = { attr = "scpn_reactor_kernels.__version__" }
"""
    commit, digest = _commit_kernel_variant(kernels, b"not-json", dynamic)
    findings = _verify_pin(
        device.name,
        device,
        kernels,
        {"source_commit": commit, "inventory_sha256": digest, "version": "1.2.3", "kernels": []},
    )
    assert any("undecodable" in item for item in findings)

    inventory = {"library": {"distribution": "other"}, "kernels": "bad"}
    commit, digest = _commit_kernel_variant(
        kernels, inventory, dynamic, init_source="NO_VERSION = True\n"
    )
    findings = _verify_pin(
        device.name,
        device,
        kernels,
        {"source_commit": commit, "inventory_sha256": digest, "version": "1.2.3", "kernels": []},
    )
    assert any("distribution mismatch" in item for item in findings)
    assert any("version mismatch" in item for item in findings)

    invalid_toml = "[project\n"
    commit, digest = _commit_kernel_variant(
        kernels,
        {"library": {"distribution": "scpn-reactor-kernels"}, "kernels": []},
        invalid_toml,
    )
    findings = _verify_pin(
        device.name,
        device,
        kernels,
        {"source_commit": commit, "inventory_sha256": digest, "version": "1.2.3", "kernels": []},
    )
    assert any("undecodable" in item for item in findings)
