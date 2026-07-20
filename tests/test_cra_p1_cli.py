# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA P1 CLI integration tests
"""Exercise real Git, CLI, append-only SBOM storage, drift, and OSV registration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository
from test_cra_inventory import cyclonedx, spdx

from rigor_foundry.adapter_profiles import AdapterProfileEvidence, profile_by_name
from rigor_foundry.adapters import AdapterResult
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.cli import main
from rigor_foundry.cra_p1_store import CraP1Store
from rigor_foundry.cra_protocol import json_text
from rigor_foundry.sandbox_provenance import (
    BubblewrapCompatibilityPolicy,
    BubblewrapProvenance,
)

NOW = "2026-07-20T10:00:00Z"


def bootstrap(repository: GitRepository) -> None:
    """Create real P0 state through the public CLI."""
    assert (
        main(
            [
                "cra-bootstrap",
                "--root",
                str(repository.root),
                "--product-key",
                "PRODUCT-1",
                "--product-name",
                "Product",
                "--manufacturer-name",
                "Manufacturer",
                "--main-establishment-ms",
                "SK",
                "--establishment-basis",
                "decisions",
                "--csirt-endpoint-id",
                "CSIRT-SK",
                "--user-notice-channel",
                "https://example.invalid/notices",
                "--support-period-months",
                "60",
                "--registered-at",
                NOW,
            ]
        )
        == 0
    )


def repository(tmp_path: Path) -> GitRepository:
    """Return a committed real Git repository with bootstrapped CRA storage."""
    result = GitRepository.create(tmp_path / "repository")
    result.write_text("tracked.txt", "initial\n")
    result.commit()
    bootstrap(result)
    return result


def osv_output() -> bytes:
    """Return one exact OSV-Scanner findings document."""
    return json.dumps(
        {
            "results": [
                {
                    "source": {"path": "/workspace/requirements.txt", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "urllib3",
                                "version": "1.26.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [{"id": "OSV-TEST-1"}],
                        }
                    ],
                }
            ]
        },
        sort_keys=True,
    ).encode()


def osv_result(payload: bytes) -> AdapterResult:
    """Build one complete G1 OSV adapter result bound to ``payload``."""
    output_digest = hashlib.sha256(payload).hexdigest()
    policy = BubblewrapCompatibilityPolicy()
    provenance = BubblewrapProvenance.build(
        policy=policy,
        executable_digest="2" * 64,
        semantic_version="0.9.0",
        package_query_digest="3" * 64,
        package_name=policy.package_name,
        package_version="0.9.0-1",
        package_architecture="amd64",
        package_status=policy.required_package_status,
        capability_digest="4" * 64,
    )
    profile = profile_by_name("osv-lockfile-offline-json-v1")
    evidence = AdapterProfileEvidence.build(
        profile=profile,
        status="findings",
        reason="findings",
        tool_version="2.4.0",
        version_output_digest="5" * 64,
        configuration_digest="6" * 64,
        input_digest="7" * 64,
        output_digest=output_digest,
        finding_count=1,
        scanned_target_count=1,
    )
    return AdapterResult(
        name="osv-lockfile-security",
        returncode=1,
        output_digest=output_digest,
        output_bytes=len(payload),
        output_truncated=False,
        timed_out=False,
        required=True,
        spec_digest="8" * 64,
        executable_digest="9" * 64,
        command_digest="a" * 64,
        environment_digest="b" * 64,
        sandbox_digest="c" * 64,
        sandbox_provenance=provenance,
        profile_evidence=evidence,
    )


@pytest.mark.parametrize(
    ("sbom_format", "payload"),
    [
        ("cyclonedx-1.5", cyclonedx("1.5")),
        ("cyclonedx-1.6", cyclonedx("1.6")),
        ("spdx-2.3", spdx()),
    ],
)
def test_sbom_import_and_status_cross_real_cli_and_git_boundaries(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sbom_format: str,
    payload: bytes,
) -> None:
    """Each supported SBOM reaches append-only storage and exact Git drift status."""
    repo = repository(tmp_path)
    source = tmp_path / f"{sbom_format}.json"
    source.write_bytes(payload)
    assert (
        main(
            [
                "sbom-import",
                "--root",
                str(repo.root),
                "--product-key",
                "PRODUCT-1",
                "--file",
                str(source),
                "--format",
                sbom_format,
                "--source-tool",
                "generator@1.2.3",
                "--source-evidence",
                "build-log:7",
                "--coverage",
                "top-level-only",
                "--captured-at",
                NOW,
            ]
        )
        == 0
    )
    inventory = CraP1Store.open(repo.root).current_inventory("PRODUCT-1")
    assert inventory.sbom_sha256 == hashlib.sha256(payload).hexdigest()
    assert inventory.covers_top_level_only
    capsys.readouterr()
    assert (
        main(
            [
                "sbom-status",
                "--root",
                str(repo.root),
                "--product-key",
                "PRODUCT-1",
                "--observed-at",
                "2026-07-20T10:01:00Z",
            ]
        )
        == 0
    )
    clean = json.loads(capsys.readouterr().out)
    assert clean["drift"]["drifted"] is False

    repo.write_text("tracked.txt", "changed\n")
    assert (
        main(
            [
                "sbom-status",
                "--root",
                str(repo.root),
                "--product-key",
                "PRODUCT-1",
                "--observed-at",
                "2026-07-20T10:02:00Z",
            ]
        )
        == 1
    )
    changed = json.loads(capsys.readouterr().out)
    assert changed["drift"]["tracked_content_changed"] is True


def test_osv_bundle_requires_explicit_registration_and_exploitation_evidence(
    tmp_path: Path,
) -> None:
    """An exact OSV finding supplies awareness only and never registers by itself."""
    repo = repository(tmp_path)
    payload = osv_output()
    result = osv_result(payload)
    output_path = tmp_path / "osv-output.json"
    result_path = tmp_path / "adapter-result.json"
    output_path.write_bytes(payload)
    result_path.write_text(json_text(result.to_dict()), encoding="utf-8")
    common = [
        "vuln-register",
        "EVENT-1",
        "--root",
        str(repo.root),
        "--product-key",
        "PRODUCT-1",
        "--track",
        "vulnerability",
        "--aware-at",
        NOW,
        "--osv-adapter-result",
        str(result_path),
        "--osv-output",
        str(output_path),
        "--osv-id",
        "OSV-TEST-1",
        "--osv-package",
        "urllib3",
        "--recorded-at",
        NOW,
    ]

    assert main(common) == 2
    with pytest.raises(ValueError, match="no verified revisions"):
        CraP1Store.open(repo.root).base.current_event("EVENT-1")

    assert main([*common, "--exploitation-evidence", "operator-evidence:incident-7"]) == 0
    event = CraP1Store.open(repo.root).base.current_event("EVENT-1")
    assert event.aware_evidence_ref.startswith("osv-awareness:")
    assert event.external_ids == ("OSV-TEST-1",)
    assert event.affected_components == ("PyPI:urllib3@1.26.0",)
    assert event.exploitation_evidence == ("operator-evidence:incident-7",)
    digest = event.aware_evidence_ref.removeprefix("osv-awareness:")
    evidence = CraP1Store.open(repo.root).awareness(digest)
    assert evidence.external_id == "OSV-TEST-1"
    assert evidence.adapter_result_digest == canonical_digest(result.to_dict())


def test_osv_bridge_rejects_incomplete_bundle_wrong_bytes_and_ambiguous_findings(
    tmp_path: Path,
) -> None:
    """The public CLI rejects partial arguments, digest drift, and non-unique selection."""
    repo = repository(tmp_path)
    payload = osv_output()
    result = osv_result(payload)
    output_path = tmp_path / "osv-output.json"
    result_path = tmp_path / "adapter-result.json"
    output_path.write_bytes(payload)
    result_path.write_text(json_text(result.to_dict()), encoding="utf-8")
    base = [
        "vuln-register",
        "EVENT-1",
        "--root",
        str(repo.root),
        "--product-key",
        "PRODUCT-1",
        "--track",
        "vulnerability",
        "--aware-at",
        NOW,
        "--exploitation-evidence",
        "operator:evidence",
        "--recorded-at",
        NOW,
    ]
    assert main([*base, "--osv-output", str(output_path)]) == 2

    output_path.write_bytes(payload + b" ")
    assert (
        main(
            [
                *base,
                "--osv-adapter-result",
                str(result_path),
                "--osv-output",
                str(output_path),
                "--osv-id",
                "OSV-TEST-1",
                "--osv-package",
                "urllib3",
            ]
        )
        == 2
    )

    duplicate = json.loads(payload)
    duplicate["results"].append(duplicate["results"][0])
    duplicate_payload = json.dumps(duplicate, sort_keys=True).encode()
    output_path.write_bytes(duplicate_payload)
    duplicate_result = osv_result(duplicate_payload).to_dict()
    profile = duplicate_result["profile_evidence"]
    assert isinstance(profile, dict)
    profile["finding_count"] = 2
    profile["scanned_target_count"] = 1
    fields = {key: value for key, value in profile.items() if key != "evidence_digest"}
    profile["evidence_digest"] = canonical_digest(fields)
    duplicate_result["output_bytes"] = len(duplicate_payload)
    result_path.write_text(json_text(duplicate_result), encoding="utf-8")
    assert (
        main(
            [
                *base,
                "--osv-adapter-result",
                str(result_path),
                "--osv-output",
                str(output_path),
                "--osv-id",
                "OSV-TEST-1",
                "--osv-package",
                "urllib3",
            ]
        )
        == 2
    )


def test_sbom_storage_rejects_source_tamper_and_non_monotonic_capture(tmp_path: Path) -> None:
    """Stored raw bytes remain replayable and inventory history advances monotonically."""
    repo = repository(tmp_path)
    source = tmp_path / "sbom.json"
    source.write_bytes(cyclonedx())
    arguments = [
        "sbom-import",
        "--root",
        str(repo.root),
        "--product-key",
        "PRODUCT-1",
        "--file",
        str(source),
        "--format",
        "cyclonedx-1.5",
        "--source-tool",
        "generator@1",
        "--source-evidence",
        "build:1",
        "--coverage",
        "declared-complete",
        "--captured-at",
        NOW,
    ]
    assert main(arguments) == 0
    assert main([*arguments[:-1], "2026-07-20T09:00:00Z"]) == 2
    inventory = CraP1Store.open(repo.root).current_inventory("PRODUCT-1")
    stored = repo.root / ".rigor" / "cra" / "sboms" / f"{inventory.sbom_sha256}.json"
    stored.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="digest does not match"):
        CraP1Store.open(repo.root).current_inventory("PRODUCT-1")


def test_cli_rejects_invalid_source_tool_and_missing_awareness(tmp_path: Path) -> None:
    """Required explicit provenance and awareness cannot be omitted or guessed."""
    repo = repository(tmp_path)
    source = tmp_path / "sbom.json"
    source.write_bytes(cyclonedx())
    assert (
        main(
            [
                "sbom-import",
                "--root",
                str(repo.root),
                "--product-key",
                "PRODUCT-1",
                "--file",
                str(source),
                "--format",
                "cyclonedx-1.5",
                "--source-tool",
                "missing-version",
                "--source-evidence",
                "build:1",
                "--coverage",
                "top-level-only",
                "--captured-at",
                NOW,
            ]
        )
        == 2
    )
    assert (
        main(
            [
                "vuln-register",
                "EVENT-1",
                "--root",
                str(repo.root),
                "--product-key",
                "PRODUCT-1",
                "--track",
                "vulnerability",
                "--aware-at",
                NOW,
                "--exploitation-evidence",
                "operator:evidence",
                "--recorded-at",
                NOW,
            ]
        )
        == 2
    )


def test_cli_preserves_plain_awareness_and_rejects_osv_conflicts(tmp_path: Path) -> None:
    """The P0 awareness path remains intact and OSV options stay mutually exclusive."""
    repo = repository(tmp_path)
    assert (
        main(
            [
                "vuln-register",
                "EVENT-PLAIN",
                "--root",
                str(repo.root),
                "--product-key",
                "PRODUCT-1",
                "--track",
                "vulnerability",
                "--aware-at",
                NOW,
                "--aware-evidence",
                "operator:awareness",
                "--exploitation-evidence",
                "operator:exploitation",
                "--external-id",
                "CVE-TEST-1",
                "--component",
                "alpha@1",
                "--recorded-at",
                NOW,
            ]
        )
        == 0
    )
    event = CraP1Store.open(repo.root).base.current_event("EVENT-PLAIN")
    assert event.aware_evidence_ref == "operator:awareness"
    assert event.external_ids == ("CVE-TEST-1",)

    payload = osv_output()
    result_path = tmp_path / "result.json"
    output_path = tmp_path / "output.json"
    result_path.write_text(json_text(osv_result(payload).to_dict()), encoding="utf-8")
    output_path.write_bytes(payload)
    bundle = [
        "--osv-adapter-result",
        str(result_path),
        "--osv-output",
        str(output_path),
        "--osv-id",
        "OSV-TEST-1",
        "--osv-package",
        "urllib3",
    ]
    base = [
        "vuln-register",
        "EVENT-CONFLICT",
        "--root",
        str(repo.root),
        "--product-key",
        "PRODUCT-1",
        "--aware-at",
        NOW,
        "--exploitation-evidence",
        "operator:exploitation",
        "--recorded-at",
        NOW,
    ]
    assert main([*base, "--track", "vulnerability", "--aware-evidence", "x", *bundle]) == 2
    assert main([*base, "--track", "incident", *bundle]) == 2
