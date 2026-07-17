# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository policy record tests
"""Verify the dedicated policy owner, strict parsing, and compatibility facade."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rigor_foundry.audit_primitives import AUDIT_DOMAINS, canonical_digest
from rigor_foundry.models import AdapterSpec as ModelsAdapterSpec
from rigor_foundry.models import AuditDomainSpec as ModelsAuditDomainSpec
from rigor_foundry.models import AuditPolicy as ModelsAuditPolicy
from rigor_foundry.policy_models import AdapterSpec, AuditDomainSpec, AuditPolicy


def test_models_preserves_policy_record_import_compatibility() -> None:
    """The split policy owner keeps established imports as identical objects."""
    assert ModelsAdapterSpec is AdapterSpec
    assert ModelsAuditDomainSpec is AuditDomainSpec
    assert ModelsAuditPolicy is AuditPolicy
    assert AuditPolicy.__module__ == "rigor_foundry.models"


def test_policy_round_trip_and_digest_are_deterministic(tmp_path: Path) -> None:
    """The full domain/adapter policy survives exact JSON round-trip."""
    adapter = AdapterSpec(
        name="real-control",
        command=("{python}", "tools/control.py"),
        timeout_seconds=12,
        scope="full",
        working_directory=".",
        required=True,
        domains=("application-security",),
    )
    policy = AuditPolicy(
        audit_domains=tuple(
            AuditDomainSpec(name, "required", f"{name} applies") for name in AUDIT_DOMAINS
        ),
        native_audits=(adapter,),
    )
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
    loaded = AuditPolicy.from_path(path)
    assert loaded == policy
    assert canonical_digest(loaded.to_dict()) == canonical_digest(policy.to_dict())


@pytest.mark.parametrize(
    "change, message",
    [
        ({"schema_version": "9"}, "schema"),
        ({"enforcement_mode": "weaker"}, "unsupported"),
        ({"maturity_policy_digest": "not-a-digest"}, "lowercase hexadecimal"),
        ({"canonical_todo": "../TODO.md"}, "repository-relative"),
        ({"audit_domains": "all"}, "array"),
        ({"native_audits": "all"}, "array"),
        ({"unknown_policy_field": "rejected"}, "fields do not match schema"),
    ],
)
def test_policy_rejects_invalid_top_level_contracts(
    change: dict[str, object],
    message: str,
) -> None:
    """Policy parsing fails closed for version, path, mode, and shape defects."""
    value = AuditPolicy().to_dict()
    value.update(change)
    with pytest.raises(ValueError, match=message):
        AuditPolicy.from_dict(value)


def test_non_observe_policy_requires_bound_maturity_policy() -> None:
    """Repository ratchet modes cannot delegate calibration to an operator argument."""
    value = AuditPolicy().to_dict()
    value["enforcement_mode"] = "ratchet"
    with pytest.raises(ValueError, match="require maturity_policy_digest"):
        AuditPolicy.from_dict(value)

    value["maturity_policy_digest"] = "a" * 64
    policy = AuditPolicy.from_dict(value)
    assert policy.enforcement_mode == "ratchet"
    assert policy.maturity_policy_digest == "a" * 64


def test_policy_rejects_duplicate_and_unknown_domains() -> None:
    """The domain matrix cannot contain duplicates or invented domains."""
    value = AuditPolicy().to_dict()
    decision = {
        "name": "test-authenticity",
        "applicability": "required",
        "rationale": "tests apply",
    }
    value["audit_domains"] = [decision, decision]
    with pytest.raises(ValueError, match="unique"):
        AuditPolicy.from_dict(value)
    value["audit_domains"] = [
        {"name": "unknown", "applicability": "required", "rationale": "invalid"}
    ]
    with pytest.raises(ValueError, match="unsupported"):
        AuditPolicy.from_dict(value)
    value["audit_domains"] = [
        {
            "name": "test-authenticity",
            "applicability": "optional",
            "rationale": "invalid",
        }
    ]
    with pytest.raises(ValueError, match="applicability"):
        AuditPolicy.from_dict(value)


def test_adapter_rejects_shell_shape_escape_and_unknown_domain() -> None:
    """Native adapters accept argv only and repository-contained work directories."""
    base: dict[str, object] = {
        "name": "control",
        "command": ["{python}", "control.py"],
        "timeout_seconds": 1,
        "scope": "both",
        "working_directory": ".",
        "required": True,
        "domains": ["application-security"],
    }
    assert AdapterSpec.from_dict(base, 0).name == "control"
    for key, value in (
        ("command", []),
        ("scope", "partial"),
        ("working_directory", "../outside"),
        ("domains", ["invented"]),
        ("domains", ["application-security", "application-security"]),
        ("required", "yes"),
    ):
        changed = {**base, key: value}
        with pytest.raises(ValueError):
            AdapterSpec.from_dict(changed, 0)


def test_builtin_profile_policy_round_trip_owns_command_and_domains() -> None:
    """Adopters select fixed profiles without reconstructing argv or domain claims."""
    declaration: dict[str, object] = {
        "name": "semgrep-security",
        "profile": "semgrep-local-json-v1",
        "configuration_path": ".rigor/semgrep.yml",
        "target_paths": ["tests", "src"],
        "timeout_seconds": 90,
        "scope": "full",
        "working_directory": ".",
        "required": True,
    }
    spec = AdapterSpec.from_dict(declaration, 0)
    assert spec.built_in
    assert spec.command == ("semgrep",)
    assert spec.domains == ("application-security",)
    assert spec.target_paths == ("src", "tests")
    assert spec.to_dict() == {**declaration, "target_paths": ["src", "tests"]}
    assert AdapterSpec.from_dict(spec.to_dict(), 0) == spec

    for change in (
        {"profile": "unknown-profile"},
        {"command": ["semgrep", "--config", "auto"]},
        {"domains": ["supply-chain"]},
        {"configuration_path": "../semgrep.yml"},
        {"target_paths": []},
        {"working_directory": "src"},
    ):
        with pytest.raises(ValueError):
            AdapterSpec.from_dict({**declaration, **change}, 0)


def test_policy_file_loading_rejects_missing_and_malformed_documents(tmp_path: Path) -> None:
    """Policy loading distinguishes unavailable files from invalid JSON."""
    with pytest.raises(ValueError, match="cannot read audit policy"):
        AuditPolicy.from_path(tmp_path / "missing.json")

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot parse audit policy JSON"):
        AuditPolicy.from_path(malformed)
