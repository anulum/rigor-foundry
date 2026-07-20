# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — 1.0 stable contract tests
"""Ratchet the supported Python, command-line, and wire-schema surfaces."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from rigor_foundry.api_stability import STABLE_PUBLIC_API
from rigor_foundry.cli import _parser, main
from rigor_foundry.stable_contract import (
    STABLE_CONTRACT_SCHEMA_VERSION,
    STABLE_CONTRACT_TARGET_RELEASE,
    STABLE_SCHEMA_VERSIONS,
    CliCommandContract,
    stable_contract_errors,
    stable_contract_manifest,
)

_SCHEMA_SYMBOLS = {
    "adapter-catalogue": "adapter_catalogue.ADAPTER_CATALOGUE_SCHEMA_VERSION",
    "adapter-profile-evidence": "adapter_profiles.PROFILE_EVIDENCE_SCHEMA_VERSION",
    "adapter-result": "adapters.ADAPTER_RESULT_SCHEMA_VERSION",
    "api-declaration-manifest": "api_compatibility.API_MANIFEST_SCHEMA_VERSION",
    "api-stability-manifest": "api_stability.API_STABILITY_SCHEMA_VERSION",
    "assisted-review": "assisted_review.ASSISTED_REVIEW_SCHEMA_VERSION",
    "audit-policy": "audit_primitives.POLICY_SCHEMA_VERSION",
    "audit-policy-legacy": "audit_primitives.LEGACY_POLICY_SCHEMA_VERSION",
    "audit-report": "audit_primitives.REPORT_SCHEMA_VERSION",
    "bubblewrap-provenance": ("sandbox_provenance.BUBBLEWRAP_PROVENANCE_SCHEMA_VERSION"),
    "campaign": "campaign_models.CAMPAIGN_SCHEMA_VERSION",
    "candidate-anchor": "candidate_anchor.ANCHOR_SCHEMA_VERSION",
    "claim-isolation": "claim_isolation.CLAIM_ISOLATION_SCHEMA_VERSION",
    "compliance-map": "compliance_maps.COMPLIANCE_MAP_SCHEMA_VERSION",
    "condition-language": "condition_language.CONDITION_SCHEMA_VERSION",
    "control-assessment": "control_assessment.ASSESSMENT_SCHEMA_VERSION",
    "coverage-residual": "coverage_residuals.COVERAGE_RESIDUAL_SCHEMA_VERSION",
    "cra-policy": "cra_policy.CRA_POLICY_SCHEMA_VERSION",
    "cra-record": "cra_protocol.CRA_SCHEMA_VERSION",
    "cross-repository-campaign": (
        "cross_repository_campaign.CROSS_REPOSITORY_CAMPAIGN_SCHEMA_VERSION"
    ),
    "detached-evidence-signature": (
        "offline_verification_models.DETACHED_EVIDENCE_SIGNATURE_SCHEMA_VERSION"
    ),
    "digest-dependency": "digest_dependencies.DIGEST_DEPENDENCY_SCHEMA_VERSION",
    "effective-profile-lock": "effective_profile.LOCK_SCHEMA_VERSION",
    "effective-profile-lock-legacy": "effective_profile.LEGACY_LOCK_SCHEMA_VERSION",
    "enforcement-result": "enforcement.ENFORCEMENT_SCHEMA_VERSION",
    "fleet-view": "fleet_view.FLEET_VIEW_SCHEMA_VERSION",
    "git-provenance": "git_provenance.GIT_PROVENANCE_SCHEMA_VERSION",
    "historical-execution": ("cross_repository_execution.HISTORICAL_EXECUTION_SCHEMA_VERSION"),
    "ignored-inventory": "ignored_inventory.IGNORED_INVENTORY_SCHEMA_VERSION",
    "inference-identity": "campaign_identity.INFERENCE_IDENTITY_SCHEMA_VERSION",
    "maturity-case-manifest": ("rule_maturity_manifest.MATURITY_CASE_MANIFEST_SCHEMA_VERSION"),
    "model-alias-evidence": ("offline_verification_models.MODEL_ALIAS_EVIDENCE_SCHEMA_VERSION"),
    "model-witness": "campaign_identity.MODEL_WITNESS_SCHEMA_VERSION",
    "offline-trust-policy": "verification_policy.OFFLINE_TRUST_POLICY_SCHEMA_VERSION",
    "offline-verification": ("offline_verification_models.OFFLINE_VERIFICATION_SCHEMA_VERSION"),
    "oscal": "oscal_export.OSCAL_VERSION",
    "osv-database-manifest": "osv_database.OSV_DATABASE_MANIFEST_SCHEMA_VERSION",
    "pack-component": "standard_pack.PACK_COMPONENT_SCHEMA_VERSION",
    "pack-signature": "standard_pack.PACK_SIGNATURE_SCHEMA_VERSION",
    "pack-verification": "effective_profile.PACK_VERIFICATION_SCHEMA_VERSION",
    "polyglot-capability-matrix": "polyglot_capability_matrix.MATRIX_SCHEMA_VERSION",
    "project-profile": "project_profile.PROFILE_SCHEMA_VERSION",
    "remediation-authority": "remediation_authority.AUTHORITY_SCHEMA_VERSION",
    "remediation-executor": "remediation_executor.EXECUTOR_SCHEMA_VERSION",
    "remediation-plan": "remediation_plan.PLAN_SCHEMA_VERSION",
    "report-diff": "report_diff.REPORT_DIFF_SCHEMA_VERSION",
    "review-attestation": "review_attestation.REVIEW_ATTESTATION_SCHEMA_VERSION",
    "review-evidence": "offline_verification_models.REVIEW_EVIDENCE_SCHEMA_VERSION",
    "review-record": "audit_primitives.REVIEW_SCHEMA_VERSION",
    "rule-maturity": "rule_maturity.RULE_MATURITY_SCHEMA_VERSION",
    "rule-pack": "rules.RULE_PACK_SCHEMA_VERSION",
    "sarif": "sarif.SARIF_VERSION",
    "source-provenance": "source_capture.SOURCE_PROVENANCE_SCHEMA_VERSION",
    "stable-contract": "stable_contract.STABLE_CONTRACT_SCHEMA_VERSION",
    "standard-pack": "standard_pack.PACK_SCHEMA_VERSION",
    "trust-store": "trust.TRUST_STORE_SCHEMA_VERSION",
    "verification-key-policy": ("verification_policy.VERIFICATION_KEY_POLICY_SCHEMA_VERSION"),
    "work-closure": "work_closure.WORK_CLOSURE_SCHEMA_VERSION",
    "work-record": "work_models.WORK_SCHEMA_VERSION",
}

_SCHEMA_DISCOVERY_EXCLUSIONS = {
    "audit_primitives.SCHEMA_VERSION": "alias of audit_primitives.REPORT_SCHEMA_VERSION",
    "ignored_inventory._DIRECTORY_MANIFEST_SCHEMA_VERSION": (
        "private nested helper, not a public or standalone interchange identifier"
    ),
}

_EXTERNAL_PROTOCOL_VERSION_SYMBOLS = {
    "oscal_export.OSCAL_VERSION": "external OSCAL interchange version",
    "sarif.SARIF_VERSION": "external SARIF interchange version",
}


def _observed_commands() -> dict[str, CliCommandContract]:
    parser = _parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    observed: dict[str, CliCommandContract] = {}
    for name, command in subparsers.choices.items():
        options: list[str] = []
        positionals: list[str] = []
        for action in command._actions:
            if action.dest == "help":
                continue
            if action.option_strings:
                options.extend(action.option_strings)
            else:
                positionals.append(action.dest)
        observed[name] = CliCommandContract(tuple(sorted(options)), tuple(positionals))
    return observed


def _observed_schemas() -> dict[str, str]:
    observed: dict[str, str] = {}
    for name, target in _SCHEMA_SYMBOLS.items():
        module_name, symbol = target.rsplit(".", 1)
        module = importlib.import_module(f"rigor_foundry.{module_name}")
        observed[name] = str(getattr(module, symbol))
    return observed


def _declared_schema_symbols() -> set[str]:
    """Find every top-level schema-version declaration in production source."""
    package_root = __file__.replace("tests/test_stable_contract.py", "src/rigor_foundry")
    discovered: set[str] = set()
    for path in Path(package_root).glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets.extend(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets.append(node.target)
            for target in targets:
                if isinstance(target, ast.Name) and (
                    target.id == "SCHEMA_VERSION" or target.id.endswith("_SCHEMA_VERSION")
                ):
                    discovered.add(f"{path.stem}.{target.id}")
    return discovered


def test_live_surfaces_match_the_frozen_1_0_contract() -> None:
    """Every supported command, flag, positional, schema, and stable API is exact."""
    assert set(_SCHEMA_SYMBOLS) == set(STABLE_SCHEMA_VERSIONS)
    assert (
        stable_contract_errors(_observed_commands(), _observed_schemas(), STABLE_PUBLIC_API) == ()
    )


def test_every_production_schema_version_is_frozen_or_explicitly_private() -> None:
    """A new non-private schema declaration cannot silently evade the 1.0 inventory."""
    observed_symbols = set(_SCHEMA_SYMBOLS.values()) - set(_EXTERNAL_PROTOCOL_VERSION_SYMBOLS)
    discovered = _declared_schema_symbols()
    assert set(_SCHEMA_DISCOVERY_EXCLUSIONS) <= discovered
    assert discovered - set(_SCHEMA_DISCOVERY_EXCLUSIONS) == observed_symbols


def test_manifest_is_deterministic_digest_bound_json() -> None:
    """The public manifest has one reproducible identity and no NaN ambiguity."""
    manifest = stable_contract_manifest()
    digest = manifest.pop("contract_digest")
    encoded = json.dumps(
        manifest, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    assert digest == hashlib.sha256(encoded).hexdigest()
    assert manifest["schema_version"] == STABLE_CONTRACT_SCHEMA_VERSION == "1.0"
    assert manifest["target_release"] == STABLE_CONTRACT_TARGET_RELEASE == "1.0.0"
    assert json.loads(json.dumps(manifest, allow_nan=False, sort_keys=True)) == manifest


def test_contract_command_emits_the_exact_manifest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Installed consumers can retrieve the frozen contract without private imports."""
    assert main(["contract"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == stable_contract_manifest()


def test_drift_validator_rejects_every_surface_class() -> None:
    """Removal, addition, rebinding, and schema reinterpretation all fail closed."""
    commands = dict(_observed_commands())
    commands.pop("scan")
    commands["unknown"] = CliCommandContract(())
    commands["verify"] = CliCommandContract(("--bundle",), ("unexpected",))
    schemas = dict(_observed_schemas())
    schemas.pop("audit-report")
    schemas["review-record"] = "9.0"
    schemas["unknown"] = "1.0"
    stable_api = set(STABLE_PUBLIC_API)
    stable_api.remove("AuditReport")
    stable_api.add("Unknown")

    errors = stable_contract_errors(commands, schemas, stable_api)
    assert "stable CLI commands are missing: scan" in errors
    assert "CLI commands are unclassified: unknown" in errors
    assert "verify: stable CLI options changed" in errors
    assert "verify: stable CLI positionals changed" in errors
    assert "stable schemas are missing: audit-report" in errors
    assert "schemas are unclassified: unknown" in errors
    assert "review-record: stable schema version changed" in errors
    assert "stable Python APIs are missing: AuditReport" in errors
    assert "stable Python APIs are unclassified: Unknown" in errors
