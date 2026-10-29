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
    "variable-assignment": "model_primitives.VARIABLE_ASSIGNMENT_SCHEMA_VERSION",
    "variable-definition": "model_primitives.VARIABLE_DEFINITION_SCHEMA_VERSION",
    "work-closure": "work_closure.WORK_CLOSURE_SCHEMA_VERSION",
    "work-record": "work_models.WORK_SCHEMA_VERSION",
}

_PROVISIONAL_SCHEMA_SYMBOLS = {
    "policy_hold.POLICY_HOLD_SCHEMA_VERSION": "1.0",
    "rule_chain_profile_v3.PROFILE_RULE_DISPOSITION_SCHEMA_VERSION": "1.0",
    "rule_chain_pack_v3.STANDARD_PACK_V3_SCHEMA_VERSION": "3.0",
    "rule_chain_profile_v3.PROJECT_PROFILE_V3_SCHEMA_VERSION": "3.0",
    "rule_corpus_ratification.RULE_CORPUS_RATIFICATION_SCHEMA_VERSION": "1.0",
    "rule_corpus_acceptance.RULE_CORPUS_ACCEPTANCE_SCHEMA_VERSION": "1.0",
    "rule_chain_trust_v3.TRUST_ROLES_V3_SCHEMA_VERSION": "3.0",
    "signed_rule_chain_v3.RULE_CHAIN_V3_SCHEMA_VERSION": "3.0",
    "rule_source_document.RULE_SOURCE_DOCUMENT_SCHEMA_VERSION": "1.0",
    "selected_control_assessment_v2.SELECTED_CONTROL_ASSESSMENT_V2_SCHEMA_VERSION": "2.0",
    "quality_projection_v3.QUALITY_PROJECTION_V3_SCHEMA_VERSION": "3.0",
    "freshness_proof.INVALIDATOR_OBSERVATION_SCHEMA_VERSION": "1.0",
    "freshness_proof.FRESHNESS_PROOF_SCHEMA_VERSION": "1.0",
    "evidence_reference_v2.EVIDENCE_REFERENCE_V2_SCHEMA_VERSION": "2.0",
    "evidence_reference_v2.EVIDENCE_SUBJECT_SCHEMA_VERSION": "1.0",
    "legacy_control_binding.LEGACY_CONTROL_BINDING_SCHEMA_VERSION": "1.0",
    "control_definition_v2.CONTROL_DEFINITION_V2_SCHEMA_VERSION": "2.0",
    "evidence_contract_v2.EVIDENCE_REQUIREMENT_SCHEMA_VERSION": "1.0",
    "evidence_contract_v2.EVIDENCE_CONTRACT_V2_SCHEMA_VERSION": "2.0",
    "review_policy.REVIEW_ROLE_REQUIREMENT_SCHEMA_VERSION": "1.0",
    "review_policy.REVIEW_POLICY_SCHEMA_VERSION": "1.0",
    "atomic_rule.ATOMIC_RULE_SCHEMA_VERSION": "1.0",
    "rule_scope.RULE_SCOPE_SCHEMA_VERSION": "1.0",
    "semantic_decision.SEMANTIC_DECISION_SCHEMA_VERSION": "1.0",
    "source_universe.SOURCE_UNIVERSE_ENTRY_SCHEMA_VERSION": "1.0",
    "inventory_domain.INVENTORY_DOMAIN_SCHEMA_VERSION": "1.0",
    "inventory_baseline.INVENTORY_BASELINE_SCHEMA_VERSION": "1.0",
    "maintained_surface.MAINTAINED_SURFACE_SCHEMA_VERSION": "1.0",
    "maintained_inventory.MAINTAINED_INVENTORY_SCHEMA_VERSION": "1.0",
    "fact_context.FACT_OBSERVATION_SCHEMA_VERSION": "1.0",
    "fact_context.FACT_CONTEXT_SCHEMA_VERSION": "1.0",
    "task_context.TASK_CONTEXT_SCHEMA_VERSION": "1.0",
    "remediation_task_binding.REMEDIATION_TASK_BINDING_SCHEMA_VERSION": "1.0",
    "typed_object_reference.TYPED_OBJECT_REF_SCHEMA_VERSION": "1.0",
    "context_owner_proof.OWNER_PROOF_SCHEMA_VERSION": "1.0",
    "context_owner_observations.CONTEXT_PRODUCER_OBSERVATION_SCHEMA_VERSION": "1.0",
    "repository_state.REPOSITORY_STATE_SCHEMA_VERSION": "1.0",
    "task_definition.TASK_DEFINITION_SCHEMA_VERSION": "1.0",
    "task_definition.TASK_IDENTITY_SCHEMA_VERSION": "1.0",
    "task_definition.TYPED_OBJECT_REF_SCHEMA_VERSION": "1.0",
    "context_producer_contract.CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION": "1.0",
    "policy_read_budget.POLICY_READ_BUDGET_SCHEMA_VERSION": "1.0",
    "policy_source_spans.SOURCE_SPAN_SCHEMA_VERSION": "1.0",
    "policy_source_regions.SOURCE_REGION_SCHEMA_VERSION": "1.0",
    "condition_evaluation_cli.CONDITION_OBSERVATIONS_SCHEMA_VERSION": "rigor.condition-observations.v1",
    "condition_evaluation_cli.CONDITION_EVALUATION_SCHEMA_VERSION": "rigor.condition-evaluation.v1",
    "instruction_dispatch_permit_v2.PERMIT_V2_SCHEMA_VERSION": "instruction-dispatch-permit.v2.1",
    "verification_policy.SEMANTIC_KEY_POLICY_SCHEMA_VERSION": "2.0",
    "permit_anchor_records_v2.ANCHOR_SCHEMA_VERSION": "2.4",
    "recovery_evidence_schema_v2.ANCHOR_FINAL_RECOVERY_SCHEMA_VERSION": "rigor.permit-anchor-final-recovery.v2.4",
    "recovery_evidence_schema_v2.ANCHOR_ADOPTION_RECOVERY_SCHEMA_VERSION": "rigor.permit-anchor-recovery.v2.4",
    "recovery_evidence_schema_v2.JOURNAL_TAIL_RECOVERY_SCHEMA_VERSION": "rigor.effect-journal-tail-recovery.v2.1",
}

_SCHEMA_DISCOVERY_EXCLUSIONS = {
    "discovery_progress._INTAKE_SCHEMA_VERSION": (
        "private discovery intake transaction, not a frozen public 1.0 interchange"
    ),
    "discovery_progress._PROGRESS_SCHEMA_VERSION": (
        "private discovery bookkeeping transaction, not ratified policy or frozen 1.0 interchange"
    ),
    "discovery_receipt_host.HOST_DISCOVERY_RECEIPT_SELECTION_SCHEMA_VERSION": (
        "host-held candidate selection digest, not a public or Guard-effective wire contract"
    ),
    "discovery_receipt_host.HOST_DISCOVERY_RECEIPT_VERIFICATION_SCHEMA_VERSION": (
        "private discovery integrity proof, not a public or Guard-effective wire contract"
    ),
    "deployment_profile.DEPLOYMENT_PROFILE_SCHEMA_VERSION": (
        "operator-local deployment topology and memory paths, not a frozen public "
        "1.0 interchange; generic parser availability does not publish profile contents"
    ),
    "project_memory_activation_plan.PROJECT_MEMORY_ACTIVATION_BINDING_SCHEMA_VERSION": (
        "private memory activation proposal binding, not a public activation receipt"
    ),
    "project_memory_activation_plan.PROFILED_MEMORY_ACTIVATION_BINDING_SCHEMA_VERSION": (
        "profile-bound private memory activation proposal, not a public activation receipt"
    ),
    "project_memory_activation_plan.PROJECT_MEMORY_BOOTSTRAP_SCHEMA_VERSION": (
        "non-ratified private scaffold-only memory envelope, never public project memory"
    ),
    "project_memory_models.PROFILED_PROJECT_MEMORY_SCHEMA_VERSION": (
        "profile-bound version of the private per-repository memory-store format"
    ),
    "project_registry_models.PROFILED_PROJECT_REGISTRY_SCHEMA_VERSION": (
        "profile-bound version of the private coordination registry format"
    ),
    "project_registry_views.PROFILED_REGISTRY_CONSUMER_SCHEMA_VERSION": (
        "profile-bound private coordination consumer envelope"
    ),
    "project_registry_views.PROFILED_GROUP_VIEW_SCHEMA_VERSION": (
        "profile-bound private generated group-memory view"
    ),
    "project_registry_views.PROFILED_MEMORY_REGISTRY_BINDING_SCHEMA_VERSION": (
        "profile-bound private generated project-memory binding"
    ),
    "audit_primitives.SCHEMA_VERSION": "alias of audit_primitives.REPORT_SCHEMA_VERSION",
    "ignored_inventory._DIRECTORY_MANIFEST_SCHEMA_VERSION": (
        "private nested helper, not a public or standalone interchange identifier"
    ),
    "pack_source_host.HOST_PACK_SOURCE_SELECTION_SCHEMA_VERSION": (
        "host-held retained-source selection, not a frozen public 1.0 interchange"
    ),
    "pack_source_host.HOST_PACK_SOURCE_VERIFICATION_SCHEMA_VERSION": (
        "private retained-source integrity proof, not a Guard-effective rule lock"
    ),
    "project_memory_primitives.PROJECT_MEMORY_SCHEMA_VERSION": (
        "private per-repository memory-store format, permanently excluded from public "
        "Git, package, documentation and artifact surfaces"
    ),
    "project_registry_models.PROJECT_REGISTRY_SCHEMA_VERSION": (
        "private monorepo coordination format, not a consumer-facing 1.0 interchange identifier"
    ),
    "project_registry_views.PROJECT_GROUP_VIEW_SCHEMA_VERSION": (
        "private generated group-memory view, not a consumer-facing 1.0 interchange identifier"
    ),
    "project_registry_views.PROJECT_MEMORY_REGISTRY_BINDING_SCHEMA_VERSION": (
        "private generated project-memory binding, not a consumer-facing 1.0 "
        "interchange identifier"
    ),
    "project_registry_views.PROJECT_REGISTRY_CONSUMER_SCHEMA_VERSION": (
        "private monorepo consumer envelope, not a consumer-facing 1.0 interchange identifier"
    ),
    "release_quorum.RELEASE_QUORUM_SCHEMA_VERSION": (
        "internal release-governance certificate sealed as internal evidence; not a "
        "consumer-facing 1.0 public interchange identifier, so it is excluded from the "
        "frozen public contract rather than ratcheted into it"
    ),
    "rule_chain_candidate.RULE_CHAIN_CANDIDATE_REPORT_SCHEMA_VERSION": (
        "read-only provisional report, never an effective-rule lock or frozen 1.0 wire"
    ),
    "semantic_review_host.HOST_SEMANTIC_REVIEW_SELECTION_SCHEMA_VERSION": (
        "host-held candidate reviewer selection, not a ratified public semantic CLEAR"
    ),
    "semantic_review_host.HOST_SEMANTIC_REVIEW_VERIFICATION_SCHEMA_VERSION": (
        "private signed-review dependency proof, not Guard admission"
    ),
    "semantic_source_host.HOST_SEMANTIC_SOURCE_SELECTION_SCHEMA_VERSION": (
        "host-held candidate source selection, not a frozen public 1.0 interchange"
    ),
    "semantic_source_host.HOST_SEMANTIC_SOURCE_VERIFICATION_SCHEMA_VERSION": (
        "private source-integrity proof, not a semantic acceptance or Guard lock"
    ),
    "signed_rule_chain_v2.RULE_CHAIN_V2_SCHEMA_VERSION": (
        "unratified v2 signed-chain proposal, not the frozen public 1.0 contract"
    ),
}

_EXTERNAL_PROTOCOL_VERSION_SYMBOLS = {
    "oscal_export.OSCAL_VERSION": "external OSCAL interchange version",
    "sarif.SARIF_VERSION": "external SARIF interchange version",
}


def _observed_commands() -> dict[str, CliCommandContract]:
    """Read the real installed root parser's complete command signatures."""
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
    """Resolve each frozen declaration from its actual owning public module."""
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


def _literal_schema_version_sites(package_root: Path) -> tuple[str, ...]:
    """Find bare string schema identifiers that would evade the named inventory."""
    sites: list[str] = []
    for path in package_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "schema_version"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        sites.append(f"{path.name}:{node.lineno}")
            if not isinstance(node, ast.Compare):
                continue
            values = (node.left, *node.comparators)
            has_literal = any(
                isinstance(value, ast.Constant) and isinstance(value.value, str)
                for value in values
            )
            has_schema_lookup = any(
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "get"
                and value.args
                and isinstance(value.args[0], ast.Constant)
                and value.args[0].value == "schema_version"
                for value in values
            )
            if has_literal and has_schema_lookup:
                sites.append(f"{path.name}:{node.lineno}")
    return tuple(sorted(set(sites)))


def test_live_surfaces_match_the_frozen_1_0_contract() -> None:
    """Every supported command, flag, positional, schema, and stable API is exact."""
    assert set(_SCHEMA_SYMBOLS) == set(STABLE_SCHEMA_VERSIONS)
    assert (
        stable_contract_errors(_observed_commands(), _observed_schemas(), STABLE_PUBLIC_API) == ()
    )


def test_every_production_schema_version_has_an_explicit_classification() -> None:
    """Every declaration is frozen, version-pinned provisional or individually justified."""
    observed_symbols = set(_SCHEMA_SYMBOLS.values()) - set(_EXTERNAL_PROTOCOL_VERSION_SYMBOLS)
    discovered = _declared_schema_symbols()
    assert set(_SCHEMA_DISCOVERY_EXCLUSIONS) <= discovered
    assert set(_PROVISIONAL_SCHEMA_SYMBOLS) <= discovered
    assert not set(_PROVISIONAL_SCHEMA_SYMBOLS).intersection(observed_symbols)
    assert not set(_PROVISIONAL_SCHEMA_SYMBOLS).intersection(_SCHEMA_DISCOVERY_EXCLUSIONS)
    assert discovered - set(_SCHEMA_DISCOVERY_EXCLUSIONS) == (
        observed_symbols | set(_PROVISIONAL_SCHEMA_SYMBOLS)
    )


def test_provisional_schema_versions_are_explicit_and_cannot_drift() -> None:
    """Provisional declarations retain their pinned version outside the frozen manifest."""
    for target, expected_version in _PROVISIONAL_SCHEMA_SYMBOLS.items():
        module_name, symbol = target.rsplit(".", 1)
        module = importlib.import_module(f"rigor_foundry.{module_name}")
        assert getattr(module, symbol) == expected_version


def test_production_serializers_do_not_use_bare_schema_version_literals() -> None:
    """A nested wire format cannot evade discovery by using a bare version string."""
    package_root = Path(__file__.replace("tests/test_stable_contract.py", "src/rigor_foundry"))
    assert _literal_schema_version_sites(package_root) == ()


def test_bare_schema_guard_detects_actual_serializer_and_parser_mutations(
    tmp_path: Path,
) -> None:
    """Detect real copied production wire/version mutations rather than bypass discovery."""
    package_root = Path(__file__.replace("tests/test_stable_contract.py", "src/rigor_foundry"))
    original = (package_root / "cra_policy.py").read_text(encoding="utf-8")
    copied = tmp_path / "cra_policy.py"
    copied.write_text(original, encoding="utf-8")
    assert _literal_schema_version_sites(tmp_path) == ()
    replacements = (
        ('"schema_version": CRA_POLICY_SCHEMA_VERSION', '"schema_version": "1.0"'),
        (
            'data.get("schema_version") != CRA_POLICY_SCHEMA_VERSION',
            'data.get("schema_version") != "1.0"',
        ),
    )
    detected: set[str] = set()
    for before, after in replacements:
        assert before in original
        copied.write_text(original.replace(before, after), encoding="utf-8")
        sites = _literal_schema_version_sites(tmp_path)
        assert len(sites) == original.count(before)
        assert {site.split(":")[0] for site in sites} == {"cra_policy.py"}
        detected.update(sites)
    mutated = original
    for before, after in replacements:
        mutated = mutated.replace(before, after)
    copied.write_text(mutated, encoding="utf-8")
    assert _literal_schema_version_sites(tmp_path) == tuple(sorted(detected))


def test_profiled_serializers_preserve_wire_versions() -> None:
    """Round-trip actual profiled objects with unchanged envelope and payload versions."""
    from test_project_memory_models import profiled_manifest
    from test_project_registry_models import profiled_registry

    from rigor_foundry.deployment_profile import DeploymentProfile
    from rigor_foundry.project_memory_models import ProjectMemoryManifest
    from rigor_foundry.project_registry_models import ProjectRegistry
    from rigor_foundry.project_registry_views import (
        ProjectRegistryConsumerOutput,
        build_registry_consumer_outputs,
    )

    registry = profiled_registry()
    assert ProjectRegistry.from_bytes(registry.to_bytes()) == registry
    assert json.loads(registry.to_bytes())["schema_version"] == "project-registry.v2"
    assert registry.profile is not None
    profile_bytes = registry.profile.to_bytes()
    assert json.loads(profile_bytes)["schema_version"] == "deployment-profile.v1"
    assert DeploymentProfile.from_bytes(profile_bytes) == registry.profile
    memory = profiled_manifest()
    assert json.loads(memory.to_bytes())["schema_version"] == "project-memory.v2"
    assert ProjectMemoryManifest.from_bytes(memory.to_bytes()) == memory
    outputs = build_registry_consumer_outputs(registry, {})
    assert {output.consumer_kind for output in outputs} == {"group-view", "project-index"}
    for output in outputs:
        data = json.loads(output.to_bytes())
        assert data["schema_version"] == "project-registry-consumer.v2"
        assert (
            data["payload"]["schema_version"]
            == {
                "group-view": "project-group-view.v2",
                "project-index": "project-memory-registry-binding.v2",
            }[output.consumer_kind]
        )
        assert ProjectRegistryConsumerOutput.from_dict(data) == output


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
