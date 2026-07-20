# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — 1.0 stable compatibility contract
"""Freeze the supported Python, CLI, and serialized-protocol surfaces for 1.0."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

STABLE_CONTRACT_SCHEMA_VERSION = "1.0"
STABLE_CONTRACT_TARGET_RELEASE = "1.0.0"
MINIMUM_DEPRECATION_MINOR_RELEASES = 2


@dataclass(frozen=True)
class CliCommandContract:
    """One exact command spelling, option set, and positional interface."""

    options: tuple[str, ...]
    positionals: tuple[str, ...] = ()


def _command(*options: str, positionals: tuple[str, ...] = ()) -> CliCommandContract:
    """Build one deterministically ordered command contract."""
    return CliCommandContract(tuple(sorted(options)), positionals)


STABLE_CLI_COMMANDS: Mapping[str, CliCommandContract] = MappingProxyType(
    {
        "advisory-delay": _command(
            "--evidence", "--reason", "--review-at", "--root", positionals=("event_key",)
        ),
        "advisory-draft": _command(
            "--advisory-path",
            "--drafted-at",
            "--root",
            "--security-update-ref",
            positionals=("event_key",),
        ),
        "advisory-publish": _command(
            "--evidence", "--published-at", "--root", positionals=("event_key",)
        ),
        "bootstrap": _command(
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
            "--policy",
            "--review-ledger",
            "--root",
            "--source-line-threshold",
            "--source-root",
            "--test-line-threshold",
            "--test-root",
            "--todo",
        ),
        "campaign-compare": _command(
            "--actor",
            "--campaign",
            "--comparison-id",
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
        ),
        "campaign-create": _command(
            "--actor",
            "--audit-root",
            "--campaign-id",
            "--expected-runs",
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
            "--policy",
            "--project",
            "--purpose",
            "--required-model-witnesses",
            "--root",
        ),
        "campaign-run": _command(
            "--agent",
            "--allow-native-audits",
            "--campaign",
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
            "--model",
            "--model-family",
            "--operator",
            "--provider",
            "--run-id",
            "--session",
        ),
        "contract": _command(),
        "cra-bootstrap": _command(
            "--csirt-endpoint-id",
            "--establishment-basis",
            "--expected-use-evidence-ref",
            "--expected-use-months",
            "--main-establishment-ms",
            "--manufacturer-name",
            "--product-key",
            "--product-name",
            "--registered-at",
            "--root",
            "--support-period-months",
            "--user-notice-channel",
        ),
        "cra-draft": _command("--generated-at", "--root", "--stage", positionals=("event_key",)),
        "cra-pack": _command("--key-id", "--out", "--signing-key"),
        "cra-receipt": _command(
            "--bound-at",
            "--csirt-endpoint-id",
            "--draft-digest",
            "--evidence",
            "--platform-ref",
            "--root",
            "--stage",
            "--submitted-at",
            positionals=("event_key",),
        ),
        "cra-skip": _command(
            "--evidence-ref",
            "--provided-in-receipt-digest",
            "--provided-in-stage",
            "--reason",
            "--root",
            "--skipped-at",
            "--stage",
            positionals=("event_key",),
        ),
        "cra-status": _command("--event-key", "--json", "--now", "--root"),
        "gate": _command(
            "--allow-native-audits",
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
            "--maturity",
            "--mode",
            "--output",
            "--policy",
            "--review",
            "--root",
            "--scope",
        ),
        "maturity-evaluate": _command("--cases", "--output"),
        "oscal": _command("--assessments", "--generated-at", "--lock", "--output", "--template"),
        "promote": _command(
            "--apply",
            "--campaign",
            "--candidate-id",
            "--comparison",
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
            "--policy",
            "--report",
            "--review",
            "--root",
            "--todo",
        ),
        "report-diff": _command(
            "--after",
            "--anchor-matches",
            "--before",
            "--declare-branch-change",
            "--declare-policy-change",
            "--declare-repository-change",
            "--declare-rule-pack-change",
            "--declare-scanner-change",
            "--justification",
            "--output",
        ),
        "residuals-check": _command("--manifest", "--root"),
        "review-template": _command("--output", "--report"),
        "sarif": _command("--output", "--report", "--review"),
        "sbom-import": _command(
            "--captured-at",
            "--coverage",
            "--file",
            "--format",
            "--product-key",
            "--root",
            "--source-evidence",
            "--source-tool",
        ),
        "sbom-status": _command("--observed-at", "--product-key", "--root"),
        "scan": _command(
            "--changed-since",
            "--fail-on-candidates",
            "--git-executable",
            "--git-max-version-exclusive",
            "--git-min-version",
            "--git-trust-root",
            "--json-out",
            "--markdown-out",
            "--policy",
            "--root",
        ),
        "source-capture": _command(
            "--final-uri",
            "--http-status",
            "--media-type",
            "--output",
            "--payload",
            "--policy",
            "--redirect-count",
            "--requested-uri",
            "--retrieved-at",
            "--retriever-executable-digest",
            "--retriever-name",
            "--retriever-version",
        ),
        "source-verify": _command(
            "--capture", "--claim", "--output", "--payload", "--verified-at", "--verifier"
        ),
        "user-notice": _command(
            "--audience",
            "--generated-at",
            "--machine-readable",
            "--root",
            positionals=("event_key",),
        ),
        "validate-review": _command("--report", "--review"),
        "verify": _command("--at", "--bundle", "--output", "--trust-policy"),
        "vuln-register": _command(
            "--aware-at",
            "--aware-evidence",
            "--component",
            "--corrective-measure-available-at",
            "--exploitation-evidence",
            "--external-id",
            "--intermediate-due-at",
            "--intermediate-evidence",
            "--intermediate-requested-at",
            "--member-state",
            "--osv-adapter-result",
            "--osv-id",
            "--osv-imported-at",
            "--osv-output",
            "--osv-package",
            "--product-key",
            "--recorded-at",
            "--root",
            "--sensitivity",
            "--severe-evidence",
            "--severe-prong",
            "--severity-source",
            "--severity-value",
            "--status",
            "--suspected-cause",
            "--track",
            positionals=("event_key",),
        ),
        "vuln-timeline": _command("--now", "--root", positionals=("event_key",)),
    }
)

STABLE_PYTHON_API: frozenset[str] = frozenset(
    {
        "AuditPolicy",
        "AuditReport",
        "Candidate",
        "GitTrustPolicy",
        "ReviewRecord",
        "__version__",
        "report_markdown",
        "review_templates",
        "scan_repository",
        "stable_contract_manifest",
        "validate_reviews",
    }
)

STABLE_SCHEMA_VERSIONS: Mapping[str, str] = MappingProxyType(
    {
        "adapter-catalogue": "1.0",
        "adapter-profile-evidence": "1.0",
        "adapter-result": "2.0",
        "api-declaration-manifest": "1.0",
        "api-stability-manifest": "1.1",
        "assisted-review": "1.0",
        "audit-policy": "1.4",
        "audit-report": "1.3",
        "campaign": "1.9",
        "candidate-anchor": "1.0",
        "claim-isolation": "1.0",
        "compliance-map": "1.0",
        "condition-language": "1.1",
        "control-assessment": "1.1",
        "cra-policy": "1.0",
        "cra-record": "1.0",
        "cross-repository-campaign": "1.0",
        "detached-evidence-signature": "1.0",
        "digest-dependency": "1.8",
        "effective-profile-lock": "1.1",
        "enforcement-result": "1.4",
        "fleet-view": "1.0",
        "ignored-inventory": "1.0",
        "inference-identity": "1.0",
        "maturity-case-manifest": "1.0",
        "model-alias-evidence": "1.0",
        "model-witness": "1.2",
        "offline-trust-policy": "1.0",
        "offline-verification": "1.0",
        "oscal": "1.1.3",
        "osv-database-manifest": "1.0",
        "pack-component": "1.0",
        "pack-signature": "1.0",
        "pack-verification": "1.0",
        "polyglot-capability-matrix": "1.0",
        "project-profile": "1.0",
        "remediation-authority": "1.0",
        "remediation-executor": "1.0",
        "remediation-plan": "1.0",
        "report-diff": "1.0",
        "review-attestation": "2.0",
        "review-evidence": "1.0",
        "review-record": "1.0",
        "rule-maturity": "1.0",
        "rule-pack": "1.0",
        "sarif": "2.1.0",
        "source-provenance": "1.0",
        "standard-pack": "1.1",
        "trust-store": "1.0",
        "verification-key-policy": "1.0",
        "work-closure": "1.0",
        "work-record": "1.0",
    }
)


def _payload() -> dict[str, object]:
    """Return the canonical contract payload before its digest is attached."""
    return {
        "schema_version": STABLE_CONTRACT_SCHEMA_VERSION,
        "target_release": STABLE_CONTRACT_TARGET_RELEASE,
        "compatibility": {
            "breaking_changes": "next-major-release-only",
            "minimum_deprecation_minor_releases": MINIMUM_DEPRECATION_MINOR_RELEASES,
            "schema_rule": (
                "never reinterpret a published schema identifier; retain its reader or "
                "publish a new identifier with an explicit migration"
            ),
        },
        "python_api": {
            "stable": sorted(STABLE_PYTHON_API),
            "deprecated": [],
            "provisional_policy": (
                "unlisted package exports remain provisional and require an explicit "
                "changelog entry before incompatible change"
            ),
        },
        "cli": {
            "stable": [
                {
                    "command": name,
                    "options": list(contract.options),
                    "positionals": list(contract.positionals),
                }
                for name, contract in sorted(STABLE_CLI_COMMANDS.items())
            ],
            "deprecated": [],
            "exit_codes": {
                "0": "operation completed",
                "1": "candidate, review, or policy gate did not pass",
                "2": "invalid input or unsafe/unavailable state",
            },
        },
        "schemas": [
            {"name": name, "version": version}
            for name, version in sorted(STABLE_SCHEMA_VERSIONS.items())
        ],
    }


def stable_contract_manifest() -> dict[str, object]:
    """Return the deterministic, digest-bound 1.0 compatibility contract."""
    payload = _payload()
    encoded = json.dumps(
        payload, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return {**payload, "contract_digest": hashlib.sha256(encoded).hexdigest()}


def stable_contract_errors(
    commands: Mapping[str, CliCommandContract],
    schemas: Mapping[str, str],
    stable_python_api: Iterable[str],
) -> tuple[str, ...]:
    """Return deterministic drift errors against the frozen 1.0 surfaces."""
    errors: list[str] = []
    expected_commands = set(STABLE_CLI_COMMANDS)
    observed_commands = set(commands)
    missing_commands = expected_commands - observed_commands
    unknown_commands = observed_commands - expected_commands
    if missing_commands:
        errors.append("stable CLI commands are missing: " + ", ".join(sorted(missing_commands)))
    if unknown_commands:
        errors.append("CLI commands are unclassified: " + ", ".join(sorted(unknown_commands)))
    for name in sorted(expected_commands & observed_commands):
        expected = STABLE_CLI_COMMANDS[name]
        observed = commands[name]
        if tuple(sorted(observed.options)) != expected.options:
            errors.append(f"{name}: stable CLI options changed")
        if observed.positionals != expected.positionals:
            errors.append(f"{name}: stable CLI positionals changed")

    expected_schemas = set(STABLE_SCHEMA_VERSIONS)
    observed_schemas = set(schemas)
    missing_schemas = expected_schemas - observed_schemas
    unknown_schemas = observed_schemas - expected_schemas
    if missing_schemas:
        errors.append("stable schemas are missing: " + ", ".join(sorted(missing_schemas)))
    if unknown_schemas:
        errors.append("schemas are unclassified: " + ", ".join(sorted(unknown_schemas)))
    for name in sorted(expected_schemas & observed_schemas):
        if schemas[name] != STABLE_SCHEMA_VERSIONS[name]:
            errors.append(f"{name}: stable schema version changed")

    observed_api = set(stable_python_api)
    missing_api = set(STABLE_PYTHON_API) - observed_api
    unknown_api = observed_api - set(STABLE_PYTHON_API)
    if missing_api:
        errors.append("stable Python APIs are missing: " + ", ".join(sorted(missing_api)))
    if unknown_api:
        errors.append("stable Python APIs are unclassified: " + ", ".join(sorted(unknown_api)))
    return tuple(sorted(set(errors)))
