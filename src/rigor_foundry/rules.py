# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository-audit rule registry
"""Versioned rule registry and deterministic rule-pack identity."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .audit_primitives import canonical_digest
from .model_primitives import require_semantic_version

RULE_PACK_SCHEMA_VERSION = "1.0"
RULE_PACK_VERSION = "rigor-foundry/1.6.0"
INITIAL_RULE_PACK_VERSION = "rigor-foundry/1.0.0"
APPLICATION_SECURITY_RULE_PACK_VERSION = "rigor-foundry/1.2.0"
JAVASCRIPT_RULE_PACK_VERSION = "rigor-foundry/1.3.0"
GO_RUST_RULE_PACK_VERSION = "rigor-foundry/1.4.0"
C_RULE_PACK_VERSION = "rigor-foundry/1.5.0"
JULIA_SHELL_RULE_PACK_VERSION = "rigor-foundry/1.6.0"

_RULE_ID = re.compile(r"(?:TA|AR|GF|GV|AS)[0-9]{3}-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_CATEGORY_PREFIXES = {
    "test-authenticity": "TA",
    "architecture": "AR",
    "godfile": "GF",
    "governance": "GV",
    "application-security": "AS",
}
_VERSION_PREFIX = "rigor-foundry/"


def _rule_pack_version(value: object, field: str) -> str:
    """Return one prefixed strict semantic version for rule-pack metadata."""
    if not isinstance(value, str) or not value.startswith(_VERSION_PREFIX):
        raise ValueError(f"{field} must be a prefixed semantic version")
    require_semantic_version(value.removeprefix(_VERSION_PREFIX), field)
    return value


@dataclass(frozen=True)
class RuleDefinition:
    """Stable metadata for one static candidate rule.

    Parameters
    ----------
    rule_id:
        Immutable rule identifier carried by reports and review ledgers.
    category:
        Candidate domain produced by the rule.
    summary:
        Short factual description of the signal.
    introduced:
        Rule-pack version that first defined the rule.

    """

    rule_id: str
    category: str
    summary: str
    introduced: str = INITIAL_RULE_PACK_VERSION

    def to_dict(self) -> dict[str, str]:
        """Serialise stable rule metadata."""
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "summary": self.summary,
            "introduced": self.introduced,
        }


RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition("TA001-test-double", "test-authenticity", "Test-double API or fixture signal."),
    RuleDefinition(
        "TA002-synthetic-fixture",
        "test-authenticity",
        "Synthetic fake, stub, dummy, or toy naming signal.",
    ),
    RuleDefinition(
        "TA003-skip-or-xfail", "test-authenticity", "Skipped or expected-failure test signal."
    ),
    RuleDefinition(
        "TA004-coverage-exclusion",
        "test-authenticity",
        "Coverage exclusion signal in tracked Python or JavaScript-family text.",
    ),
    RuleDefinition(
        "TA005-lint-suppression", "test-authenticity", "Local lint or security suppression signal."
    ),
    RuleDefinition(
        "TA006-type-suppression", "test-authenticity", "Local static-type suppression signal."
    ),
    RuleDefinition(
        "TA007-module-injection", "test-authenticity", "Module-resolution injection signal."
    ),
    RuleDefinition(
        "TA008-coverage-bucket-name", "test-authenticity", "Non-specific test-owner name signal."
    ),
    RuleDefinition(
        "TA009-unparseable-python-test",
        "test-authenticity",
        "Tracked Python test cannot be parsed.",
    ),
    RuleDefinition(
        "TA010-smoke-only-test",
        "test-authenticity",
        "Test has no local behavioural contract signal.",
    ),
    RuleDefinition(
        "TA011-private-production-surface",
        "test-authenticity",
        "Test directly reaches an underscored first-party surface.",
    ),
    RuleDefinition(
        "AR001-first-party-import-cycle",
        "architecture",
        "Non-trivial first-party Python import cycle.",
    ),
    RuleDefinition(
        "AR002-wildcard-import-boundary", "architecture", "Wildcard Python import boundary."
    ),
    RuleDefinition(
        "AR003-broad-optional-import-boundary",
        "architecture",
        "Import guarded by a broad exception handler.",
    ),
    RuleDefinition(
        "AR004-executable-facade", "architecture", "Facade also owns executable function bodies."
    ),
    RuleDefinition(
        "AR005-no-module-named-test-owner",
        "architecture",
        "Production module lacks an obvious module-named test owner.",
    ),
    RuleDefinition(
        "AR006-duplicate-python-implementation",
        "architecture",
        "Exact non-trivial top-level Python implementation body has multiple owners.",
    ),
    RuleDefinition(
        "AR007-relative-dependency-cycle",
        "architecture",
        "Non-trivial relative dependency cycle in a non-Python language surface.",
    ),
    RuleDefinition(
        "AR008-no-polyglot-test-owner",
        "architecture",
        "Non-Python production owner lacks an obvious source-named test owner.",
    ),
    RuleDefinition(
        "GF001-large-responsibility-owner",
        "godfile",
        "Tracked code owner exceeds its review threshold.",
    ),
    RuleDefinition(
        "GF002-missing-size-registry", "godfile", "Configured module-size registry is unavailable."
    ),
    RuleDefinition(
        "GF003-invalid-size-registry", "godfile", "Configured module-size registry is malformed."
    ),
    RuleDefinition(
        "GF004-incomplete-size-decision",
        "godfile",
        "Module-size decision lacks required evidence.",
    ),
    RuleDefinition(
        "GF005-size-decision-drift",
        "godfile",
        "Module-size decision differs from the tracked tree.",
    ),
    RuleDefinition(
        "GV001-missing-repository-audit-policy",
        "governance",
        "Repository-specific audit policy is absent.",
    ),
    RuleDefinition(
        "GV002-unscanned-tracked-code",
        "governance",
        "Tracked code or test content could not be parsed as bounded UTF-8 text.",
    ),
    RuleDefinition(
        "GV003-undeclared-audit-domain",
        "governance",
        "Mandatory audit domain has no repository applicability decision.",
    ),
    RuleDefinition(
        "GV004-uncontrolled-required-domain",
        "governance",
        "Required audit domain has no active portable rule or required native adapter.",
    ),
    RuleDefinition(
        "AS001-dynamic-code-execution",
        "application-security",
        "Dynamic code execution through eval or exec.",
        APPLICATION_SECURITY_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS002-shell-command-execution",
        "application-security",
        "Shell command execution surface via shell=True, os.system, or os.popen.",
        APPLICATION_SECURITY_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS003-unsafe-deserialization",
        "application-security",
        "Unsafe deserialization via pickle or an unbounded yaml.load.",
        APPLICATION_SECURITY_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS004-weak-hash-primitive",
        "application-security",
        "Weak hash primitive md5 or sha1 in a possible security context.",
        APPLICATION_SECURITY_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS005-insecure-temporary-file",
        "application-security",
        "Insecure temporary file creation through tempfile.mktemp.",
        APPLICATION_SECURITY_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS006-js-dynamic-code-execution",
        "application-security",
        "Native JavaScript or TypeScript dynamic code execution via eval or Function.",
        JAVASCRIPT_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS007-go-command-execution",
        "application-security",
        "Native Go external command execution via os/exec Command or CommandContext.",
        GO_RUST_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS008-rust-unsafe-block",
        "application-security",
        "Native Rust unsafe block that suspends compiler memory-safety guarantees.",
        GO_RUST_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS009-c-unsafe-libc",
        "application-security",
        "Native C or C++ call to an unbounded or command-executing libc function.",
        C_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS010-julia-unsafe-memory",
        "application-security",
        "Native Julia unsafe_* intrinsic that bypasses bounds, type, and GC safety.",
        JULIA_SHELL_RULE_PACK_VERSION,
    ),
    RuleDefinition(
        "AS011-shell-eval-execution",
        "application-security",
        "Native shell eval builtin that re-parses its argument as a command.",
        JULIA_SHELL_RULE_PACK_VERSION,
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}


def rule_pack_digest(
    *,
    rules: tuple[RuleDefinition, ...] = RULES,
    version: str = RULE_PACK_VERSION,
) -> str:
    """Return the canonical identity of one versioned ordered rule registry.

    Parameters
    ----------
    rules:
        Ordered rule definitions whose complete metadata enters the identity.
    version:
        Rule-pack version bound into the identity envelope.
    """
    validated_version = _rule_pack_version(version, "rule_pack_version")
    return canonical_digest(
        {
            "schema_version": RULE_PACK_SCHEMA_VERSION,
            "rule_pack_version": validated_version,
            "rules": [rule.to_dict() for rule in rules],
        }
    )


def validate_rule_registry(
    rules: tuple[RuleDefinition, ...] = RULES,
) -> tuple[str, ...]:
    """Return structural errors in one ordered rule registry.

    Parameters
    ----------
    rules:
        Registry to validate. The built-in registry is used by default.
    """
    errors: list[str] = []
    identifiers = [rule.rule_id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        errors.append("rule identifiers must be unique")
    for rule in rules:
        if _RULE_ID.fullmatch(rule.rule_id) is None:
            errors.append(f"{rule.rule_id}: rule identifier is invalid")
        expected_prefix = _CATEGORY_PREFIXES.get(rule.category)
        if expected_prefix is None:
            errors.append(f"{rule.rule_id}: unsupported category {rule.category}")
        elif not rule.rule_id.startswith(expected_prefix):
            errors.append(f"{rule.rule_id}: identifier does not match category {rule.category}")
        if not rule.summary.strip():
            errors.append(f"{rule.rule_id}: summary is empty")
        try:
            _rule_pack_version(rule.introduced, f"{rule.rule_id}.introduced")
        except ValueError:
            errors.append(f"{rule.rule_id}: introduced version is invalid")
    return tuple(sorted(set(errors)))
