# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — configured inventory domain tests
"""Exercise exact bounded domain source documents and their inline relationships."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.inventory_domain import (
    InventoryClassificationRule,
    InventoryDomain1,
    InventoryDomainRoot,
)
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.typed_object_reference import TypedObjectRef1


def domain_budget(**changes: int) -> PolicyReadBudget1:
    """Supply explicit ceilings for real domain source reads and classification."""
    limits = {
        "max_document_bytes": 65536,
        "max_source_bytes": 65536,
        "max_total_source_bytes": 1048576,
        "max_sources": 256,
        "max_rules": 64,
        "max_references": 512,
        "max_depth": 16,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def domain() -> InventoryDomain1:
    """Declare two actual source domains without claiming they are installed or captured."""
    root = "03_CODE/GROUP-A/repositories/PROJECT-A"
    rules = (
        InventoryClassificationRule("core", "language", "suffix", ".py", "python"),
        InventoryClassificationRule("core", "language", "suffix", ".ts", "typescript"),
        InventoryClassificationRule(
            "core", "language", "suffix", ".d.ts", "typescript-declaration"
        ),
        InventoryClassificationRule("core", "language", "exact", ".gitignore", "text"),
        InventoryClassificationRule("core", "language", "exact", "src/generated.py", "json"),
        InventoryClassificationRule("core", "role", "prefix", "src", "source"),
        InventoryClassificationRule("core", "role", "prefix", "tests", "test"),
        InventoryClassificationRule("core", "role", "prefix", "tests/fixtures", "fixture"),
        InventoryClassificationRule("core", "role", "exact", "tests/special.py", "example"),
        InventoryClassificationRule("core", "role", "exact", ".gitignore", "configuration"),
        InventoryClassificationRule("private", "language", "suffix", ".py", "python"),
        InventoryClassificationRule("private", "role", "prefix", "scripts", "tool"),
    )
    return InventoryDomain1.build(
        domain_id="configured-project",
        project_id="PROJECT-A",
        roots=(
            InventoryDomainRoot("core", root, "git"),
            InventoryDomainRoot("private", root + "/tools/.internal", "ignored"),
        ),
        rules=tuple(
            sorted(
                rules,
                key=lambda item: (item.root_id, item.field, item.selector_kind, item.selector),
            )
        ),
        budget=domain_budget(),
    )


def test_inventory_domain_round_trip_through_actual_source_bytes(tmp_path: Path) -> None:
    """Every inline root/rule and both headers participate in the complete identity."""
    declared = domain()
    path = tmp_path / "domain.json"
    path.write_text(json.dumps(declared.to_dict()), encoding="utf-8")
    loaded = InventoryDomain1.from_dict(
        read_policy_document(path, budget=domain_budget()), budget=domain_budget()
    )
    assert loaded == declared
    ref = TypedObjectRef1.from_dict(loaded.reference())
    assert ref.kind == "inventory-domain" and ref.object_digest == loaded.domain_digest
    body = loaded.to_dict()
    assert body.pop("domain_digest") == canonical_digest(body)
    assert not {"installed", "complete", "enabled", "loader", "authority"}.intersection(body)
    assert loaded.roots[1].source_kind == "ignored"
    generated = replace(loaded.roots[1], source_kind="generated")
    assert InventoryDomainRoot.from_dict(generated.to_dict()) == generated


@pytest.mark.parametrize("path", (".", "../outside", "/absolute", "a/.git/config", "a//b", "a\\b"))
def test_domain_roots_and_path_rules_refuse_unsafe_selectors(path: str) -> None:
    """Portable source declarations retain no traversal or Git-administration paths."""
    with pytest.raises(ValueError):
        InventoryDomainRoot("root", path, "git")
    with pytest.raises(ValueError):
        InventoryClassificationRule("root", "role", "prefix", path, "source")


@pytest.mark.parametrize(
    "suffix",
    (
        ".",
        "..",
        "py",
        ".PY",
        ".p*",
        ".p?",
        ".p[0]",
        ".a/b",
        ".a\\b",
        ".a\0b",
        ".a b",
        "." + "x" * 64,
    ),
)
def test_domain_suffix_rules_refuse_ambiguous_or_executable_patterns(suffix: str) -> None:
    """Suffixes are bounded literal names, never glob, regex or callback selectors."""
    with pytest.raises(ValueError, match="suffix"):
        InventoryClassificationRule("core", "language", "suffix", suffix, "python")


@pytest.mark.parametrize(
    ("field", "kind", "value"),
    (
        ("language", "prefix", "python"),
        ("role", "suffix", "test"),
        ("unknown", "exact", "text"),
        ("role", "exact", "unknown-role"),
    ),
)
def test_domain_rule_field_and_role_vocabulary_are_closed(
    field: str, kind: str, value: str
) -> None:
    """Rehashed data cannot invent selector semantics or maintained roles."""
    with pytest.raises(ValueError):
        InventoryClassificationRule("core", field, kind, "source.py", value)
    with pytest.raises(ValueError):
        InventoryDomainRoot("root", "project", "scan-fallback")


@pytest.mark.parametrize(
    "change",
    (
        "root-extra",
        "rule-extra",
        "root-duplicate",
        "path-duplicate",
        "rule-duplicate",
        "root-order",
        "rule-order",
        "foreign-root",
        "empty-roots",
        "roots-type",
        "rules-type",
        "version",
        "kind",
        "digest",
        "extra",
        "missing",
    ),
)
def test_rehashed_invalid_domain_sources_refuse(change: str) -> None:
    """Actual closed parsers reject conflicting or incomplete source declarations."""
    body = domain().to_dict()
    roots = cast(list[dict[str, object]], body["roots"])
    rules = cast(list[dict[str, object]], body["rules"])
    if change == "root-extra":
        roots[0]["callback"] = "caller"
    elif change == "rule-extra":
        rules[0]["priority"] = 999
    elif change == "root-duplicate":
        roots.append(roots[0])
    elif change == "path-duplicate":
        roots[1]["canonical_path"] = roots[0]["canonical_path"]
    elif change == "rule-duplicate":
        rules.insert(1, {**rules[0], "value": "different"})
    elif change == "root-order":
        roots.reverse()
    elif change == "rule-order":
        rules.reverse()
    elif change == "foreign-root":
        rules[0]["root_id"] = "absent"
    elif change == "empty-roots":
        body["roots"] = []
    elif change == "roots-type":
        body["roots"] = None
    elif change == "rules-type":
        body["rules"] = None
    elif change == "version":
        body["schema_version"] = "2.0"
    elif change == "kind":
        body["object_kind"] = "other"
    elif change == "digest":
        body["domain_digest"] = "0" * 64
    elif change == "extra":
        body["callback"] = "caller"
    else:
        body.pop("project_id")
    if change != "digest":
        body.pop("domain_digest")
        body["domain_digest"] = canonical_digest(body)
    with pytest.raises(ValueError):
        InventoryDomain1.from_dict(body, budget=domain_budget())


@pytest.mark.parametrize("limits", ({"max_sources": 1}, {"max_rules": 1}, {"max_references": 1}))
def test_domain_builders_and_parsers_enforce_original_collection_budgets(
    limits: dict[str, int],
) -> None:
    """A valid source cannot allocate its children before the explicit limit checks."""
    actual = domain()
    budget = domain_budget(**limits)
    with pytest.raises(ValueError, match="budget"):
        InventoryDomain1.from_dict(actual.to_dict(), budget=budget)
    with pytest.raises(ValueError, match="budget"):
        InventoryDomain1.build(
            domain_id=actual.domain_id,
            project_id=actual.project_id,
            roots=actual.roots,
            rules=actual.rules,
            budget=budget,
        )


def test_direct_domain_mutations_and_wrong_record_types_refuse() -> None:
    """Public serialization revalidates mutable Python forgery without a source lookup."""
    actual = domain()
    for roots, rules in (
        (cast(tuple[InventoryDomainRoot, ...], []), actual.rules),
        (actual.roots, cast(tuple[InventoryClassificationRule, ...], [])),
        (cast(tuple[InventoryDomainRoot, ...], ({},)), actual.rules),
        (actual.roots, cast(tuple[InventoryClassificationRule, ...], ({},))),
    ):
        with pytest.raises(ValueError):
            InventoryDomain1.build(
                domain_id="domain",
                project_id="PROJECT-A",
                roots=roots,
                rules=rules,
                budget=domain_budget(),
            )
        with pytest.raises(ValueError):
            replace(actual, roots=roots, rules=rules)
    with pytest.raises(ValueError, match="digest differs"):
        replace(actual, domain_id="changed")
    with pytest.raises(ValueError):
        replace(actual, roots=actual.roots * 2049)
    with pytest.raises(ValueError):
        replace(actual, rules=actual.rules * 1366)
    with pytest.raises(ValueError, match="budget is required"):
        InventoryDomain1.from_dict(None, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="budget is required"):
        InventoryDomain1.build(
            domain_id="domain",
            project_id="PROJECT-A",
            roots=actual.roots,
            rules=actual.rules,
            budget=cast(PolicyReadBudget1, {}),
        )
