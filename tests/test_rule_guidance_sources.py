# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — static proof that detectors take candidate text only from RULE_GUIDANCE
"""Read every detector's tracked source and prove its candidate text comes from RULE_GUIDANCE."""

from __future__ import annotations

import ast
import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from rigor_foundry.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
_FIELDS = ("rationale", "verification")
_RULE_IDS = frozenset(rule.rule_id for rule in RULES)


@dataclass
class _ModuleSites:
    """What one detector module's candidate-text sites reference."""

    literal_keys: set[str] = field(default_factory=set)
    variable_keyed: bool = False
    rule_id_literals: set[str] = field(default_factory=set)
    case_indices: set[tuple[str, int]] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)


def _detector_modules() -> list[Path]:
    """Return every tracked package module that publishes ``RULE_GUIDANCE``."""
    package = ROOT / "src" / "rigor_foundry"
    return sorted(
        path
        for path in package.glob("*.py")
        if "\nRULE_GUIDANCE: " in path.read_text(encoding="utf-8")
    )


def _definition_nodes(tree: ast.Module) -> set[int]:
    """Return the ids of every node inside the module's ``RULE_GUIDANCE`` definition."""
    for statement in tree.body:
        target = statement.target if isinstance(statement, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == "RULE_GUIDANCE":
            return {id(node) for node in ast.walk(statement)}
    raise AssertionError("module publishes no RULE_GUIDANCE definition")


def _chain(value: ast.expr, field_name: str) -> tuple[ast.expr, int | None] | None:
    """Return the key and case index of ``RULE_GUIDANCE[key](.cases[i]).<field_name>``."""
    if not (isinstance(value, ast.Attribute) and value.attr == field_name):
        return None
    base = value.value
    index: int | None = None
    if (
        isinstance(base, ast.Subscript)
        and isinstance(base.value, ast.Attribute)
        and base.value.attr == "cases"
        and isinstance(base.slice, ast.Constant)
        and isinstance(base.slice.value, int)
    ):
        index = base.slice.value
        base = base.value.value
    if (
        isinstance(base, ast.Subscript)
        and isinstance(base.value, ast.Name)
        and base.value.id == "RULE_GUIDANCE"
    ):
        return base.slice, index
    return None


def _is_passthrough(value: ast.expr, field_name: str) -> bool:
    """Return whether ``value`` forwards an already-sourced text of the same field."""
    if isinstance(value, ast.Name):
        return value.id == field_name
    return (
        isinstance(value, ast.Attribute)
        and value.attr == field_name
        and isinstance(value.value, ast.Name)
    )


def _literal(node: ast.expr | None) -> str | None:
    """Return the string value of a literal node, or ``None`` for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _record(
    sites: _ModuleSites, key: ast.expr, index: int | None, expected: ast.expr | None, where: str
) -> None:
    """Record one guidance key and check that it names the same rule as its site."""
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        sites.literal_keys.add(key.value)
        if index is not None:
            sites.case_indices.add((key.value, index))
        expected_id = _literal(expected)
        if expected_id is not None and expected_id != key.value:
            sites.problems.append(f"{where}: reads {key.value} for {expected_id}")
    elif isinstance(key, ast.Name):
        sites.variable_keyed = True
        if isinstance(expected, ast.Name) and expected.id != key.id:
            sites.problems.append(f"{where}: reads RULE_GUIDANCE[{key.id}] for {expected.id}")
        expected_id = _literal(expected)
        if expected_id is not None:
            sites.problems.append(f"{where}: variable key for literal rule {expected_id}")
    else:
        sites.problems.append(f"{where}: unclassifiable guidance key {ast.unparse(key)}")


def _situation(value: ast.expr, field_name: str) -> tuple[str, str, int | None] | None:
    """Return which situation one text value names: a guidance key and case, or a forwarded owner."""
    chain = _chain(value, field_name)
    if chain is not None:
        return "guidance", ast.unparse(chain[0]), chain[1]
    if isinstance(value, ast.Name) and value.id == field_name:
        return "forwarded", "", None
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
        return "forwarded", value.value.id, None
    return None


def _require_one_situation(sites: _ModuleSites, values: dict[str, ast.expr], where: str) -> None:
    """Report a site whose rationale and verification name different situations."""
    if len(values) != len(_FIELDS):
        return
    named = {_situation(value, field_name) for field_name, value in values.items()}
    if len(named) != 1:
        sites.problems.append(f"{where}: mixed situations")


def analyse_module(source: str, name: str) -> _ModuleSites:
    """Classify every candidate-text site of one detector source.

    Parameters
    ----------
    source : str
        The detector module's exact source text.
    name : str
        The module name used in problem reports.

    Returns
    -------
    _ModuleSites
        The referenced keys, case indices and every unclassifiable or cross-rule site.
    """
    tree = ast.parse(source)
    skip = _definition_nodes(tree)
    sites = _ModuleSites()
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "RULE_GUIDANCE"
        ):
            _record(sites, node.slice, None, None, f"{name}:{node.lineno} lookup")
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _RULE_IDS
        ):
            sites.rule_id_literals.add(node.value)
        if isinstance(node, ast.Call):
            keywords = {item.arg: item.value for item in node.keywords if item.arg}
            expected = keywords.get("rule_id")
            for field_name in _FIELDS:
                value = keywords.get(field_name)
                if value is None:
                    continue
                where = f"{name}:{value.lineno} {field_name}"
                chain = _chain(value, field_name)
                if chain is not None:
                    _record(sites, chain[0], chain[1], expected, where)
                elif not _is_passthrough(value, field_name):
                    sites.problems.append(
                        f"{where}: unclassifiable value {ast.unparse(value)[:60]}"
                    )
            present = {key: keywords[key] for key in _FIELDS if key in keywords}
            _require_one_situation(sites, present, f"{name}:{node.lineno}")
        if isinstance(node, ast.Tuple):
            literal_ids = [
                item.value
                for item in node.elts
                if isinstance(item, ast.Constant)
                and isinstance(item.value, str)
                and item.value in _RULE_IDS
            ]
            tuple_values: dict[str, ast.expr] = {}
            for item in node.elts:
                for field_name in _FIELDS:
                    chain = _chain(item, field_name)
                    if chain is None:
                        continue
                    tuple_values[field_name] = item
                    where = f"{name}:{item.lineno} tuple {field_name}"
                    expected_id = ast.Constant(literal_ids[0]) if len(literal_ids) == 1 else None
                    if expected_id is None:
                        sites.problems.append(f"{where}: tuple does not name exactly one rule")
                    _record(sites, chain[0], chain[1], expected_id, where)
            _require_one_situation(sites, tuple_values, f"{name}:{node.lineno} tuple")
    return sites


def _referenced(sites: _ModuleSites) -> set[str]:
    """Return the rule ids a module's sites reference, through literal or variable keys."""
    return sites.literal_keys | (sites.rule_id_literals if sites.variable_keyed else set())


def test_every_candidate_text_site_reads_its_own_rules_published_guidance() -> None:
    """No site passes a literal or formatted text, and none reads another rule's entry."""
    problems: list[str] = []
    for path in _detector_modules():
        problems += analyse_module(path.read_text(encoding="utf-8"), path.stem).problems
    assert problems == []


def test_the_sites_reference_every_registered_rule_and_every_further_case() -> None:
    """Across the 20 detectors the sites reach all 68 rules and each published case."""
    referenced: set[str] = set()
    cases: set[tuple[str, int]] = set()
    for path in _detector_modules():
        sites = analyse_module(path.read_text(encoding="utf-8"), path.stem)
        module = importlib.import_module(f"rigor_foundry.{path.stem}")
        published = set(module.RULE_GUIDANCE)
        reached = _referenced(sites) & published
        assert reached == published, (
            f"{path.stem} leaves {sorted(published - reached)} unreferenced"
        )
        referenced |= reached
        cases |= sites.case_indices
        for rule_id, guidance in module.RULE_GUIDANCE.items():
            for index in range(len(guidance.cases)):
                assert (rule_id, index) in sites.case_indices, f"{rule_id} case {index} is unused"
    assert len(_detector_modules()) == 20
    assert referenced == set(_RULE_IDS)
    assert cases == {
        ("AA001-unbound-api-manifest", 0),
        ("CR004-untracked-reporting-timeline", 0),
    }


def test_a_literal_bypass_and_a_cross_rule_key_are_both_refused() -> None:
    """The static reader refuses a literal text and a site reading another rule's entry."""
    test_authenticity = (ROOT / "src/rigor_foundry/test_authenticity.py").read_text(
        encoding="utf-8"
    )
    reference = 'RULE_GUIDANCE["TA001-test-double"].rationale'
    assert reference in test_authenticity
    bypassed = test_authenticity.replace(reference, '"A test double replaces a collaborator."', 1)
    assert any(
        "unclassifiable value" in problem
        for problem in analyse_module(bypassed, "test_authenticity").problems
    )
    cra = (ROOT / "src/rigor_foundry/cra_rules.py").read_text(encoding="utf-8")
    own = 'RULE_GUIDANCE["CR005-support-period-too-short"].rationale'
    assert own in cra
    crossed = cra.replace(own, 'RULE_GUIDANCE["CR004-untracked-reporting-timeline"].rationale', 1)
    assert any(
        "reads CR004-untracked-reporting-timeline for CR005-support-period-too-short" in problem
        for problem in analyse_module(crossed, "cra_rules").problems
    )


def _primary_verification_at_the_second_case(source: str, rule_id: str) -> str:
    """Return ``source`` with the rule's second-case verification read from its primary entry."""
    second = re.compile(
        r'RULE_GUIDANCE\["' + re.escape(rule_id) + r'"\]\s*\.cases\[0\]\s*\.verification'
    )
    mixed, replaced = second.subn(f'RULE_GUIDANCE["{rule_id}"].verification', source, count=1)
    assert replaced == 1
    return mixed


def test_a_site_mixing_two_situations_of_one_rule_is_refused() -> None:
    """Rationale from the second situation with the primary verification is a mixed site."""
    for module, rule_id in (
        ("api_compatibility", "AA001-unbound-api-manifest"),
        ("cra_rules", "CR004-untracked-reporting-timeline"),
    ):
        source = (ROOT / f"src/rigor_foundry/{module}.py").read_text(encoding="utf-8")
        assert analyse_module(source, module).problems == []
        mixed = _primary_verification_at_the_second_case(source, rule_id)
        assert any(
            problem.endswith("mixed situations")
            for problem in analyse_module(mixed, module).problems
        ), rule_id
