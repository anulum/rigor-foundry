# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — test-authenticity candidate scanner
"""Collect static test-authenticity signals for evidence review."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence


@dataclass(frozen=True)
class _TextRule:
    """One textual test-authenticity candidate rule."""

    rule_id: str
    expression: re.Pattern[str]
    confidence: Confidence
    rationale: str
    verification: str


_TEST_DOUBLE_RULE = _TextRule(
    rule_id="TA001-test-double",
    expression=re.compile(
        r"(?:\bmonkeypatch\b|pytest\.MonkeyPatch|unittest\.mock|"
        r"\bMagicMock\b|\bMock\b|\bmocker\b|\bpatch\s*\(|"
        r"jest\.(?:mock|spyOn)|vi\.(?:mock|spyOn|fn|stubGlobal|useFakeTimers)|"
        r"sinon\.(?:mock|stub|spy)|mockall)"
    ),
    confidence="high",
    rationale=("A test double may replace the production boundary that the test claims to prove."),
    verification=(
        "Trace the test from its public API, CLI, adapter, or workflow entry point; verify that "
        "the substituted object is an approved protocol-faithful external fixture and that the "
        "production adapter and validation path still execute."
    ),
)

_SYNTHETIC_RULE = _TextRule(
    rule_id="TA002-synthetic-fixture",
    expression=re.compile(r"\b(?:fake|faker|mocked|stub|dummy|toy)[A-Za-z0-9_]*\b", re.IGNORECASE),
    confidence="medium",
    rationale="Synthetic naming can identify fixtures that do not represent a real contract.",
    verification=(
        "Compare the fixture with the repository schema, external protocol, recorded artefact, or "
        "documented domain example and prove which production boundary consumes it."
    ),
)

_SKIP_RULE = _TextRule(
    rule_id="TA003-skip-or-xfail",
    expression=re.compile(
        r"(?:pytest\.mark\.(?:skip|skipif|xfail)|pytest\.(?:skip|xfail|importorskip)|"
        r"@unittest\.skip|\bskipTest\b|#\[ignore\]|@test_skip|@test_broken|"
        r"\b(?:describe|it|test)\.skip\s*\(|\bt\.Skip\s*\()"
    ),
    confidence="high",
    rationale="A conditional or ignored test can hide an unverified production path.",
    verification=(
        "Reproduce the dependency or hardware boundary, verify the gate is explicit and fail-closed, "
        "and identify the separate real integration job or evidence path that executes the contract."
    ),
)

_COVERAGE_RULE = _TextRule(
    rule_id="TA004-coverage-exclusion",
    expression=re.compile(
        r"(?:pragma:\s*no cover|coverage:\s*ignore|istanbul\s+ignore|c8\s+ignore|lcov_excl)"
    ),
    confidence="high",
    rationale="Coverage exclusions can conceal reachable error or integration paths.",
    verification=(
        "Prove the branch is structurally unreachable on every supported runtime or replace the "
        "exclusion with a real error-path or matrix test."
    ),
)

_LINT_RULE = _TextRule(
    rule_id="TA005-lint-suppression",
    expression=re.compile(r"(?:#\s*noqa\b|eslint-disable|ruff:\s*noqa|#\s*nosec\b)"),
    confidence="medium",
    rationale="A local suppression may hide a policy or security defect.",
    verification=(
        "Run the owning analyser without the suppression, establish the exact diagnostic, and verify "
        "a tracked, source-specific justification or remove the suppression."
    ),
)

_TYPE_RULE = _TextRule(
    rule_id="TA006-type-suppression",
    expression=re.compile(r"#\s*type:\s*ignore\b|@ts-ignore|@ts-expect-error"),
    confidence="medium",
    rationale="A type suppression can hide a broken production or test contract.",
    verification=(
        "Run strict typing on the owning module, confirm the exact error code and external typing "
        "boundary, then replace the suppression or document the narrow tracked reason."
    ),
)

_MODULE_INJECTION_RULE = _TextRule(
    rule_id="TA007-module-injection",
    expression=re.compile(r"(?:sys\.modules\s*\[|require\.cache|moduleNameMapper)"),
    confidence="high",
    rationale="Module injection can bypass import, packaging, or optional-dependency wiring.",
    verification=(
        "Execute the real package or direct-script import path in a clean subprocess and prove the "
        "same packaging and dependency boundary without replacing module resolution."
    ),
)

_TEXT_RULES = (
    _TEST_DOUBLE_RULE,
    _SYNTHETIC_RULE,
    _SKIP_RULE,
    _COVERAGE_RULE,
    _LINT_RULE,
    _TYPE_RULE,
    _MODULE_INJECTION_RULE,
)

_BUCKET_NAME = re.compile(
    r"(?:^test_(?:cov|coverage|batch|round\d+|misc|final|new_modules)|"
    r"(?:coverage_closure|final_gaps|remaining|coverage_100|_push)\.py$)"
)

_BEHAVIOURAL_CALLS = frozenset(
    {
        "approx",
        "raises",
        "warns",
        "fail",
        "assert_called",
        "assert_called_once",
        "assert_called_with",
        "assert_allclose",
        "assert_array_equal",
        "assert_equal",
    }
)


def _is_test_path(path: str, policy: AuditPolicy) -> bool:
    """Return whether a tracked path is a recognised test owner."""
    pure = PurePosixPath(path)
    parts = set(pure.parts)
    name = pure.name.lower()
    return (
        any(root in parts for root in policy.test_roots)
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def _line_matches(text: str, expression: re.Pattern[str]) -> tuple[int, ...]:
    """Return one-based locations matching a textual rule without source content."""
    return tuple(
        number for number, line in enumerate(text.splitlines(), start=1) if expression.search(line)
    )


def _line_evidence(item: TrackedFile, line: int, *, occurrences: int = 1) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = item.text.splitlines() if item.text is not None else []
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return (
        f"file_sha256={item.content_digest}; line_sha256={line_digest}; occurrences={occurrences}"
    )


def _text_candidates(item: TrackedFile, policy: AuditPolicy) -> tuple[Candidate, ...]:
    """Collect file-level text-rule candidates."""
    if item.text is None:
        return ()
    is_test = _is_test_path(item.path, policy)
    suffix = PurePosixPath(item.path).suffix.lower()
    candidates: list[Candidate] = []
    for rule in _TEXT_RULES:
        global_rule = rule in {_COVERAGE_RULE, _LINT_RULE, _TYPE_RULE}
        rust_ignore = rule is _SKIP_RULE and suffix == ".rs"
        if not is_test and not global_rule and not rust_ignore:
            continue
        matches = _line_matches(item.text, rule.expression)
        if not matches:
            continue
        line = matches[0]
        candidates.append(
            Candidate.build(
                category="test-authenticity",
                rule_id=rule.rule_id,
                path=item.path,
                line=line,
                symbol=f"occurrences={len(matches)}",
                evidence=_line_evidence(item, line, occurrences=len(matches)),
                confidence=rule.confidence,
                rationale=rule.rationale,
                verification=rule.verification,
            )
        )
    if is_test and _BUCKET_NAME.search(PurePosixPath(item.path).name):
        candidates.append(
            Candidate.build(
                category="test-authenticity",
                rule_id="TA008-coverage-bucket-name",
                path=item.path,
                line=1,
                symbol=PurePosixPath(item.path).stem,
                evidence=PurePosixPath(item.path).name,
                confidence="high",
                rationale="The test owner name suggests a cross-module coverage bucket.",
                verification=(
                    "Map every test to one production module or one named integration contract and "
                    "split unrelated behaviours into their owning test surfaces."
                ),
            )
        )
    return tuple(candidates)


def _call_name(node: ast.expr) -> str:
    """Return the final name component of one call target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _has_behavioural_contract(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether one test body contains a local observable contract."""
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        if isinstance(child, ast.Call):
            name = _call_name(child.func)
            if name in _BEHAVIOURAL_CALLS or name.startswith(("assert_", "_assert")):
                return True
    return False


def _test_functions(tree: ast.Module) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    """Return top-level and class-owned pytest functions."""
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            functions.append(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            functions.extend(
                member
                for member in node.body
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                and member.name.startswith("test_")
            )
    return tuple(functions)


def _production_import_aliases(tree: ast.Module, packages: frozenset[str]) -> frozenset[str]:
    """Return local names bound to first-party production modules."""
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", maxsplit=1)[0] in packages:
                    aliases.add(alias.asname or alias.name.split(".", maxsplit=1)[0])
    return frozenset(aliases)


def _private_surface_nodes(
    tree: ast.Module,
    packages: frozenset[str],
) -> tuple[tuple[int, str], ...]:
    """Return private first-party import or attribute locations."""
    findings: set[tuple[int, str]] = set()
    module_aliases = _production_import_aliases(tree, packages)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module.split(".", maxsplit=1)[0] in packages:
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        findings.add((node.lineno, alias.name))
        elif (
            isinstance(node, ast.Attribute)
            and node.attr.startswith("_")
            and not node.attr.startswith("__")
            and isinstance(node.value, ast.Name)
            and node.value.id in module_aliases
        ):
            findings.add((node.lineno, f"{node.value.id}.{node.attr}"))
    return tuple(sorted(findings))


def _python_candidates(
    item: TrackedFile,
    policy: AuditPolicy,
    packages: frozenset[str],
) -> tuple[Candidate, ...]:
    """Collect AST-backed candidates from one Python test module."""
    if item.text is None or not item.path.endswith(".py") or not _is_test_path(item.path, policy):
        return ()
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError as exc:
        line = exc.lineno if exc.lineno is not None and exc.lineno > 0 else 1
        return (
            Candidate.build(
                category="test-authenticity",
                rule_id="TA009-unparseable-python-test",
                path=item.path,
                line=line,
                symbol="",
                evidence=str(exc.msg),
                confidence="high",
                rationale="An unparseable tracked test cannot be structurally audited.",
                verification="Run the supported Python parser and repair or remove stale test code.",
            ),
        )
    candidates: list[Candidate] = []
    for function in _test_functions(tree):
        if _has_behavioural_contract(function):
            continue
        candidates.append(
            Candidate.build(
                category="test-authenticity",
                rule_id="TA010-smoke-only-test",
                path=item.path,
                line=function.lineno,
                symbol=function.name,
                evidence=_line_evidence(item, function.lineno),
                confidence="medium",
                rationale="The test exposes no local assertion, exception, or behavioural helper call.",
                verification=(
                    "Identify the observable production regression this test catches and add an "
                    "explicit result, state, persistence, error, or integration contract."
                ),
            )
        )
    private_nodes = _private_surface_nodes(tree, packages)
    if private_nodes:
        line, symbol = private_nodes[0]
        candidates.append(
            Candidate.build(
                category="test-authenticity",
                rule_id="TA011-private-production-surface",
                path=item.path,
                line=line,
                symbol=f"{symbol}; occurrences={len(private_nodes)}",
                evidence=_line_evidence(item, line, occurrences=len(private_nodes)),
                confidence="high",
                rationale="The test directly reaches an underscored first-party production surface.",
                verification=(
                    "Run the behaviour through the public API, CLI, adapter, pipeline, or documented "
                    "internal contract and prove that the private call is not bypassing that boundary."
                ),
            )
        )
    return tuple(candidates)


def _infer_packages(inventory: GitInventory, policy: AuditPolicy) -> frozenset[str]:
    """Return configured or source-root-derived first-party package names."""
    if policy.production_packages:
        return frozenset(policy.production_packages)
    packages: set[str] = set()
    for item in inventory.files:
        pure = PurePosixPath(item.path)
        if len(pure.parts) >= 3 and pure.parts[0] == "src" and pure.parts[-1].endswith(".py"):
            packages.add(pure.parts[1])
    return frozenset(packages)


def scan_test_authenticity(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return test-authenticity candidates for one tracked inventory.

    Parameters
    ----------
    inventory:
        Exact Git-tracked repository inventory.
    policy:
        Repository-local roots and package configuration.

    Returns
    -------
    tuple[Candidate, ...]
        Static signals requiring production-boundary verification.

    """
    packages = _infer_packages(inventory, policy)
    candidates: list[Candidate] = []
    for item in inventory.files:
        candidates.extend(_text_candidates(item, policy))
        candidates.extend(_python_candidates(item, policy, packages))
    return tuple(candidates)
