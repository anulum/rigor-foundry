# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — performance and reproducibility candidate scanner
"""Collect bounded wall-clock use in Python test assertions."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Literal

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .language_capabilities import is_test_path
from .models import AuditPolicy, Candidate
from .python_test_functions import collect_test_functions

_Semantic = Literal[
    "time-module",
    "time-function",
    "datetime-module",
    "datetime-class",
    "freezegun-module",
    "freeze-function",
    "time-machine-module",
    "travel-function",
]
_ClockSource = Literal["time-module", "time-direct", "datetime-module", "datetime-direct"]
_ALL_CLOCK_SOURCES: frozenset[_ClockSource] = frozenset(
    {"time-module", "time-direct", "datetime-module", "datetime-direct"}
)


@dataclass(frozen=True)
class _Aliases:
    """Unambiguously imported names used by one test function."""

    time_modules: frozenset[str]
    time_functions: frozenset[str]
    datetime_modules: frozenset[str]
    datetime_classes: frozenset[str]
    freezegun_modules: frozenset[str]
    freeze_functions: frozenset[str]
    time_machine_modules: frozenset[str]
    travel_functions: frozenset[str]


@dataclass(frozen=True)
class _SuiteScan:
    """Findings and surviving monkeypatch controls after one statement suite."""

    findings: tuple[tuple[int, _ClockSource], ...]
    patch_controls: frozenset[_ClockSource]


class _ScopeBindings(ast.NodeVisitor):
    """Collect imports and conservative same-scope shadowing."""

    def __init__(self) -> None:
        self.imports: dict[str, set[_Semantic]] = {}
        self.other: set[str] = set()

    def _import(self, name: str, semantic: _Semantic) -> None:
        self.imports.setdefault(name, set()).add(semantic)

    def visit_Import(self, node: ast.Import) -> None:
        """Record supported module imports."""
        supported: dict[str, _Semantic] = {
            "time": "time-module",
            "datetime": "datetime-module",
            "freezegun": "freezegun-module",
            "time_machine": "time-machine-module",
        }
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            semantic = supported.get(alias.name)
            if semantic is not None:
                self._import(local, semantic)
            else:
                self.other.add(local)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record supported direct imports."""
        supported: dict[tuple[str | None, str], _Semantic] = {
            ("time", "time"): "time-function",
            ("datetime", "datetime"): "datetime-class",
            ("freezegun", "freeze_time"): "freeze-function",
            ("time_machine", "travel"): "travel-function",
        }
        for alias in node.names:
            local = alias.asname or alias.name
            semantic = supported.get((node.module, alias.name))
            if semantic is not None:
                self._import(local, semantic)
            else:
                self.other.add(local)

    def visit_Name(self, node: ast.Name) -> None:
        """Record non-import name bindings in the current scope."""
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.other.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Treat a nested function name as a binding without entering its scope."""
        self.other.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Treat a nested async-function name as a binding without entering its scope."""
        self.other.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Treat a nested class name as a binding without entering its scope."""
        self.other.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Do not mix lambda-local bindings into the containing scope."""

    def visit_Global(self, node: ast.Global) -> None:
        """Reject names whose binding is explicitly redirected to module scope."""
        self.other.update(node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Record exception-target bindings before visiting the handler body."""
        if node.name is not None:
            self.other.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        """Record structural-pattern capture names."""
        if node.name is not None:
            self.other.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        """Record starred structural-pattern capture names."""
        if node.name is not None:
            self.other.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        """Record mapping-rest capture names."""
        if node.rest is not None:
            self.other.add(node.rest)
        self.generic_visit(node)


class _ClockCalls(ast.NodeVisitor):
    """Collect supported clock calls from one assertion expression."""

    def __init__(self, aliases: _Aliases) -> None:
        self.aliases = aliases
        self.calls: list[tuple[int, _ClockSource]] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Record one imported wall-clock call and inspect its arguments."""
        source = _clock_source(node, self.aliases)
        if source is not None:
            self.calls.append((node.lineno, source))
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Ignore deferred lambda bodies that an assertion may only retain."""


def _scope_bindings(statements: list[ast.stmt]) -> _ScopeBindings:
    """Return import and shadowing evidence for one lexical statement suite."""
    collector = _ScopeBindings()
    for statement in statements:
        collector.visit(statement)
    return collector


def _parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Return every parameter name bound by one test function."""
    arguments = function.args
    names = {
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return frozenset(names)


def _resolved_imports(
    module_bindings: _ScopeBindings,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, _Semantic]:
    """Resolve only import names with no competing same-scope binding."""
    local = _scope_bindings(function.body)
    local.other.update(_parameters(function))
    local_names = local.other | set(local.imports)
    resolved: dict[str, _Semantic] = {}
    for name, semantics in module_bindings.imports.items():
        if name not in module_bindings.other and name not in local_names and len(semantics) == 1:
            resolved[name] = next(iter(semantics))
    for name, semantics in local.imports.items():
        if name not in local.other and len(semantics) == 1:
            resolved[name] = next(iter(semantics))
    return resolved


def _aliases(
    module_bindings: _ScopeBindings,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> _Aliases:
    """Build the supported alias sets for one test function."""
    resolved = _resolved_imports(module_bindings, function)

    def names(semantic: _Semantic) -> frozenset[str]:
        return frozenset(name for name, value in resolved.items() if value == semantic)

    return _Aliases(
        time_modules=names("time-module"),
        time_functions=names("time-function"),
        datetime_modules=names("datetime-module"),
        datetime_classes=names("datetime-class"),
        freezegun_modules=names("freezegun-module"),
        freeze_functions=names("freeze-function"),
        time_machine_modules=names("time-machine-module"),
        travel_functions=names("travel-function"),
    )


def _clock_source(call: ast.Call, aliases: _Aliases) -> _ClockSource | None:
    """Return the imported wall-clock binding used by one call."""
    function = call.func
    if isinstance(function, ast.Name) and function.id in aliases.time_functions:
        return "time-direct"
    if not isinstance(function, ast.Attribute):
        return None
    if (
        function.attr == "time"
        and isinstance(function.value, ast.Name)
        and function.value.id in aliases.time_modules
    ):
        return "time-module"
    if function.attr != "now":
        return None
    receiver = function.value
    if isinstance(receiver, ast.Name) and receiver.id in aliases.datetime_classes:
        return "datetime-direct"
    if (
        isinstance(receiver, ast.Attribute)
        and receiver.attr == "datetime"
        and isinstance(receiver.value, ast.Name)
        and receiver.value.id in aliases.datetime_modules
    ):
        return "datetime-module"
    return None


def _freeze_callable(expression: ast.expr, aliases: _Aliases) -> bool:
    """Return whether an expression resolves to a supported freeze API."""
    if not isinstance(expression, ast.Call):
        return False
    expression = expression.func
    if isinstance(expression, ast.Name):
        return expression.id in aliases.freeze_functions | aliases.travel_functions
    return (
        isinstance(expression, ast.Attribute)
        and isinstance(expression.value, ast.Name)
        and (
            (expression.value.id in aliases.freezegun_modules and expression.attr == "freeze_time")
            or (
                expression.value.id in aliases.time_machine_modules and expression.attr == "travel"
            )
        )
    )


def _monkeypatch_controls(
    call: ast.Call,
    aliases: _Aliases,
    *,
    fixture_available: bool,
) -> frozenset[_ClockSource]:
    """Return clock bindings controlled by one exact ``monkeypatch.setattr`` call."""
    function = call.func
    if not (
        fixture_available
        and isinstance(function, ast.Attribute)
        and function.attr == "setattr"
        and isinstance(function.value, ast.Name)
        and function.value.id == "monkeypatch"
        and call.args
    ):
        return frozenset()
    target = call.args[0]
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        if len(call.args) < 2:
            return frozenset()
        if target.value == "time.time":
            return frozenset({"time-module"})
        if target.value == "datetime.datetime":
            return frozenset({"datetime-module"})
        return frozenset()
    if len(call.args) < 3:
        return frozenset()
    name = call.args[1]
    if not (isinstance(name, ast.Constant) and isinstance(name.value, str)):
        return frozenset()
    attribute = name.value
    if isinstance(target, ast.Name):
        if target.id in aliases.time_modules and attribute == "time":
            return frozenset({"time-module"})
        if target.id in aliases.datetime_modules and attribute == "datetime":
            return frozenset({"datetime-module"})
    return frozenset()


def _monkeypatch_undo(call: ast.Call, *, fixture_available: bool) -> bool:
    """Return whether one call explicitly restores all monkeypatch changes."""
    function = call.func
    return (
        fixture_available
        and isinstance(function, ast.Attribute)
        and function.attr == "undo"
        and isinstance(function.value, ast.Name)
        and function.value.id == "monkeypatch"
    )


def _statement_call(statement: ast.stmt) -> ast.Call | None:
    """Return a direct call evaluated by one straight-line statement."""
    value: ast.expr | None = None
    if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)):
        value = statement.value
    return value if isinstance(value, ast.Call) else None


def _assertion_calls(node: ast.Assert, aliases: _Aliases) -> tuple[tuple[int, _ClockSource], ...]:
    """Return supported clock calls evaluated by one assertion condition."""
    visitor = _ClockCalls(aliases)
    visitor.visit(node.test)
    return tuple(visitor.calls)


def _scan_suite(
    statements: list[ast.stmt],
    aliases: _Aliases,
    fixed_controls: frozenset[_ClockSource],
    *,
    patch_controls: frozenset[_ClockSource] = frozenset(),
    monkeypatch_available: bool,
) -> _SuiteScan:
    """Scan one suite and retain deterministic straight-line patch state."""
    findings: list[tuple[int, _ClockSource]] = []
    current_patches = set(patch_controls)

    def nested(
        suite: list[ast.stmt],
        nested_fixed_controls: frozenset[_ClockSource],
        nested_patch_controls: frozenset[_ClockSource],
    ) -> _SuiteScan:
        return _scan_suite(
            suite,
            aliases,
            nested_fixed_controls,
            patch_controls=nested_patch_controls,
            monkeypatch_available=monkeypatch_available,
        )

    for statement in statements:
        call = _statement_call(statement)
        if call is not None:
            if _monkeypatch_undo(
                call,
                fixture_available=monkeypatch_available,
            ):
                current_patches.clear()
            else:
                current_patches.update(
                    _monkeypatch_controls(
                        call,
                        aliases,
                        fixture_available=monkeypatch_available,
                    )
                )
            continue
        controls = fixed_controls | current_patches
        inherited_patches = frozenset(current_patches)

        if isinstance(statement, ast.Assert):
            findings.extend(
                (line, source)
                for line, source in _assertion_calls(statement, aliases)
                if source not in controls
            )
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            frozen = any(_freeze_callable(item.context_expr, aliases) for item in statement.items)
            nested_fixed = _ALL_CLOCK_SOURCES if frozen else fixed_controls
            findings.extend(nested(statement.body, nested_fixed, inherited_patches).findings)
        elif isinstance(statement, ast.If):
            body = nested(statement.body, fixed_controls, inherited_patches)
            orelse = nested(statement.orelse, fixed_controls, inherited_patches)
            findings.extend(body.findings)
            findings.extend(orelse.findings)
            current_patches = set(body.patch_controls & orelse.patch_controls)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body = nested(statement.body, fixed_controls, inherited_patches)
            orelse = nested(statement.orelse, fixed_controls, inherited_patches)
            findings.extend(body.findings)
            findings.extend(orelse.findings)
            current_patches.intersection_update(body.patch_controls, orelse.patch_controls)
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            findings.extend(nested(statement.body, fixed_controls, inherited_patches).findings)
            for handler in statement.handlers:
                findings.extend(nested(handler.body, fixed_controls, inherited_patches).findings)
            findings.extend(nested(statement.orelse, fixed_controls, inherited_patches).findings)
            finalbody = nested(statement.finalbody, fixed_controls, inherited_patches)
            findings.extend(finalbody.findings)
            current_patches = set(finalbody.patch_controls)
        elif isinstance(statement, ast.Match):
            case_controls: list[frozenset[_ClockSource]] = []
            for case in statement.cases:
                result = nested(case.body, fixed_controls, inherited_patches)
                findings.extend(result.findings)
                case_controls.append(result.patch_controls)
            current_patches.intersection_update(*case_controls)
    return _SuiteScan(tuple(findings), frozenset(current_patches))


def _line_evidence(
    item: TrackedFile, line: int, findings: tuple[tuple[int, _ClockSource], ...]
) -> str:
    """Return exact line identity and bounded clock-source metadata."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    apis = sorted(
        {"time.time" if source.startswith("time-") else "datetime.now" for _, source in findings}
    )
    return (
        f"file_sha256={item.content_digest}; line_sha256={digest}; "
        f"clock_apis={','.join(apis)}; occurrences={len(findings)}"
    )


def _file_candidates(item: TrackedFile, policy: AuditPolicy) -> tuple[Candidate, ...]:
    """Collect wall-clock assertion candidates from one tracked Python test."""
    if (
        item.text is None
        or not item.path.endswith(".py")
        or not is_test_path(item.path, policy.test_roots)
    ):
        return ()
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError:
        return ()
    module_bindings = _scope_bindings(tree.body)
    candidates: list[Candidate] = []
    for function in collect_test_functions(tree):
        aliases = _aliases(module_bindings, function)
        parameters = _parameters(function)
        local_bindings = _scope_bindings(function.body)
        frozen = (
            "freezer" in parameters
            and "freezer" not in local_bindings.other
            and "freezer" not in local_bindings.imports
        ) or any(_freeze_callable(decorator, aliases) for decorator in function.decorator_list)
        monkeypatch_available = (
            "monkeypatch" in parameters
            and "monkeypatch" not in local_bindings.other
            and "monkeypatch" not in local_bindings.imports
        )
        findings = tuple(
            sorted(
                _scan_suite(
                    function.body,
                    aliases,
                    _ALL_CLOCK_SOURCES if frozen else frozenset(),
                    monkeypatch_available=monkeypatch_available,
                ).findings
            )
        )
        if not findings:
            continue
        line = findings[0][0]
        candidates.append(
            Candidate.build(
                category="performance",
                rule_id="PR001-wall-clock-in-test",
                anchor=TrackedBlobAnchor.build(item, line_start=line),
                symbol=function.name,
                evidence=_line_evidence(item, line, findings),
                confidence="high",
                rationale=(
                    "A test assertion reads a process wall clock without a recognised local "
                    "freeze or dominating monkeypatch, so scheduling and clock movement can "
                    "change its result."
                ),
                verification=(
                    "Inject or freeze the clock at the assertion boundary, then replay the test "
                    "with the exact controlled timestamp; retain a live-clock assertion only "
                    "with bounded timing evidence and an explicit review."
                ),
            )
        )
    return tuple(candidates)


def scan_performance(inventory: GitInventory, policy: AuditPolicy) -> tuple[Candidate, ...]:
    """Return bounded performance/reproducibility review candidates."""
    return tuple(
        candidate for item in inventory.files for candidate in _file_candidates(item, policy)
    )
