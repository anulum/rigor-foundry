# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Python process-output lexical resolution
"""Resolve bounded Python calls that reach builtin ``print``."""

from __future__ import annotations

import ast
from collections.abc import Sequence

_Comprehension = ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
_Function = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


def bound_target_names(node: ast.expr) -> frozenset[str]:
    """Return names bound by one assignment target."""
    if isinstance(node, ast.Name):
        return frozenset({node.id})
    if isinstance(node, (ast.Tuple, ast.List)):
        return frozenset(name for item in node.elts for name in bound_target_names(item))
    return frozenset()


def _type_alias_name(node: ast.AST) -> str | None:
    """Return a PEP 695 type-alias binding without requiring Python 3.12 AST types."""
    if node.__class__.__name__ != "TypeAlias":
        return None
    name = getattr(node, "name", None)
    return name.id if isinstance(name, ast.Name) else None


def _type_parameter_names(node: ast.AST) -> frozenset[str]:
    """Return PEP 695 type-parameter names when the running parser exposes them."""
    return frozenset(str(parameter.name) for parameter in getattr(node, "type_params", ()))


def _scope_nodes(body: Sequence[ast.AST]) -> tuple[ast.AST, ...]:
    """Return nodes evaluated in one lexical scope, excluding nested scope bodies."""
    pending: list[ast.AST] = list(reversed(body))
    nodes: list[ast.AST] = []
    while pending:
        node = pending.pop()
        nodes.append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return tuple(nodes)


def _bound_names(node: ast.AST) -> frozenset[str]:
    """Return names bound by one scope-local syntax node."""
    if isinstance(node, ast.Assign):
        return frozenset(name for target in node.targets for name in bound_target_names(target))
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return bound_target_names(node.target)
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return bound_target_names(node.target)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return frozenset(
            name
            for item in node.items
            if item.optional_vars is not None
            for name in bound_target_names(item.optional_vars)
        )
    if isinstance(node, ast.ExceptHandler) and node.name is not None:
        return frozenset({node.name})
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name is not None:
        return frozenset({node.name})
    if isinstance(node, ast.MatchMapping) and node.rest is not None:
        return frozenset({node.rest})
    type_alias = _type_alias_name(node)
    if type_alias is not None:
        return frozenset({type_alias})
    if isinstance(node, ast.Delete):
        return frozenset(name for target in node.targets for name in bound_target_names(target))
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return frozenset({node.name})
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return frozenset(
            alias.asname or alias.name.split(".", maxsplit=1)[0] for alias in node.names
        )
    return frozenset()


def _function_body(function: _Function) -> Sequence[ast.AST]:
    """Return syntax evaluated in one function or lambda body."""
    return (function.body,) if isinstance(function, ast.Lambda) else function.body


def _builtin_print_aliases(body: Sequence[ast.AST]) -> frozenset[str]:
    """Return explicit names imported from ``builtins.print`` in one scope."""
    return frozenset(
        alias.asname or "print"
        for node in _scope_nodes(body)
        if isinstance(node, ast.ImportFrom) and node.module == "builtins"
        for alias in node.names
        if alias.name == "print"
    )


def _builtin_module_aliases(body: Sequence[ast.AST]) -> frozenset[str]:
    """Return explicit aliases introduced by ``import builtins`` in one scope."""
    return frozenset(
        alias.asname or "builtins"
        for node in _scope_nodes(body)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "builtins"
    )


def _module_bindings(tree: ast.Module) -> frozenset[str]:
    """Return non-builtin-print names explicitly bound at module scope."""
    aliases = _builtin_print_aliases(tree.body)
    return frozenset(
        name
        for node in _scope_nodes(tree.body)
        for name in _bound_names(node)
        if not (
            name in aliases
            and isinstance(node, ast.ImportFrom)
            and node.module == "builtins"
            and any(
                alias.name == "print" and (alias.asname or "print") == name for alias in node.names
            )
        )
    )


def _module_binds_builtin_module(tree: ast.Module, name: str) -> bool:
    """Return whether a module binding shadows one ``builtins`` module alias."""
    return any(
        name in _bound_names(node) and not _is_builtin_module_import(node, name)
        for node in _scope_nodes(tree.body)
    )


def _function_declaration(function: _Function, name: str) -> str | None:
    """Return an explicit ``global`` or ``nonlocal`` declaration for one name."""
    for node in _scope_nodes(_function_body(function)):
        if isinstance(node, ast.Global) and name in node.names:
            return "global"
        if isinstance(node, ast.Nonlocal) and name in node.names:
            return "nonlocal"
    return None


def _function_binds(function: _Function, name: str) -> bool:
    """Return whether Python resolves one name as local to the function."""
    if _function_declaration(function, name) is not None:
        return False
    if name in _type_parameter_names(function):
        return True
    arguments = (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
    if any(argument.arg == name for argument in arguments):
        return True
    if function.args.vararg is not None and function.args.vararg.arg == name:
        return True
    if function.args.kwarg is not None and function.args.kwarg.arg == name:
        return True
    aliases = _builtin_print_aliases(_function_body(function))
    return any(
        name in _bound_names(node)
        and not (
            name in aliases
            and isinstance(node, ast.ImportFrom)
            and node.module == "builtins"
            and any(
                alias.name == "print" and (alias.asname or "print") == name for alias in node.names
            )
        )
        for node in _scope_nodes(_function_body(function))
    )


def _function_binds_builtin_module(function: _Function, name: str) -> bool:
    """Return whether a function binding shadows one ``builtins`` module alias."""
    if _function_declaration(function, name) is not None:
        return False
    if name in _type_parameter_names(function):
        return True
    arguments = (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
    if any(argument.arg == name for argument in arguments):
        return True
    if function.args.vararg is not None and function.args.vararg.arg == name:
        return True
    if function.args.kwarg is not None and function.args.kwarg.arg == name:
        return True
    return any(
        name in _bound_names(node) and not _is_builtin_module_import(node, name)
        for node in _scope_nodes(_function_body(function))
    )


def _contains(node: ast.AST, owner: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Return whether ``node`` is nested under ``owner`` in the parsed tree."""
    current: ast.AST | None = node
    while current is not None:
        if current is owner:
            return True
        current = parents.get(current)
    return False


def _comprehension_bindings(
    scope: _Comprehension, node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> frozenset[str] | None:
    """Return active targets, or ``None`` in the outer iterable expression."""
    generators = scope.generators
    if _contains(node, generators[0].iter, parents):
        return None
    active = len(generators)
    for index, generator in enumerate(generators):
        if index > 0 and _contains(node, generator.iter, parents):
            active = index
            break
        if any(_contains(node, condition, parents) for condition in generator.ifs):
            active = index + 1
            break
    return frozenset(
        name for generator in generators[:active] for name in bound_target_names(generator.target)
    )


def _is_builtin_print_import(node: ast.AST, name: str) -> bool:
    """Return whether one node explicitly imports builtin ``print``."""
    return (
        isinstance(node, ast.ImportFrom)
        and node.module == "builtins"
        and any(
            alias.name == "print" and (alias.asname or "print") == name for alias in node.names
        )
    )


def _is_builtin_module_import(node: ast.AST, name: str) -> bool:
    """Return whether one node binds a name through ``import builtins``."""
    return isinstance(node, ast.Import) and any(
        alias.name == "builtins" and (alias.asname or "builtins") == name for alias in node.names
    )


def _class_binding(
    scope: ast.ClassDef, node: ast.AST, name: str, *, module_alias: bool = False
) -> bool | None:
    """Return class-suite binding state established before one call."""
    state: bool | None = False if name in _type_parameter_names(scope) else None
    position = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
    for candidate in _scope_nodes(scope.body):
        candidate_position = (
            getattr(candidate, "lineno", 0),
            getattr(candidate, "col_offset", 0),
        )
        if candidate_position >= position or name not in _bound_names(candidate):
            continue
        if isinstance(candidate, ast.Delete):
            state = None
        elif module_alias:
            state = _is_builtin_module_import(candidate, name)
        else:
            state = _is_builtin_print_import(candidate, name)
    return state


def _function_scope_active(
    scope: _Function, node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> bool:
    """Return whether a call executes inside a function body, not its definition syntax."""
    if isinstance(scope, ast.Lambda):
        return _contains(node, scope.body, parents)
    return any(_contains(node, statement, parents) for statement in scope.body)


def _name_resolves_to_builtin_print(
    name: str,
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    module_bindings: frozenset[str],
    module_aliases: frozenset[str],
) -> bool:
    """Return whether one lexical name resolves to builtin ``print``."""
    current = parents.get(node)
    class_visible = True
    while current is not None:
        if isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            bindings = _comprehension_bindings(current, node, parents)
            if bindings is not None:
                if name in bindings:
                    return False
                class_visible = False
        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if _function_scope_active(current, node, parents):
                declaration = _function_declaration(current, name)
                if declaration == "global":
                    break
                aliases = _builtin_print_aliases(_function_body(current))
                if name in aliases and not _function_binds(current, name):
                    return True
                if _function_binds(current, name):
                    return False
                class_visible = False
        elif isinstance(current, ast.ClassDef):
            if class_visible:
                binding = _class_binding(current, node, name)
                if binding is not None:
                    return binding
            class_visible = False
        current = parents.get(current)
    return (name == "print" or name in module_aliases) and name not in module_bindings


def _name_resolves_to_builtin_module(
    name: str,
    node: ast.AST,
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
    module_aliases: frozenset[str],
) -> bool:
    """Return whether one lexical name resolves to the ``builtins`` module."""
    current = parents.get(node)
    class_visible = True
    while current is not None:
        if isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            bindings = _comprehension_bindings(current, node, parents)
            if bindings is not None:
                if name in bindings:
                    return False
                class_visible = False
        elif isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if _function_scope_active(current, node, parents):
                declaration = _function_declaration(current, name)
                if declaration == "global":
                    break
                aliases = _builtin_module_aliases(_function_body(current))
                if name in aliases and not _function_binds_builtin_module(current, name):
                    return True
                if _function_binds_builtin_module(current, name):
                    return False
                class_visible = False
        elif isinstance(current, ast.ClassDef):
            if class_visible:
                binding = _class_binding(current, node, name, module_alias=True)
                if binding is not None:
                    return binding
            class_visible = False
        current = parents.get(current)
    return name in module_aliases and not _module_binds_builtin_module(tree, name)


def print_lines(tree: ast.Module) -> tuple[int, ...]:
    """Return calls that resolve to builtin print rather than a lexical binding."""
    module_bindings = _module_bindings(tree)
    module_aliases = _builtin_print_aliases(tree.body)
    builtins_aliases = _builtin_module_aliases(tree.body)
    parents = {
        child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and _name_resolves_to_builtin_module(
                node.func.value.id, node, tree, parents, builtins_aliases
            )
            and node.func.attr == "print"
        ):
            lines.add(node.lineno)
            continue
        if isinstance(node.func, ast.Name) and _name_resolves_to_builtin_print(
            node.func.id, node, parents, module_bindings, module_aliases
        ):
            lines.add(node.lineno)
    return tuple(sorted(lines))
