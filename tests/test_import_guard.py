# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — import-syntax policy tests
"""Verify static private imports and opt-in reserved syntax are deterministic."""

from __future__ import annotations

import pytest

from rigor_foundry.import_guard import forbidden_imports

PREFIXES = ("rigor_foundry._",)


@pytest.mark.parametrize(
    "source",
    [
        "import rigor_foundry._graph",
        "import rigor_foundry._graph_extra as graph",
        "from rigor_foundry import _graph",
        "from rigor_foundry._graph import digest",
    ],
)
def test_static_private_imports_match_prefix_contract(source: str) -> None:
    """Direct, member, and from-import spellings retain exact evidence."""
    matches = forbidden_imports(source, PREFIXES, "allow")

    assert matches == (("static-prefix:rigor_foundry._", 1),)


def test_static_public_imports_and_allowed_dynamic_syntax_remain_clear() -> None:
    """The explicit allow policy does not silently enable private static imports."""
    source = "import importlib\nimport rigor_foundry.models\nimportlib.import_module('public')\n"

    assert forbidden_imports(source, PREFIXES, "allow") == ()


@pytest.mark.parametrize(
    "source",
    [
        "import builtins",
        "import importlib",
        "import importlib.util",
        "from builtins import __import__",
        "from importlib import import_module",
        "__import__('public')",
        "loader.import_module",
        "def __import__(name):\n    return name\n__import__('public')",
        "eval('public')",
        "exec('pass')",
        "compile('pass', '<test>', 'exec')",
        "runner = eval",
        "runner = runtime.exec",
        "runner = compile",
        "getattr(loader, '__import__')",
        "getattr(loader, name='import_' + 'module')",
        "getattr(runtime, 'eval')",
        "globals()['__' + 'import__']",
        "registry['import_module']",
        "registry['ex' + 'ec']",
    ],
)
def test_forbid_syntax_reports_reserved_dynamic_import_surfaces(source: str) -> None:
    """Reserved modules, names, reflection, and code-generation calls are lexical."""
    matches = forbidden_imports(source, PREFIXES, "forbid-syntax")

    assert matches
    assert all(evidence.startswith("reserved-") for evidence, _line in matches)


@pytest.mark.parametrize(
    "source",
    [
        "label = '__import__'",
        "def __import__(name):\n    return name",
        "getattr(loader, 'public')",
        "getattr(loader, name='public')",
        "getattr(loader)",
        "registry['public']",
        "registry[prefix + name]",
    ],
)
def test_forbid_syntax_ignores_comments_plain_strings_and_other_names(source: str) -> None:
    """Only reserved AST use sites violate; inert text and other names do not."""
    assert forbidden_imports(source, PREFIXES, "forbid-syntax") == ()


def test_relative_and_invalid_policy_inputs_fail_closed() -> None:
    """Package context and policy vocabulary cannot be guessed by the guard."""
    with pytest.raises(ValueError, match="relative import cannot be resolved"):
        forbidden_imports("from . import private", PREFIXES, "allow")
    with pytest.raises(ValueError, match="unsupported dynamic import policy"):
        forbidden_imports("pass", PREFIXES, "semantic")  # type: ignore[arg-type]
