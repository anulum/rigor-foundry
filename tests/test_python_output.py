# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Python process-output lexical resolution tests
"""Verify direct OP001 lexical-resolution boundaries."""

from __future__ import annotations

import ast
import textwrap

from rigor_foundry.python_output import print_lines


def _lines(source: str) -> tuple[int, ...]:
    """Return flagged lines for one dedented Python source fixture."""
    return print_lines(ast.parse(textwrap.dedent(source)))


def test_class_and_comprehension_execution_scopes() -> None:
    source = """
    class Local:
        print = lambda *values: values
        print('class local')
    class Direct:
        print('class builtin')
    class Methods:
        print = lambda *values: values
        def method(self):
            print('method builtin')
    def comprehensions(values):
        local = [print(value) for print in [str] for value in values]
        staged = [value for print in [lambda: values] for value in print()]
        early = [value for value in values if print(value) for print in [str]]
        builtin = [print(value) for value in values]
    """

    assert _lines(source) == (6, 10, 14, 15)


def test_function_closure_lambda_and_pattern_bindings() -> None:
    source = """
    from builtins import print as output
    output('explicit builtin')
    def outer():
        print = lambda value: value
        def inner():
            print('closure local')
        return lambda: print('lambda closure local')
    def captures(value):
        match value:
            case [print]:
                print('pattern local')
    def global_output():
        global print
        print('global builtin')
    """

    assert _lines(source) == (3, 15)
