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


def _pep695_supported() -> bool:
    """Return whether the running parser accepts PEP 695 syntax."""
    try:
        ast.parse("type Alias = int")
    except SyntaxError:
        return False
    return True


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


def test_nested_builtins_aliases_and_class_definition_timing() -> None:
    nested_aliases = """
    def function_output():
        import builtins as runtime
        runtime.print('function builtin')
    class SuiteOutput:
        import builtins
        builtins.print('class builtin')
    def shadowed():
        import builtins as runtime
        runtime = str
        runtime.print('not builtin')
    """
    class_timing = """
    class Local:
        print = str
        def method(self, value=print('default local')):
            pass
        @print('decorator local')
        def decorated(self):
            pass
    class Deleted:
        print = lambda *values: values
        print('class local')
        del print
        print('builtin after delete')
    class BuiltinDefault:
        def method(self, value=print('builtin default')):
            pass
    class BuiltinDecorator:
        @print('builtin decorator')
        def method(self):
            pass
    """

    assert _lines(nested_aliases) == (4, 7)
    assert _lines(class_timing) == (13, 15, 18)


def test_pep695_type_bindings_when_supported() -> None:
    if not _pep695_supported():
        return
    source = """
    type print = int
    print('module type alias')
    def generic[print]():
        print('function type parameter')
    class Generic[print]:
        print('class type parameter')
    def aliases():
        type print = int
        print('function type alias')
    """

    assert _lines(source) == ()


def test_builtin_module_alias_lexical_scopes() -> None:
    source = """
    import builtins as runtime
    runtime.print('module builtin')
    def global_output():
        global runtime
        runtime.print('global builtin')
    def parameter(runtime):
        runtime.print('parameter local')
    def variadic(*runtime):
        runtime.print('variadic local')
    def keywords(**runtime):
        runtime.print('keyword local')
    def comprehensions(values):
        local = [runtime.print(value) for runtime in values for value in values]
        builtin = [runtime.print(value) for value in values]
        first = [value for value in runtime.print(values)]
    class Local:
        import builtins as local_runtime
        local_runtime.print('class builtin')
    class Shadow:
        import builtins as local_runtime
        local_runtime = str
        local_runtime.print('class local')
    class Method:
        import builtins as class_runtime
        def method(self):
            class_runtime.print('not class scoped')
    class Default:
        import builtins as default_runtime
        def method(self, value=default_runtime.print('class default builtin')):
            pass
    class ModuleFallback:
        runtime.print('module alias from class suite')
    """

    assert _lines(source) == (3, 6, 15, 16, 19, 30, 33)
    assert _lines("import builtins as runtime\nruntime = str\nruntime.print('local')\n") == ()
    assert _lines(
        """
        def outer():
            import builtins as runtime
            def inner():
                nonlocal runtime
                runtime.print('nonlocal builtin module')
        """
    ) == (6,)
    if _pep695_supported():
        assert _lines("def generic[runtime]():\n    runtime.print('type parameter')\n") == ()
