# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared Python test-function ownership tests
"""Verify source-ordered pytest function discovery over parsed production input."""

from __future__ import annotations

import ast

from rigor_foundry.python_test_functions import collect_test_functions


def test_python_test_function_discovery_respects_execution_scopes() -> None:
    """Only top-level and Test-class sync/async test owners are returned."""
    tree = ast.parse(
        "def helper():\n"
        "    pass\n\n"
        "def test_top_level():\n"
        "    def test_nested():\n"
        "        pass\n\n"
        "async def test_async_top_level():\n"
        "    pass\n\n"
        "class TestClock:\n"
        "    def helper(self):\n"
        "        pass\n"
        "    def test_method(self):\n"
        "        pass\n"
        "    async def test_async_method(self):\n"
        "        pass\n\n"
        "class ClockTests:\n"
        "    def test_not_pytest_owned(self):\n"
        "        pass\n"
    )

    functions = collect_test_functions(tree)
    assert [function.name for function in functions] == [
        "test_top_level",
        "test_async_top_level",
        "test_method",
        "test_async_method",
    ]
    assert [function.lineno for function in functions] == [4, 8, 14, 16]
