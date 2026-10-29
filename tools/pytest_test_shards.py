# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Final pytest collection partitioning
"""Partition actual collected items and retain provisional execution observations."""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path

import pytest


class ShardObserver:
    """Observe one explicit invocation without changing nested pytest commands.

    Parameters
    ----------
    config : pytest.Config
        Invocation containing explicit index, count and provisional output.
    """

    def __init__(self, config: pytest.Config) -> None:
        self.index = int(config.getoption("test_shard_index"))
        self.count = int(config.getoption("test_shard_count"))
        self.output = Path(config.getoption("test_shard_observations"))
        self.collected: list[str] = []
        self.selected: list[str] = []
        self.phases: dict[str, list[list[str]]] = {}

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_runtestloop(self, session: pytest.Session) -> Generator[None, object, object]:
        """Select final collected items before delegating actual test execution.

        Parameters
        ----------
        session : pytest.Session
            Actual session whose final item objects retain their fixture context.

        Yields
        ------
        None
            Delegate the ordinary runtime loop after the entire collection chain.

        Returns
        -------
        object
            Unmodified runtime hook result.

        Raises
        ------
        pytest.UsageError
            Collection identities or the selected partition are incomplete.
        """
        self.collected = [item.nodeid for item in session.items]
        if len(set(self.collected)) != len(self.collected):
            raise pytest.UsageError("duplicate collected test identity")
        session.items[:] = session.items[self.index :: self.count]
        self.selected = [item.nodeid for item in session.items]
        session.testscollected = len(session.items)
        if not self.selected:
            raise pytest.UsageError("empty test shard")
        result = yield
        return result

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """Retain every real setup, call and teardown outcome in arrival order.

        Parameters
        ----------
        report : pytest.TestReport
            Actual pytest phase report, including existing skip/xfail outcomes.
        """
        self.phases.setdefault(report.nodeid, []).append([report.when, report.outcome])

    def pytest_sessionfinish(self, exitstatus: int) -> None:
        """Save provisional observations; the external launcher owns success.

        Parameters
        ----------
        exitstatus : int
            Pytest's current status, before later finalisation can still fail.
        """
        self.output.write_text(
            json.dumps(
                {
                    "index": self.index,
                    "count": self.count,
                    "collected": self.collected,
                    "selected": self.selected,
                    "phases": self.phases,
                    "exitstatus": int(exitstatus),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register command-local partition arguments.

    Parameters
    ----------
    parser : pytest.Parser
        Actual pytest argument parser.
    """
    group = parser.getgroup("complete test shards")
    group.addoption("--test-shard-index", type=int)
    group.addoption("--test-shard-count", type=int)
    group.addoption("--test-shard-observations")


def pytest_configure(config: pytest.Config) -> None:
    """Refuse selective or early-success invocations before partitioning.

    Parameters
    ----------
    config : pytest.Config
        Parsed actual invocation and repository configuration.

    Raises
    ------
    pytest.UsageError
        Required arguments are missing or any admission filter is active.
    """
    index = config.getoption("test_shard_index")
    count = config.getoption("test_shard_count")
    output = config.getoption("test_shard_observations")
    forbidden = (
        "collectonly",
        "maxfail",
        "keyword",
        "markexpr",
        "lf",
        "failedfirst",
        "newfirst",
        "stepwise",
        "deselect",
        "ignore",
        "ignore_glob",
        "pyargs",
        "keepduplicates",
    )
    if (
        type(index) is not int
        or type(count) is not int
        or not 0 <= index < count
        or not output
        or config.args != ["tests"]
        or any(config.getoption(name, default=None) for name in forbidden)
    ):
        raise pytest.UsageError("complete test shard invocation required")
    config.pluginmanager.register(ShardObserver(config), "complete-test-shard-observer")
