# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Explicit native-owner pytest observations
"""Observe complete declared native files without weakening exhaustive shard admission."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.pytest_test_shards import (
    ShardObserver,
)
from tools.pytest_test_shards import (
    pytest_addoption as pytest_addoption,
)


def pytest_configure(config: pytest.Config) -> None:
    """Require whole explicit files and reject selection or early-success switches.

    Parameters
    ----------
    config : pytest.Config
        Actual native pytest invocation. The outer producer and consumer bind its
        complete file inventory to the admitted platform and interpreter.

    Raises
    ------
    pytest.UsageError
        The invocation is empty, selective or not one complete native partition.
    """
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
        config.getoption("test_shard_index") != 0
        or config.getoption("test_shard_count") != 1
        or not config.getoption("test_shard_observations")
        or not config.args
        or any(
            not name.startswith("tests/") or not name.endswith(".py") or not Path(name).is_file()
            for name in config.args
        )
        or any(config.getoption(name, default=None) for name in forbidden)
    ):
        raise pytest.UsageError("complete native test-file invocation required")
    config.pluginmanager.register(ShardObserver(config), "native-test-observer")
