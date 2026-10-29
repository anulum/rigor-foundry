# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Actual balanced collection qualification
"""Exercise complete warm schedules through real terminal shard processes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_run_test_shard import (
    FIXTURE_TESTS,
    execute_shard,
    shard_environment,
    shard_repository,
)

from tools.run_test_shard import pytest_command
from tools.test_shard_evidence import read_record, source_identity, validate_receipt
from tools.test_shard_schedule import (
    COLD_STRATEGY,
    MAX_TIMINGS_BYTES,
    TIMINGS_PATH,
    WARM_STRATEGY,
    partition,
    read_timings,
    validate_timings,
)


def timing_repository(destination: Path) -> Path:
    """Create real executable modules with parameterized subprocess dispatch.

    Parameters
    ----------
    destination : Path
        Independent infrastructure qualification repository.

    Returns
    -------
    Path
        Real collection with an unseen module and a stale timing hint.
    """
    root = shard_repository(destination)
    (root / "tests/test_dispatch.py").unlink()
    for index in range(8):
        (root / f"tests/test_dispatch_{index}.py").write_text(FIXTURE_TESTS)
    path = root / TIMINGS_PATH
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "durations": {
                    **{f"tests/test_dispatch_{index}.py": index + 1 for index in range(7)},
                    "tests/test_deleted.py": 100,
                },
            }
        )
    )
    return root


def test_real_warm_shards_are_complete_disjoint_and_bind_one_profile(tmp_path: Path) -> None:
    """Run every partition and reject a changed profile before union admission.

    Parameters
    ----------
    tmp_path : Path
        Actual independent source and retained artifacts.
    """
    root = timing_repository(tmp_path)
    original = source_identity(root, shard_environment(root, WARM_STRATEGY))
    directory_root = root / "test-shards"
    directory_root.mkdir()
    seen: list[str] = []
    for index in range(8):
        completed = execute_shard(root, index, 8, WARM_STRATEGY)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        directory = root / ".rigor-test-shard"
        observed = read_record(directory / "observations.json")
        assert observed["timings"] == read_timings(root)
        assert len({node.split("::")[0] for node in observed["selected"]}) == 1
        assert len(observed["selected"]) == 4
        assert (
            observed["selected"] == partition(observed["collected"], 8, read_timings(root))[index]
        )
        validate_receipt(directory, original, index, 8, pytest_command(index, 8))
        seen.extend(observed["selected"])
        directory.rename(directory_root / f"shard-{index}")
    assert len(seen) == len(set(seen)) == 32
    assert any("test_dispatch_7.py::" in node for node in seen)
    assert all("test_deleted.py" not in node for node in seen)
    receipt_path = directory_root / "shard-0/receipt.json"
    original_receipt = receipt_path.read_bytes()
    for field, value in (
        ("strategy", COLD_STRATEGY),
        ("schedule", "{}"),
        ("run_attempt", "3"),
        ("python", "0.0.0"),
    ):
        receipt = json.loads(original_receipt)
        receipt["identity"][field] = value
        receipt_path.write_text(json.dumps(receipt))
        refused = subprocess.run(
            [
                sys.executable,
                "-m",
                "tools.combine_test_shards",
                "--directory",
                str(directory_root),
                "--count",
                "8",
            ],
            cwd=root,
            env=shard_environment(root, WARM_STRATEGY),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert refused.returncode != 0, refused.stdout + refused.stderr
        assert not (root / ".coverage").exists()
        receipt_path.write_bytes(original_receipt)
    combined = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.combine_test_shards",
            "--directory",
            str(directory_root),
            "--count",
            "8",
        ],
        cwd=root,
        env=shard_environment(root, WARM_STRATEGY),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert combined.returncode == 0, combined.stdout + combined.stderr
    assert (root / "coverage.xml").is_file()
    retained = directory_root / "shard-0"
    observed = read_record(retained / "observations.json")
    observed["timings"] = {}
    (retained / "observations.json").write_text(json.dumps(observed))
    with pytest.raises(ValueError):
        validate_receipt(retained, original, 0, 8, pytest_command(0, 8))
    observed["timings"] = read_timings(root)
    observed["strategy"] = COLD_STRATEGY
    (retained / "observations.json").write_text(json.dumps(observed))
    with pytest.raises(ValueError):
        validate_receipt(retained, original, 0, 8, pytest_command(0, 8))
    profile = root / TIMINGS_PATH
    profile.write_text('{"schema_version":1,"durations":{"tests/test_dispatch_0.py":99}}')
    changed = source_identity(root, shard_environment(root, WARM_STRATEGY))
    assert changed != original
    with pytest.raises(ValueError):
        validate_receipt(retained, changed, 0, 8, pytest_command(0, 8))
    assert sorted(partition(seen, 8, read_timings(root))[0]) == sorted(
        partition(list(reversed(seen)), 8, read_timings(root))[0]
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b"{}",
        b'{"schema_version":true,"durations":{}}',
        b'{"schema_version":2,"durations":{}}',
        b'{"schema_version":1,"schema_version":1,"durations":{}}',
        b'{"schema_version":1,"durations":[]}',
        b'{"schema_version":1,"durations":{}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":0}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":-1}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":true}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":"slow"}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":NaN}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":Infinity}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":86401}}',
        b'{"schema_version":1,"durations":{"../test_a.py":1}}',
        b'{"schema_version":1,"durations":{"tests/test_a.py":1,"tests/test_a.py":2}}',
        json.dumps(
            {"schema_version": 1, "durations": {"tests/test_" + "a" * 512 + ".py": 1}}
        ).encode(),
    ],
)
def test_actual_profile_parser_refuses_ambiguous_or_invalid_hints(
    tmp_path: Path, raw: bytes
) -> None:
    """Malformed advisory data cannot silently change the execution schedule.

    Parameters
    ----------
    tmp_path : Path
        Actual independent profile directory.
    raw : bytes
        Invalid file content.
    """
    path = tmp_path / TIMINGS_PATH
    path.parent.mkdir()
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        read_timings(tmp_path)


@pytest.mark.parametrize(
    "kind", ["absent", "directory", "link", "dangling-link", "oversize", "entries"]
)
def test_actual_profile_filesystem_and_entry_bounds_refuse(tmp_path: Path, kind: str) -> None:
    """Use real filesystem objects and complete oversized timing maps.

    Parameters
    ----------
    tmp_path : Path
        Actual independent profile directory.
    kind : str
        Nonregular or over-budget input.
    """
    path = tmp_path / TIMINGS_PATH
    path.parent.mkdir()
    if kind == "absent":
        assert not path.exists()
    elif kind == "directory":
        path.mkdir()
    elif kind in {"link", "dangling-link"}:
        target = tmp_path / "target"
        if kind == "link":
            target.write_text("{}")
        path.symlink_to(target)
    elif kind == "oversize":
        with path.open("wb") as stream:
            stream.truncate(MAX_TIMINGS_BYTES + 1)
    else:
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "durations": {f"tests/test_{index}.py": 1 for index in range(10_001)},
                }
            )
        )
    with pytest.raises(ValueError):
        read_timings(tmp_path)


def test_actual_profile_requires_one_explicit_versioned_strategy(tmp_path: Path) -> None:
    """Refuse mixed modes and invalid public inputs from a real parsed snapshot.

    Parameters
    ----------
    tmp_path : Path
        Actual independent profile and executable collection.
    """
    root = timing_repository(tmp_path)
    timings = read_timings(root)
    with pytest.raises(ValueError):
        read_timings(root, COLD_STRATEGY)
    with pytest.raises(ValueError):
        read_timings(root, "unknown-v1")
    with pytest.raises(ValueError):
        validate_timings({1: next(iter(timings.values()))})
    completed = execute_shard(root, count=8, strategy=WARM_STRATEGY)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    collected = read_record(root / ".rigor-test-shard/observations.json")["collected"]
    with pytest.raises(ValueError):
        partition(collected, 8, timings, COLD_STRATEGY)
    with pytest.raises(ValueError):
        partition(collected, 8, {}, "unknown-v1")
    (root / TIMINGS_PATH).unlink()
    assert read_timings(root, COLD_STRATEGY) == {}
    assert partition(collected, 8, {}, COLD_STRATEGY) == [
        collected[index::8] for index in range(8)
    ]


@pytest.mark.parametrize(("history", "expected"), [("weighted", {0, 6}), ("ties", {0, 4})])
def test_actual_warm_schedule_balances_costs_and_breaks_ties(
    tmp_path: Path, history: str, expected: set[int]
) -> None:
    """Check independently calculated owners through the real terminal launcher.

    Parameters
    ----------
    tmp_path : Path
        Actual independent eight-module collection.
    history : str
        Unequal history with a median-priced unseen module, or exact ties.
    expected : set[int]
        Module indices assigned to shard zero by the declared algorithm.
    """
    root = timing_repository(tmp_path)
    if history == "ties":
        (root / TIMINGS_PATH).write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "durations": {
                        f"tests/test_dispatch_{index}.py": 0.0000001 for index in range(8)
                    },
                }
            )
        )
    completed = execute_shard(root, count=4, strategy=WARM_STRATEGY)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    observed = read_record(root / ".rigor-test-shard/observations.json")
    assert {node.split("::")[0] for node in observed["selected"]} == {
        f"tests/test_dispatch_{index}.py" for index in expected
    }


@pytest.mark.parametrize("hook", ["finish", "late-registered-wrapper"])
def test_real_warm_schedule_waits_for_the_entire_collection_chain(
    tmp_path: Path, hook: str
) -> None:
    """Keep original parameter order after late hooks change the final collection.

    Parameters
    ----------
    tmp_path : Path
        Actual independent parameterized modules.
    hook : str
        Collection-finish hook or later-registered collection wrapper.
    """
    root = timing_repository(tmp_path)
    reverse = (
        "        session.items.reverse()\n"
        '        Path("final-items.json").write_text(json.dumps([item.nodeid for item in session.items]))\n'
    )
    if hook == "finish":
        body = "def pytest_collection_finish(session):\n" + reverse
    else:
        body = (
            "class LateWrapper:\n"
            "    @pytest.hookimpl(wrapper=True, tryfirst=True)\n"
            "    def pytest_collection(self, session):\n"
            "        result = yield\n" + reverse + "        return result\n"
            "@pytest.hookimpl(trylast=True)\n"
            "def pytest_configure(config):\n"
            '    config.pluginmanager.register(LateWrapper(), "late-wrapper")\n'
        )
    (root / "conftest.py").write_text("import json, pytest\nfrom pathlib import Path\n" + body)
    completed = execute_shard(root, count=8, strategy=WARM_STRATEGY)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    observed = read_record(root / ".rigor-test-shard/observations.json")
    assert observed["collected"] == json.loads((root / "final-items.json").read_text())
    assert observed["selected"][0].endswith("[version1]")
    assert observed["selected"][-1].endswith("[version0]")


@pytest.mark.parametrize("count", [0, -1, True])
def test_collected_public_schedule_refuses_invalid_counts(tmp_path: Path, count: int) -> None:
    """Reject invalid partition cardinality using an actual completed collection.

    Parameters
    ----------
    tmp_path : Path
        Actual independent execution repository.
    count : int
        Invalid partition count.
    """
    root = shard_repository(tmp_path)
    completed = execute_shard(root, count=1)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    collected = read_record(root / ".rigor-test-shard/observations.json")["collected"]
    with pytest.raises(ValueError):
        partition(collected, count, {})


@pytest.mark.parametrize("mutation", ["observations", "source"])
def test_actual_finalisation_cannot_switch_the_shared_schedule(
    tmp_path: Path, mutation: str
) -> None:
    """Refuse real post-execution changes before publishing successful evidence.

    Parameters
    ----------
    tmp_path : Path
        Actual independent executable repository.
    mutation : str
        Changed retained observations or checkout profile.
    """
    root = timing_repository(tmp_path)
    body = {
        "observations": (
            '    path = Path(".rigor-test-shard/observations.json")\n'
            "    record = json.loads(path.read_text())\n"
            '    record["timings"] = {}\n'
            "    path.write_text(json.dumps(record))\n"
        ),
        "source": (
            '    Path(".github/test-timings.json").write_text('
            '\'{"schema_version":1,"durations":{}}\')\n'
        ),
    }[mutation]
    (root / "conftest.py").write_text(
        "import json, pytest\nfrom pathlib import Path\n"
        "@pytest.hookimpl(wrapper=True, tryfirst=True)\n"
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    result = yield\n" + body + "    return result\n"
    )
    completed = execute_shard(root, count=8, strategy=WARM_STRATEGY)
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert not (root / ".rigor-test-shard/receipt.json").exists()
