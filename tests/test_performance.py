# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — performance and reproducibility scanner tests
"""Verify bounded wall-clock assertion candidates in real Git repositories."""

from __future__ import annotations

from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.performance import scan_performance
from rigor_foundry.scanner import scan_repository

_PYTEST_PATCH = "monkey" + "patch"


def test_public_scan_finds_import_bound_wall_clocks_in_assertions(tmp_path: Path) -> None:
    """The public scanner emits one digest-only PR001 candidate per test function."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_clock.py",
        "import datetime as chronology\n"
        "import time as clock\n"
        "from datetime import datetime as Moment\n"
        "from time import time as wall_time\n\n"
        "def test_module_time():\n"
        "    before = clock.time()\n"
        "    assert clock.time() >= before\n\n"
        "def test_module_datetime():\n"
        "    assert chronology.datetime.now().year >= 2020\n\n"
        "def test_direct_calls():\n"
        "    assert wall_time() > 0 and Moment.now().year >= 2020\n\n"
        "class TestAsyncClock:\n"
        "    async def test_clock(self):\n"
        "        assert clock.time() > 0\n",
    )
    repository.write_policy(required_domains=frozenset({"performance-and-reproducibility"}))
    repository.commit()

    report = scan_repository(repository.root)
    candidates = tuple(item for item in report.candidates if item.rule_id.startswith("PR"))
    assert [item.symbol for item in candidates] == [
        "test_module_time",
        "test_module_datetime",
        "test_direct_calls",
        "test_clock",
    ]
    first = candidates[0]
    assert first.category == "performance"
    assert first.confidence == "high"
    assert isinstance(first.anchor, TrackedBlobAnchor)
    assert first.anchor.line_start == 8
    assert "clock_apis=time.time" in first.evidence
    assert "occurrences=1" in first.evidence
    assert "clock.time" not in first.evidence
    assert Candidate.from_dict(first.to_dict()) == first
    direct = candidates[2]
    assert "clock_apis=datetime.now,time.time" in direct.evidence
    assert "occurrences=2" in direct.evidence
    assert not any(
        item.rule_id == "GV004-uncontrolled-required-domain"
        and item.symbol == "performance-and-reproducibility"
        for item in report.candidates
    )


def test_freezes_and_exact_dominating_patch_fixture_suppress_candidates(
    tmp_path: Path,
) -> None:
    """Recognised local clock controls suppress only the bindings they govern."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_controlled_clock.py",
        "import datetime as chronology\n"
        "import freezegun as frozen\n"
        "import time as clock\n"
        "import time_machine as machine\n"
        "from datetime import datetime as Moment\n"
        "from freezegun import freeze_time as freeze\n"
        "from time import time as wall_time\n"
        "from time_machine import travel\n\n"
        "class FrozenMoment:\n"
        "    @classmethod\n"
        "    def now(cls):\n"
        "        return cls()\n\n"
        "@freeze('2026-01-01')\n"
        "def test_decorated():\n"
        "    assert clock.time() > 0 and Moment.now() is not None\n\n"
        "@frozen.freeze_time('2026-01-01')\n"
        "def test_module_decorated():\n"
        "    assert wall_time() > 0\n\n"
        "@travel('2026-01-01')\n"
        "def test_travelled():\n"
        "    assert chronology.datetime.now() is not None\n\n"
        "def test_freezer_fixture(freezer):\n"
        "    assert clock.time() > 0 and Moment.now() is not None\n\n"
        "def test_contexts():\n"
        "    with machine.travel('2026-01-01'):\n"
        "        assert clock.time() > 0\n"
        "    with freeze('2026-01-01'):\n"
        "        assert Moment.now() is not None\n\n"
        f"def test_patch_fixture({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() == 1.0\n"
        f"    {_PYTEST_PATCH}.setattr(chronology, 'datetime', FrozenMoment)\n"
        "    assert chronology.datetime.now() is not None\n\n"
        f"def test_string_patch({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr('time.time', lambda: 1.0)\n"
        f"    {_PYTEST_PATCH}.setattr('datetime.datetime', FrozenMoment)\n"
        "    assert clock.time() == 1.0\n"
        "    assert chronology.datetime.now() is not None\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    assert (
        scan_performance(
            load_git_inventory(repository.root),
            AuditPolicy.from_path(policy_path),
        )
        == ()
    )


def test_controls_are_binding_and_control_flow_precise(tmp_path: Path) -> None:
    """Unrelated, reverted, conditional, and copied-binding patches do not hide reads."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_control_boundaries.py",
        "import datetime as chronology\n"
        "import time as clock\n"
        "from datetime import datetime as Moment\n"
        "from time import time as wall_time\n\n"
        "def test_after_context():\n"
        "    from freezegun import freeze_time\n"
        "    with freeze_time('2026-01-01'):\n"
        "        assert clock.time() > 0\n"
        "    assert clock.time() > 0\n\n"
        f"def test_after_undo({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() == 1.0\n"
        f"    {_PYTEST_PATCH}.undo()\n"
        "    assert clock.time() > 0\n\n"
        f"def test_conditional_patch({_PYTEST_PATCH}, enabled):\n"
        "    if enabled:\n"
        f"        {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "        assert clock.time() == 1.0\n"
        "    assert clock.time() > 0\n\n"
        f"def test_unrelated_patch({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(chronology, 'date', object())\n"
        f"    {_PYTEST_PATCH}.setattr('os.getcwd', lambda: '/')\n"
        "    helper = lambda: None\n"
        "    helper()\n"
        "    assert chronology.datetime.now() is not None\n\n"
        f"def test_dynamic_patch_name({_PYTEST_PATCH}):\n"
        "    attribute = 'time'\n"
        f"    {_PYTEST_PATCH}.setattr(clock, attribute, lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_keyword_patch_name({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, name='time', value=lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_incomplete_string_patch({_PYTEST_PATCH}):\n"
        "    try:\n"
        f"        {_PYTEST_PATCH}.setattr('time.time')\n"
        "    except TypeError:\n"
        "        pass\n"
        "    assert clock.time() > 0\n\n"
        f"def test_indirect_patch_target({_PYTEST_PATCH}):\n"
        "    class Holder:\n"
        "        pass\n"
        "    holder = Holder()\n"
        "    holder.clock = clock\n"
        f"    {_PYTEST_PATCH}.setattr(holder.clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_rebound_patch_fixture({_PYTEST_PATCH}):\n"
        "    class LocalPatch:\n"
        "        def setattr(self, *args):\n"
        "            return args\n"
        f"    {_PYTEST_PATCH} = LocalPatch()\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        "def test_rebound_freezer(freezer):\n"
        "    freezer = object()\n"
        "    assert freezer is not None and clock.time() > 0\n\n"
        f"def test_module_patch_does_not_replace_copied_calls({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr('time.time', lambda: 1.0)\n"
        f"    {_PYTEST_PATCH}.setattr(chronology, 'datetime', object())\n"
        "    assert wall_time() > 0 and Moment.now() is not None\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_performance(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [item.symbol for item in candidates] == [
        "test_after_context",
        "test_after_undo",
        "test_conditional_patch",
        "test_unrelated_patch",
        "test_dynamic_patch_name",
        "test_keyword_patch_name",
        "test_incomplete_string_patch",
        "test_indirect_patch_target",
        "test_rebound_patch_fixture",
        "test_rebound_freezer",
        "test_module_patch_does_not_replace_copied_calls",
    ]
    assert "occurrences=2" in candidates[-1].evidence


def test_assigned_patch_and_finally_undo_preserve_runtime_state(tmp_path: Path) -> None:
    """Assigned patches suppress candidates and deterministic finalisers restore them."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_patch_state.py",
        "import time as clock\n\n"
        f"def test_assigned_patch({_PYTEST_PATCH}):\n"
        f"    _ = {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() == 1.0\n\n"
        f"def test_annotated_patch({_PYTEST_PATCH}):\n"
        f"    ignored: object = {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert ignored is None and clock.time() == 1.0\n\n"
        f"def test_finally_undo({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    try:\n"
        "        assert clock.time() == 1.0\n"
        "    finally:\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "    assert clock.time() > 0\n\n"
        f"def test_conditional_undo({_PYTEST_PATCH}, enabled):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    if enabled:\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "    assert clock.time() > 0\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_performance(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [item.symbol for item in candidates] == ["test_finally_undo", "test_conditional_undo"]
    assert [item.anchor.line_start for item in candidates] == [17, 23]
    assert all("clock_apis=time.time" in item.evidence for item in candidates)
    assert all("occurrences=1" in item.evidence for item in candidates)


def test_composed_try_and_exhaustive_join_state(tmp_path: Path) -> None:
    """Composed finalisers and exhaustive joins retain only guaranteed patch state."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_composed_patch_state.py",
        "import time as clock\n\n"
        f"def test_try_body_undo({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    try:\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "    finally:\n"
        "        pass\n"
        "    assert clock.time() > 0\n\n"
        f"def test_nested_finally_undo({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    try:\n"
        "        try:\n"
        "            assert clock.time() == 1.0\n"
        "        finally:\n"
        f"            {_PYTEST_PATCH}.undo()\n"
        "    finally:\n"
        "        pass\n"
        "    assert clock.time() > 0\n\n"
        f"def test_try_exception_floor({_PYTEST_PATCH}, fail):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    try:\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "        if fail:\n"
        "            raise RuntimeError\n"
        f"        {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 2.0)\n"
        "    except RuntimeError:\n"
        "        pass\n"
        "    assert clock.time() > 0\n\n"
        f"def test_exhaustive_match({_PYTEST_PATCH}, value):\n"
        "    match value:\n"
        "        case 1:\n"
        f"            {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "        case _:\n"
        f"            {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 2.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_non_exhaustive_match({_PYTEST_PATCH}, value):\n"
        "    match value:\n"
        "        case 1:\n"
        f"            {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_loop_else_patch({_PYTEST_PATCH}, values):\n"
        "    for value in values:\n"
        "        assert value is not None\n"
        "    else:\n"
        f"        {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_loop_break({_PYTEST_PATCH}, values):\n"
        "    for value in values:\n"
        "        if value:\n"
        "            break\n"
        "    else:\n"
        f"        {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_performance(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [item.symbol for item in candidates] == [
        "test_try_body_undo",
        "test_nested_finally_undo",
        "test_try_exception_floor",
        "test_non_exhaustive_match",
        "test_loop_break",
    ]
    assert all("clock_apis=time.time" in item.evidence for item in candidates)
    assert all("occurrences=1" in item.evidence for item in candidates)


def test_with_suites_publish_normal_patch_state(tmp_path: Path) -> None:
    """Normal exits from synchronous and asynchronous contexts retain patch state."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_with_patch_state.py",
        "import time as clock\n"
        "from freezegun import freeze_time\n\n"
        f"def test_with_undo({_PYTEST_PATCH}, manager):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    with manager:\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "    assert clock.time() > 0\n\n"
        f"def test_with_setattr({_PYTEST_PATCH}, manager):\n"
        "    with manager:\n"
        f"        {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"async def test_async_with_undo({_PYTEST_PATCH}, manager):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    async with manager:\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "    assert clock.time() > 0\n\n"
        f"async def test_async_with_setattr({_PYTEST_PATCH}, manager):\n"
        "    async with manager:\n"
        f"        {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    assert clock.time() > 0\n\n"
        f"def test_frozen_with_undo({_PYTEST_PATCH}):\n"
        f"    {_PYTEST_PATCH}.setattr(clock, 'time', lambda: 1.0)\n"
        "    with freeze_time('2026-01-01'):\n"
        f"        {_PYTEST_PATCH}.undo()\n"
        "    assert clock.time() > 0\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_performance(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [item.symbol for item in candidates] == [
        "test_with_undo",
        "test_async_with_undo",
        "test_frozen_with_undo",
    ]
    assert all("clock_apis=time.time" in item.evidence for item in candidates)
    assert all("occurrences=1" in item.evidence for item in candidates)


def test_import_shadowing_deferred_code_and_scope_are_conservative(tmp_path: Path) -> None:
    """Only executable assertions with unambiguous imports inside test scope qualify."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_scope.py",
        "import os\n"
        "import time as clock\n"
        "from os import getcwd\n\n"
        "class LocalClock:\n"
        "    @staticmethod\n"
        "    def time():\n"
        "        return 1.0\n\n"
        "    @classmethod\n"
        "    def now(cls):\n"
        "        return cls()\n\n"
        "def test_parameter(clock):\n"
        "    assert clock.time() == 1.0\n\n"
        "def test_assignment():\n"
        "    clock = LocalClock()\n"
        "    assert clock.time() == 1.0\n\n"
        "def test_local_import():\n"
        "    import time as local_clock\n"
        "    assert local_clock.time() > 0\n\n"
        "def test_ambiguous_local():\n"
        "    import time as local_clock\n"
        "    local_clock = LocalClock()\n"
        "    assert local_clock.time() == 1.0\n\n"
        "def test_conflicting_import():\n"
        "    import time as imported_clock\n"
        "    import custom_clock as imported_clock\n"
        "    assert imported_clock.time() > 0\n\n"
        "def test_conflicting_from_import():\n"
        "    from time import time as imported_time\n"
        "    from custom_clock import time as imported_time\n"
        "    assert imported_time() > 0\n\n"
        "def test_deferred():\n"
        "    deferred = lambda: clock.time()\n"
        "    assert deferred\n"
        "    def helper():\n"
        "        assert clock.time() > 0\n"
        "    async def async_helper():\n"
        "        assert clock.time() > 0\n"
        "    assert helper() is None\n"
        "    assert async_helper is not None\n"
        "    assert LocalClock.now() is not None\n\n"
        "def test_global_binding(*values, **options):\n"
        "    global clock\n"
        "    assert values or options or LocalClock.time() == 1.0\n\n"
        "def test_exception_targets(value):\n"
        "    try:\n"
        "        raise RuntimeError\n"
        "    except RuntimeError as clock:\n"
        "        assert clock is not None\n"
        "    try:\n"
        "        raise RuntimeError\n"
        "    except RuntimeError:\n"
        "        assert value is not None\n\n"
        "def test_pattern_targets(value):\n"
        "    match value:\n"
        "        case [clock]:\n"
        "            assert clock is not None\n"
        "        case [*clock]:\n"
        "            assert clock is not None\n"
        "        case {'value': clock, **remaining}:\n"
        "            assert clock is not None and remaining is not None\n"
        "        case {'other': _}:\n"
        "            assert value is not None\n"
        "        case [*_]:\n"
        "            assert value is not None\n"
        "        case _:\n"
        "            assert value is not None\n",
    )
    repository.write_text(
        "src/pkg/core.py",
        "import time\ndef check():\n    assert time.time() > 0\n",
    )
    repository.write_text("tests/test_broken.py", "def test_clock(:\n")
    repository.write_bytes("tests/test_binary.py", b"\xff\xfe")
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_performance(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [(item.anchor.path, item.symbol) for item in candidates] == [
        ("tests/test_scope.py", "test_local_import")
    ]


def test_assertions_inside_compound_statement_suites_are_scanned(tmp_path: Path) -> None:
    """Try, match, loop, and async-context suites retain the assertion boundary."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "tests/test_compound.py",
        "import time as clock\n\n"
        "def test_try(value):\n"
        "    try:\n"
        "        assert clock.time() > 0\n"
        "    except RuntimeError:\n"
        "        assert clock.time() > 0\n"
        "    else:\n"
        "        assert clock.time() > 0\n"
        "    finally:\n"
        "        assert clock.time() > 0\n\n"
        "def test_try_star():\n"
        "    try:\n"
        "        pass\n"
        "    except* RuntimeError:\n"
        "        assert clock.time() > 0\n\n"
        "def test_match(value):\n"
        "    match value:\n"
        "        case 1:\n"
        "            assert clock.time() > 0\n"
        "        case _:\n"
        "            assert clock.time() > 0\n\n"
        "def test_loops(values):\n"
        "    for value in values:\n"
        "        assert clock.time() > value\n"
        "    else:\n"
        "        assert clock.time() > 0\n"
        "    while values:\n"
        "        assert clock.time() > 0\n"
        "        break\n\n"
        "async def test_async_suites(values, manager):\n"
        "    async with manager:\n"
        "        assert clock.time() > 0\n"
        "    async for value in values:\n"
        "        assert clock.time() > value\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_performance(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [item.symbol for item in candidates] == [
        "test_try",
        "test_try_star",
        "test_match",
        "test_loops",
        "test_async_suites",
    ]
    assert [item.evidence.rsplit("occurrences=", 1)[1] for item in candidates] == [
        "4",
        "1",
        "2",
        "3",
        "2",
    ]
