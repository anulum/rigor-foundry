# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — operations and observability scanner tests
"""Verify bounded output and credential-logging candidates in real Git trees."""

from __future__ import annotations

import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.operations import scan_operations
from rigor_foundry.scanner import scan_repository

_HEADER = "# SPDX-License-" + "Identifier: Apache-2.0\n"


def test_public_scan_finds_library_output_and_credential_logging(tmp_path: Path) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/core.py",
        _HEADER + "import logging as telemetry\n"
        "from logging import getLogger as make_logger\n\n"
        "logger = telemetry.getLogger(__name__)\n"
        "audit = make_logger(__name__)\n\n"
        "def emit(api_key, client_secret, credentials, access_token):\n"
        "    print('debug')\n"
        "    logger.info('api=%s', api_key)\n"
        "    audit.warning(f'{client_secret}')\n"
        "    telemetry.error(credentials)\n"
        "    telemetry.getLogger('audit').critical(access_token)\n",
    )
    repository.write_text(
        "src/pkg/safe.py",
        _HEADER + "import logging\nlogger = logging.getLogger(__name__)\n\n"
        "def emit(api_key_hash):\n"
        "    logger.info('password redacted')\n"
        "    logger.info('key digest=%s', api_key_hash)\n",
    )
    repository.write_policy(required_domains=frozenset({"operations-and-observability"}))
    repository.commit()

    report = scan_repository(repository.root)
    candidates = tuple(item for item in report.candidates if item.rule_id.startswith("OP"))
    assert collections.Counter(item.rule_id for item in candidates) == {
        "OP001-print-in-library-code": 1,
        "OP002-credential-in-log-call": 4,
    }
    first = candidates[0]
    assert first.category == "operations"
    assert first.symbol == "print"
    assert first.confidence == "medium"
    assert isinstance(first.anchor, TrackedBlobAnchor)
    assert Candidate.from_dict(first.to_dict()) == first
    assert all("line_sha256=" in item.evidence for item in candidates)
    assert not any(
        item.rule_id == "GV004-uncontrolled-required-domain"
        and item.symbol == "operations-and-observability"
        for item in report.candidates
    )


def test_print_scope_excludes_commands_tests_and_shadowed_names(tmp_path: Path) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("tools/helper.py", "print('command')\n")
    repository.write_text("scripts/helper.py", "print('command')\n")
    repository.write_text("src/pkg/cli.py", "print('command')\n")
    repository.write_text("src/pkg/admin_cli.py", "print('command')\n")
    repository.write_text("tests/test_output.py", "def test_output():\n    print('test')\n")
    repository.write_text("src/pkg/broken.py", "def broken(:\n")
    repository.write_bytes("src/pkg/binary.py", b"\xff\xfe")
    repository.write_text(
        "src/pkg/shadow.py",
        _HEADER + "def print(value):\n    return value\n\ndef run():\n    print('local')\n",
    )
    repository.write_text(
        "src/pkg/parameters.py",
        _HEADER + "def positional(print):\n    print('local')\n\n"
        "def variadic(*print):\n    print('local')\n\n"
        "def keywords(**print):\n    print('local')\n\n"
        "def assigned():\n    print = lambda value: value\n    print('local')\n\n"
        "def annotated():\n    print: object = lambda value: value\n    print('local')\n\n"
        "def nested():\n    def print(value):\n        return value\n    print('local')\n\n"
        "def imported():\n    import builtins as print\n    print('local')\n",
    )
    repository.write_text(
        "src/pkg/bindings.py",
        _HEADER + "class Holder:\n    value = 1\n\n"
        "[print, other] = [lambda value: value, object()]\n"
        "holder = Holder()\nholder.value = object()\n"
        "unused = object()\nprint('local')\n",
    )
    repository.write_text(
        "src/pkg/output.py",
        _HEADER + "import builtins as runtime\nruntime.print('module')\n\ndef emit():\n"
        "    runtime.print('explicit')\n"
        "    print('builtin')\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_operations(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [(item.rule_id, item.anchor.path) for item in candidates] == [
        ("OP001-print-in-library-code", "src/pkg/output.py"),
        ("OP001-print-in-library-code", "src/pkg/output.py"),
        ("OP001-print-in-library-code", "src/pkg/output.py"),
    ]


def test_print_scope_respects_python_bindings_and_explicit_builtin_imports(
    tmp_path: Path,
) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/nested_scopes.py",
        _HEADER + "def outer():\n"
        "    print('builtin')\n"
        "    def inner():\n"
        "        print = lambda value: value\n"
        "        print('local')\n"
        "    class Holder:\n"
        "        print = object()\n",
    )
    repository.write_text(
        "src/pkg/imported_builtin.py",
        _HEADER + "from builtins import print\n"
        "from builtins import print as output\n\n"
        "print('module')\n"
        "output('alias')\n\n"
        "def emit():\n"
        "    print('function')\n\n"
        "def local_alias():\n"
        "    from builtins import print as local_output\n"
        "    local_output('function alias')\n",
    )
    repository.write_text(
        "src/pkg/local_bindings.py",
        _HEADER + "def walrus():\n"
        "    (print := lambda value: value)\n"
        "    print('local')\n\n"
        "def loop(items):\n"
        "    for print in items:\n"
        "        print('local')\n\n"
        "def context(manager):\n"
        "    with manager as print:\n"
        "        print('local')\n\n"
        "def handler():\n"
        "    try:\n"
        "        raise RuntimeError\n"
        "    except RuntimeError as print:\n"
        "        print('local')\n\n"
        "async def async_bindings(items, manager):\n"
        "    async for print in items:\n"
        "        print('local')\n"
        "    async with manager as print:\n"
        "        print('local')\n\n"
        "def deleted():\n"
        "    del print\n"
        "    print('unreachable local')\n\n"
        "def global_output():\n"
        "    global print\n"
        "    print('builtin')\n",
    )
    repository.write_text(
        "src/pkg/closures_and_matches.py",
        _HEADER + "def closure():\n"
        "    print = lambda value: value\n"
        "    def inner():\n"
        "        print('free local')\n\n"
        "def global_closure():\n"
        "    print = lambda value: value\n"
        "    def inner():\n"
        "        global print\n"
        "        print('builtin')\n\n"
        "def captures(value):\n"
        "    match value:\n"
        "        case [print]:\n"
        "            print('sequence capture')\n"
        "        case {'value': print, **remaining}:\n"
        "            print('mapping capture')\n"
        "        case [*print]:\n"
        "            print('star capture')\n\n"
        "def mapping_rest(value):\n"
        "    match value:\n"
        "        case {**print}:\n"
        "            print('mapping rest capture')\n\n"
        "def nonlocal_closure():\n"
        "    print = lambda value: value\n"
        "    def inner():\n"
        "        nonlocal print\n"
        "        print('nonlocal')\n",
    )
    repository.write_text(
        "src/pkg/class_scopes.py",
        _HEADER + "class Local:\n"
        "    print = lambda *values: values\n"
        "    print('class local')\n\n"
        "class BuiltinFirst:\n"
        "    print('builtin before bind')\n"
        "    print = lambda *values: values\n\n"
        "class Methods:\n"
        "    print = lambda *values: values\n"
        "    def method(self):\n"
        "        print('method builtin')\n\n"
        "def outer():\n"
        "    class Local:\n"
        "        print = lambda *values: values\n"
        "        print('nested class local')\n"
        "    class Builtin:\n"
        "        print('nested class builtin')\n",
    )
    repository.write_text(
        "src/pkg/comprehensions.py",
        _HEADER + "def local_targets(values, groups):\n"
        "    list_result = [print(value) for print in [str] for value in values]\n"
        "    set_result = {print(value) for print in [str] for value in values}\n"
        "    dict_result = {print(value): value for print in [str] for value in values}\n"
        "    generator = tuple(print(value) for print in [str] for value in values)\n"
        "    nested = [print(value) for group in groups for print in group for value in values]\n\n"
        "def builtin(values):\n"
        "    return [print(value) for value in values]\n\n"
        "def outer_iterable():\n"
        "    return [value for value in print()]\n\n"
        "def staged_iterable(values):\n"
        "    return [value for print in [lambda: values] for value in print()]\n\n"
        "def staged_condition(values):\n"
        "    return [value for print in [lambda item: True] for value in values if print(value)]\n\n"
        "def early_condition(values):\n"
        "    return [value for value in values if print(value) for print in [str]]\n",
    )
    repository.write_text(
        "src/pkg/lambdas.py",
        _HEADER + "local = lambda print: print('local')\n"
        "builtin = lambda: print('builtin')\n"
        "walrus = lambda: ((print := str), print('local'))\n\n"
        "def closure():\n"
        "    print = lambda value: value\n"
        "    return lambda: print('free local')\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_operations(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [(item.anchor.path, item.anchor.line_start) for item in candidates] == [
        ("src/pkg/class_scopes.py", 7),
        ("src/pkg/class_scopes.py", 13),
        ("src/pkg/class_scopes.py", 20),
        ("src/pkg/closures_and_matches.py", 11),
        ("src/pkg/comprehensions.py", 10),
        ("src/pkg/comprehensions.py", 13),
        ("src/pkg/comprehensions.py", 22),
        ("src/pkg/imported_builtin.py", 5),
        ("src/pkg/imported_builtin.py", 6),
        ("src/pkg/imported_builtin.py", 9),
        ("src/pkg/imported_builtin.py", 13),
        ("src/pkg/lambdas.py", 3),
        ("src/pkg/local_bindings.py", 32),
        ("src/pkg/nested_scopes.py", 3),
    ]


def test_logging_requires_import_binding_and_sensitive_value_name(tmp_path: Path) -> None:
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/logs.py",
        _HEADER + "import logging\n"
        "from logging import getLogger as factory\n\n"
        "audit: object = factory(__name__)\n\n"
        "def emit(obj, authToken, password_digest, api_key):\n"
        "    audit.debug(authToken)\n"
        "    logging.info(obj.privateKey)\n"
        "    logging.warning(password_digest)\n"
        "    logging.getLogger('nested').exception(api_key)\n"
        "    factory('direct').critical(api_key)\n"
        "    custom.info(api_key)\n",
    )
    policy_path = repository.write_policy()
    repository.commit()
    candidates = scan_operations(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [(item.symbol, item.anchor.line_start) for item in candidates] == [
        ("debug", 8),
        ("info", 9),
        ("exception", 11),
        ("critical", 12),
    ]
    assert all(item.rule_id == "OP002-credential-in-log-call" for item in candidates)
    assert all(item.confidence == "high" for item in candidates)
