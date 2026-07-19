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
        "    print('function')\n",
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
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_operations(
        load_git_inventory(repository.root), AuditPolicy.from_path(policy_path)
    )
    assert [(item.anchor.path, item.anchor.line_start) for item in candidates] == [
        ("src/pkg/imported_builtin.py", 5),
        ("src/pkg/imported_builtin.py", 6),
        ("src/pkg/imported_builtin.py", 9),
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
