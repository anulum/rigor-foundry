# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — permit ledger native syscall race regressions
"""Schedule owned file mutation around unchanged public ledger syscalls."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace

from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2

_WORKER = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from project_registry_syscall_scheduler import arm_native_trace
from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2
ledger = ConsumedPermitLedgerV2(Path(sys.argv[1]))
operation = sys.argv[2]
initial = sys.argv[4]
arguments = dict(permit_id="01a09a66-7b5c-7a2e-93f0-b726808737d4",
                 permit_digest="a"*64, expires_at="2026-09-23T03:00:00Z")
inner = None
arm_native_trace()
try:
    if operation == "lease":
        with ledger.locked_admission(selected_count=0, selected_head_digest=initial) as lease:
            try:
                lease.consume(**arguments)
            except PermissionError as error:
                inner = str(error)
                raise
    elif operation == "recovery":
        ledger.recover_torn_tail(recovered_at="2026-09-23T02:30:00Z")
    else:
        ledger.consume(**arguments)
except PermissionError as error:
    print(json.dumps({"outcome":"refused", "reason":str(error), "inner":inner}))
else:
    print(json.dumps({"outcome":"consumed"}))
"""


@pytest.mark.parametrize(
    ("operation", "mutation", "read_number", "expected"),
    [
        ("direct", "truncate", 1, "record is torn"),
        ("direct", "append", 1, "changed outside its lock"),
        ("recovery", "append", 1, "changed outside its lock"),
        ("lease", "append", 2, "changed before admission append"),
        ("direct", "mode", 1, "changed during locked operation"),
        ("recovery", "mode", 1, "changed during locked operation"),
        ("direct", "hardlink", 1, "changed during locked operation"),
        ("recovery", "hardlink", 1, "changed during locked operation"),
        ("direct", "none", 1, "consumed"),
    ],
)
def test_native_file_drift_refuses_before_append_or_recovery(
    tmp_path: Path, operation: str, mutation: str, read_number: int, expected: str
) -> None:
    """Actual EOF and competing bytes are observed without changing registers or responses."""
    tmp_path.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(tmp_path / "consumed.bin")
    initial = ledger.initialize()
    if operation == "recovery":
        with ledger.path.open("ab") as writer:
            writer.write(b"x")
    original = ledger.path.read_bytes()
    reads = 0
    changed = False
    changed_bytes = original

    def mutate(stop: SyscallStop) -> bool:
        """Mutate this exact owned ledger at an actual read boundary and resume the syscall."""
        nonlocal reads, changed, changed_bytes
        if stop.number != 0 or stop.path != str(ledger.path):
            return False
        if stop.entering:
            reads += 1
        trigger = stop.entering if mutation == "truncate" else not stop.entering
        if trigger and reads == read_number and not changed and mutation != "none":
            if mutation == "truncate":
                with ledger.path.open("r+b") as writer:
                    writer.truncate(0)
                    writer.flush()
                    os.fsync(writer.fileno())
            elif mutation == "mode":
                ledger.path.chmod(0o640)
            elif mutation == "hardlink":
                ledger.path.with_name("alias.bin").hardlink_to(ledger.path)
            else:
                with ledger.path.open("ab") as writer:
                    writer.write(b"y")
                    writer.flush()
                    os.fsync(writer.fileno())
            changed_bytes = ledger.path.read_bytes()
            changed = True
        return False

    result = run_traced(
        [
            sys.executable,
            "-B",
            "-c",
            _WORKER,
            str(ledger.path),
            operation,
            str(Path(__file__).parent),
            initial,
        ],
        mutate,
        timeout=20,
    )
    write_trace(tmp_path / "native-trace.json", result)
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    assert reads >= read_number
    if mutation == "none":
        assert response["outcome"] == "consumed"
        assert changed is False
        assert ledger.verify_anchor(record_count=0, head_digest=initial)[0] == 1
    else:
        assert changed is True
        assert response["outcome"] == "refused"
        assert expected in (response["inner"] or response["reason"])
        assert ledger.path.read_bytes() == changed_bytes
