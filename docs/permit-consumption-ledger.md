# Permit consumption ledger

`rigor_foundry.permit_consumption_ledger_v2.ConsumedPermitLedgerV2` records
consumed permit UUIDs in a local file. It rejects replay across both the permit
and optional single-use UUID fields, verifies the complete hash chain, and
fsyncs each complete append before returning its head.

This module-level Python API supplies storage mechanics. The consuming host
separately verifies signatures, actual expiry, authority, selection and protected
anchors. A digest or parsed record grants no effect permission, and this API
does not dispatch a handler or enrol a service account. The stable CLI and
package-level compatibility contract are unchanged.

## File and wire contract

The caller selects an absolute path under an existing parent owned by the
current service UID with mode `0700`. An existing ledger must be a regular,
single-link file owned by that UID with mode `0600`. Paths are opened through
no-follow directory descriptors; symlinks, hard links, wrong modes, torn tails,
invalid complete rows and mismatched selected prefixes refuse.

The fixed header is `RIGOR-PERMIT-LEDGER-V2.2\n`. Complete records use the
big-endian layout `>B3x16s16s32sQI32s`, containing a kind, zero padding, two
UUIDs, digest, positive UTC epoch microseconds, metadata and the previous chain
head. The next head is SHA-256 of the previous head followed by the record bytes
excluding their final previous-head field. Consumption uses kind zero and
metadata zero; explicit recovery uses kind one and records the removed tail's
SHA-256 and length. Reserved UUIDs, an all-zero digest and nonzero padding refuse.

`expires_at` is retained metadata. This storage layer checks its wire range,
not whether a signed permit is currently valid. The caller must make that
authority decision before requesting consumption.

## Public operations

| Operation | Behaviour |
| --- | --- |
| `initialize()` | Exclusively create and fsync a new ledger and its parent; never replace an existing file. |
| `consume(...)` | Verify all history, refuse either previously consumed UUID, append and fsync one complete row. |
| `verify_anchor(...)` | Verify a caller-supplied prefix against all current records and return current count and head. |
| `verify_anchor_with_identity(...)` | Return that result and the same locked file's path digest, device and inode. |
| `locked_snapshot(...)` | Retain the actual lock while exposing all verified records; recheck custody on exit. |
| `locked_admission(...)` | Issue one append lease only when the complete current tail equals the selected count and head. |
| `recover_torn_tail(...)` | Explicitly remove only an incomplete tail after validating all complete history, then fsync an audited recovery row. |

A snapshot may extend an older valid selected prefix. An admission lease
requires the exact current tail and refuses an unanchored suffix. Consumption
through an issued lease rechecks actual file custody and complete history,
including same-size changes, immediately before appending. Each lease permits
one append attempt and belongs to its original process. Closing the context or
forking refuses later use; ordinary descriptor-number reuse cannot revive it.
Directly constructing a lease does not issue one.
Python copy, deep-copy and pickle operations also refuse for these descriptor leases.

An I/O failure or final custody refusal is not a rollback promise. A complete
consumption is retained even if a later handler fails. The qualified host must
retain its selection and anchor locks through ledger, journal and anchor fsync,
and reconcile failures using its separately authorised recovery procedure.

## Local storage example

This example exercises a disposable file. Its initial head is a storage result,
not a protected host selection or a signed permission.

```python
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2

with TemporaryDirectory() as directory:
    parent = Path(directory)
    parent.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(parent / "consumed.bin")
    initial = ledger.initialize()
    with ledger.locked_admission(
        selected_count=0, selected_head_digest=initial
    ) as transaction:
        record = transaction.consume(
            permit_id=str(uuid4()),
            single_use_id=str(uuid4()),
            permit_digest="a" * 64,
            expires_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
    assert ledger.verify_anchor(
        record_count=1, head_digest=record.head_digest
    ) == (1, record.head_digest)
```

The example's digest and timestamp are ordinary storage inputs. A real consumer
supplies the digest and expiry from its independently verified permit.

## Ownership and qualification

`permit_consumption_ledger_v2` owns file locking, actual snapshots, append-lease
lifetime and explicit recovery. `_permit_ledger_records_v2` owns the fixed
binary wire, UUID/time validation, complete replay and immutable record carriers.
`_permit_ledger_storage_io_v2` owns descriptor identity, owner checks and bounded
complete reads/writes. Public ledger workflows exercise both private owners.

The dedicated tests cover durable replay, concurrent consumers, both UUID
fields, actual stored corruption, modes and links, selected prefixes, stale and
inherited leases, descriptor reuse and explicit torn-tail recovery. Ordinary
user-owned fixtures qualify these mechanics; they do not qualify a protected
signer, deployment, native handler or effect-admission chain.
