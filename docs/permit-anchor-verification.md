# Permit anchor verification and recovery evidence

`PermitLedgerAnchorStoreV2` binds an owner-only anchor file to complete permit
ledger and effect journal histories. `RecoveryEvidenceStoreV2` publishes exact
canonical recovery objects under their SHA-256 filenames. These provisional
module-level Python APIs retain the V2.4 anchor and V2.1 journal recovery wires.
They add no stable CLI command or package-level 1.0 compatibility promise.

## Selected files and ordinary verification

The caller supplies absolute paths beneath existing no-follow directories owned
by the effective UID with mode `0700`. Anchor and evidence objects must be
regular, single-link, owner-owned files with mode `0600`. An ordinary fixture
demonstrates these storage checks; it does not establish protected host selection,
authenticate a supervisor, or grant an effect permission.

Initialise a new empty ledger and journal before creating their anchor:

```python
from pathlib import Path

from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2
from rigor_foundry.permit_anchor_store_v2 import PermitLedgerAnchorStoreV2
from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2
from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2

# The caller has already provisioned custody and custody/evidence at mode 0700.
custody = Path("/srv/rigor/custody")
ledger = ConsumedPermitLedgerV2(custody / "consumed.bin")
journal = EffectJournalStoreV2(custody / "effect.journal")
anchor = PermitLedgerAnchorStoreV2(custody / "anchor.bin")
evidence = RecoveryEvidenceStoreV2(custody / "evidence", 64, 1_000_000)
ledger.initialize()
journal.initialize()
initial = anchor.initialize(ledger=ledger, journal=journal, max_journal_bytes=1_000_000)
selected = anchor.current(
    ledger=ledger,
    journal=journal,
    evidence=evidence,
    selected_journal_identity=initial.journal_identity,
    max_journal_bytes=1_000_000,
)
assert selected.ledger_record_count == 0
```

Initialisation creates the anchor exclusively and fsyncs its bytes and parent;
an existing file refuses replacement. `current()` holds locks in anchor → ledger
→ journal order, validates the complete retained prefix, rechecks file custody,
and returns the verified selection and journal replay state. The host supplies
the expected journal identity and finite byte budget independently.

## Anchor wire and recovery commitments

The magic is `RIGOR-PERMIT-ANCHOR-V2.4\n`; each complete record is 200 bytes with
big-endian layout `>B3xQ32s32sQQQI32s32s32s`. Reserved bytes are zero. The chain
head is SHA-256 of the previous head plus the first 168 record bytes.

| Kind | Verified meaning |
| --- | --- |
| 0 | Genesis, ordinary consumption bound to exactly one matching final operation intent, or a journal-only advance that admits no operation intent. |
| 1 | Final-tail recovery commitment; preserves the prior ledger and journal selections and resolves one exact root/child intent chain. |
| 2 | Complete ledger suffix adoption, bound to immutable evidence, exact record arrays, selected file identities and the consumed UUID commitment. |
| 3 | Newly honoured closure, naming the last new closure frame for an already selected operation. |

Only a sole final partial or invalid complete record after a valid initial prefix
can be classified as tail damage. First/interior damage refuses. Classification
does not authorise truncation. Ordinary reads refuse damaged tails, unresolved
selected recovery intents, ledger suffixes requiring adoption, missing evidence,
and orphan audit frames. A complete unanchored audit or closure remains inert.

The tail scanner verifies the initial record against the ledger, journal and
anchor genesis values before scanning successors. Each successor therefore
inherits an already verified selection.

The three closed evidence domains are:

- `rigor.permit-anchor-final-recovery.v2.4`
- `rigor.permit-anchor-recovery.v2.4`
- `rigor.effect-journal-tail-recovery.v2.1`

Public validators in `recovery_evidence_schema_v2` produce exact PCS-CANON-1
bytes. They reject extra or missing fields, duplicate keys, noncanonical JSON,
path/time/base64 aliases, unsafe JSON integers, and inconsistent captured lengths
or digests. Grammar-valid operator identities and proof references are data;
they do not authenticate an operator.

## Immutable evidence custody

`publish(data)` validates the entire object, checks count and aggregate byte
budgets, writes and fsyncs exact bytes, and returns their SHA-256 digest.
Publishing identical bytes is idempotent. Journal intent publication uses Linux
`renameat2(RENAME_NOREPLACE)` on a staged object; syscall refusal fails closed and
clears staging. Anchor-domain objects use exclusive digest-file creation; an
interrupted write can leave an invalid object that blocks subsequent reads.

`read(digest)` and `scan()` validate every published object and the complete
bounded directory enumeration. Staging remnants confer no authority but count
toward the entry budget. Symlinks, additional hard links, substituted paths,
changed bytes and special files refuse. Writerless FIFOs are opened nonblocking
and rejected by the regular-file custody check.

Callers retain their selected chain locks while consulting evidence. The store
checks canonical bytes and custody; the anchor prefix verifier separately checks
semantic relationships to the selected chains. The destructive recovery and
adoption operators require an authenticated supervisor integration and are not
provided by these APIs.

The public journal intent verifier also rechecks each supplied map key against
the SHA-256 of its exact object bytes before filtering domains or file identities.
A caller cannot introduce a digest alias by supplying an in-memory object map.

This storage implementation uses POSIX locks and Linux no-replace publication.
It has no Rust, Go, TypeScript or Windows runtime counterpart. Existing adapter
benchmarks measure another surface and make no performance claim about these
storage operations.
