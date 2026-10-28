# Retained context sources

The provisional context source APIs connect exact typed identities to their
owning parsers and retain actual source files through use and closing checks.
They provide source integrity for a host that independently selects the source
and producer. Installed ownership, initiating task authority and operation
admission require the host's separate checks.

## Fixed source parsing

`typed_object_reference.TypedObjectRef1` has closed versioned fields for the
source kind, format, object ID, object digest and complete reference digest.
The current source table is:

| Source kind | Exact format | Owning parser |
| --- | --- | --- |
| `task-definition` | `1.0` | `TaskDefinition1` |
| `context-producer-contract` | `1.0` | `ContextProducerContract1` |
| `repository-state` | `1.0` | `RepositoryState1` |
| `inventory-domain` | `1.0` | `InventoryDomain1` |
| `inventory-baseline` | `1.0` | `InventoryBaseline1` |
| `work-task` | `1.0` | Original `WorkTask` |
| `work-record` | `1.0` | `WorkRecordSource1` with the original full task/event chain |
| `work-closure` | `1.0` | Original `WorkClosure` |
| `source-capture` | `1.0` | Original `SourceCapture` through `PolicySourceRecord1` |
| `native-source-pin` | `native-source-pin.v1` | Original `NativeSourcePin` through `PolicySourceRecord1` |
| `discovery-source-receipt` | `discovery-source-closure.v1` | Original validator receipt through `DiscoverySourceReceipt1` and `PolicySourceRecord1` |
| `project-registry` | `gotm-project-registry.v1` | `ProjectRegistry` |
| `project-registry` | `project-registry.v2` | `ProjectRegistry` with its original embedded profile |

`context_source_resolution.parse_context_source_target(reference, value,
budget=budget)` first validates the exact supported reference, then calls the
fixed owning parser and compares the resulting ID and original digest. Unknown
pairs refuse before target interpretation. Object IDs are never interpreted
as paths, URLs, import names or callbacks. Registry children retain their
original canonical serialization and generation identity. Their collection
and relationship counts also respect the supplied reference budget.

`policy_source_reads.parse_policy_document_payload(payload, budget=budget)`
decodes already retained exact bytes with the same strict byte/depth bounds,
duplicate-key, finite-number and UTF8 rules as `read_policy_document`.
It performs no additional filesystem read.

## A retained source lifetime

`context_source_lease.RetainedContextSource` is constructed by the host from an
independently selected source path, typed reference, expected raw SHA-256 and
explicit [read budget](policy-source-inputs.md). It has no request-wire loader.

```python
from pathlib import Path

from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.typed_object_reference import TypedObjectRef1

# These values come from the calling host's existing trusted source selection.
reference = TypedObjectRef1.from_dict(selected_reference)
with RetainedContextSource(
    Path(selected_path),
    reference=reference,
    raw_digest=selected_raw_sha256,
    budget=budget,
) as retained:
    source = retained.read()
    snapshot_id = retained.snapshot_id
```

The reader holds both file and parent-directory descriptors. It refuses
symlink traversal, hardlinked/nonregular sources and oversized or unstable
reads. Each read checks the selected object identities, exact raw bytes and
owning parser. Registry files additionally require their original canonical
bytes. A successful return does not replace source-access authorization.

The context manager repeats the complete check at closure and releases owned
descriptors even when that check refuses. Explicit `close()` is idempotent;
later reads, references or snapshot access refuse. Edited, replaced, deleted
or newly aliased sources and changed parent-directory identities invalidate
the selection. A new reader of equal bytes has a different selection identity
and cannot stand in for the original retained lifetime.

These descriptor guarantees require a platform with the existing no-follow
directory traversal support. An unavailable platform refuses rather than
falling back to a weaker reader.

## Independent observations and proof metadata

`context_owner_observations.OwnerObservation` is a closed inline reference,
state, value and independent subject digest. Known null, a known empty array,
exact absence and unknown remain distinct. Values follow the existing finite
scalar or flat scalar-array semantics; references use the exact bounded dotted
grammar, without wildcards or inferred descendant absence.
Equality and hashing preserve scalar wire types: Boolean `true` differs from
numeric `1`, including inside an array.

`ContextProducerObservation1` binds owner, contract-reference and source-reference
digests, actual selected snapshot, subject kind/digest and sorted unique inline
observations. Its `digest(budget=budget)` hashes this independent mapping.
The mapping contains no final proof, fact-observation or context digest.

`context_owner_proof.OwnerProof1` then binds the owner/class, exact contract and
source references, independent subject, snapshot and observation digest. Its
own digest covers the complete versioned envelope. Parsing verifies metadata
integrity; `verify_proof_binding(proof, budget=budget)` on the observation
preimage checks their agreement.

A matching envelope remains metadata until the installed owner verifies the
actual retained source, complete code/contract selection, observation domain,
current snapshot and revocation state. Supplied observations cannot appoint
that owner, manufacture authoritative absence or establish complete maintained
scope. These APIs do not emit an authenticated host or effect-admission result.

The [configured inventory Git-root observer](inventory-domains.md#actual-selected-git-root-observations)
also borrows real domain/registry/contract leases. It compares the complete
declared project root set and actual package/interpreter identity before
returning classified bytes for one Git root. Other roots and whole maintained
inventory/context admission remain separate obligations.

The [complete baseline/state observer](inventory-baselines.md) additionally
borrows an independently selected earlier baseline. It compares actual original
Git blobs and the complete configured domain before deriving repository-state
identities. Retained directory history remains explicit; it is not recovered
from the later current scan. The final baseline check rejects late mutations
without making the result an authenticated owner-proof token.

The [fixed inventory owner and source fact composition](maintained-context.md)
now generate and reverify actual maintained scope, independent inventory proof
preimages and current task/registry/inventory facts. Their closed result records
retain separate structural parsing and actual source verification. Initiating
authority, host-required-root selection and runtime admission remain separate.

`TaskRegistrySourceOwners.root_bindings()` revalidates the original actual
task/registry sources and returns their complete root selection. Source fact
composition compares every root's path, project, group and configured-domain
digest against the actual inventory, rather than joining root labels alone.

The [complete task source context](task-context.md) joins these actual identities
and optional original remediation source files before condition use. The new
work-record source projection binds the complete original task and event chain;
it does not redefine legacy events or infer initiating authority from metadata.

The [complete source universe owner](source-universe.md) additionally borrows
these original metadata selections and actual raw/native/discovery owners.
It retains held and excluded rows, requires every original discovery source
including unused rows, and verifies complete partitions over the same held
bytes. Original discovery receipts retain their original limits and digest;
neither parsing nor byte accounting grants semantic acceptance or source access.
