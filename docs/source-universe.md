# Retained source universe

The provisional Python source APIs preserve the complete host-selected policy
source cohort and verify its actual original bytes. They keep unused, unread,
unavailable, protected and excluded sources explicit. Byte integrity and a
complete partition are prerequisites for a later corpus consumer; they do not
establish semantic completeness, accepted exclusions, ready boot or effects.

## Original source formats

`policy_source_records.PolicySourceRecord1` adapts the actual original models
to the retained context-source interface. It preserves every original field,
version and owning digest. `parse_policy_source_record(kind, value,
budget=budget)` selects a fixed parser with explicit collection/depth bounds.
Request data cannot appoint a loader, parser or source location.

| Source kind | Exact original format | Original identity and digest |
| --- | --- | --- |
| `source-capture` | `1.0` | Complete `SourceCapture.capture_digest` for both fields |
| `native-source-pin` | `native-source-pin.v1` | Original `source_id` and `pin_digest` |
| `discovery-source-receipt` | `discovery-source-closure.v1` | Original `receipt_digest` for both fields |

The capture reference identifies the complete acquisition record, rather than
the payload hash alone. The native pin retains the original full JSONL-file
and exact question/reply selectors. Parsing either remains a metadata check.

`discovery_source_receipt.DiscoverySourceReceipt1` parses the existing output
of `validate_discovery_sources`. It adds no `object_kind` to that original
receipt and defines no replacement digest. Original sorted source/shard rows,
unused source IDs, manifest hash, candidate/span counts and `DiscoveryLimits`
remain intact. Its original status is `discovery-integrity-verified`, assertion
class is `declared-snapshot-integrity-only` and `promotable` remains false.
Explicit policy parser budgets do not rewrite those embedded original limits.

## Actual source selection and lifetime

`retained_policy_source.RetainedPolicySource` holds an independently selected
raw file and its parent directory through use and closing checks. The host
already owns access; opaque universe locators never become file paths.

```python
from rigor_foundry.retained_policy_source import RetainedPolicySource

with RetainedPolicySource(
    original_path,
    byte_digest=selected_byte_sha256,
    byte_count=selected_byte_count,
    budget=budget,
) as retained_bytes:
    original_payload = retained_bytes.read()
```

Every read checks complete exact bytes, the single-link regular-file policy,
no-follow traversal, retained file/parent identities and individual byte
limits. Empty files remain actual zero-byte sources. Changes or replacement
invalidate the held selection. Closure repeats the check and releases both
owned descriptors even when it refuses; later use fails. A new lease of equal
bytes has a different selection identity. No fetch or duplicate prose tree is
created by these APIs.

`policy_source_selection.PolicySourceSelection` borrows the original metadata
lease and optional raw lease. Its source ID, classification, opaque locator,
read state, disposition and optional decision ID are explicit host choices.
Held rows have no installed raw, native or discovery reader. Their metadata
can remain present even when the original payload is unavailable.

Verified HTTPS captures compare actual raw count/hash with the original
capture. Verified native selections use the actual `HostNativeSourceVerifier`
and current host pin/revocations, original captures, full file hash and exact
original file path. A caller-supplied native pin is not a trusted host state.
The original native verification remains integrity evidence, not issuer or
semantic authority.

Verified discovery selections additionally borrow `DiscoverySourceSelection`:
an explicit original root, manifest name and original `DiscoveryLimits`.
They join the retained raw path/count/hash to the actual manifest and rerun
the unchanged complete original validator. Original processing limits must
fit the current explicit policy budget. Neither a receipt alone nor a local
Markdown file relabelled as an HTTPS capture proves that observation.

## Complete fixed owner

`source_universe_owner.SourceUniverseOwner` requires the entire immutable,
source-ID-sorted cohort, actual retained registry/producer-contract files and
a prior complete package/interpreter observation. Its fixed implementation ID
is `builtin.policy-source-universe.v1`, owner class `source`; its independent
subject kinds are `source-bytes` and `source-record`, with no fact namespace.
The contract must enroll the actual registry and original source formats.
Root project/group/path relations are checked against the original registry.
Those descriptive bindings do not grant access to external source material.

```python
from rigor_foundry.source_universe_owner import SourceUniverseOwner

# All inputs are actual host selections, already held by their owning contexts.
with SourceUniverseOwner(
    sources=selected_sources,
    registry_source=selected_registry,
    contract_source=selected_source_contract,
    implementation=observed_code,
    budget=budget,
) as owner:
    universe = owner.observe()
    owner.verify(universe)
    checked_regions = owner.verify_partitions(
        universe, regions=declared_regions, spans=declared_statement_spans
    )
```

Every original discovery receipt contributes **all** its source rows, including
unused empty sources. Missing rows refuse. A mixture of held and verified
members refuses before calling any original discovery reader: complete
snapshot validation must not ingest a protected member merely to qualify
another row. An entirely held cohort remains representable without reading
its original payload files.

The owner observes its complete actual package/interpreter, original sources,
contract and registry before and after producing entries or consuming byte
partitions. Selection snapshots bind the whole cohort and source verification
results. Independent byte/record subjects precede enclosing entry/proof hashes;
there is no self-referential context digest. `verify` recomputes the complete
actual cohort, so a subset or a self-digested foreign declaration fails.
Owner closure revalidates the borrowed selections; their host closes the
underlying leases afterward. Repeated observations do not prove atomic or
continuous multi-root custody between checks.

## Source entries and byte accounting

`source_universe.SourceUniverseEntry1` has closed schema `1.0` fields:
`schema_version`, `object_kind`, `source_id`, `existing_source`, `classification`,
`locator`, `byte_digest`, `byte_count`, `read_state`, `disposition`,
`disposition_decision`, `provenance` and `entry_digest`.

Classifications are `public`, `internal`, `confidential` and `secret`. Read
states are `verified`, `unread`, `unavailable` and `protected`; dispositions
are `included` and `excluded`. Verified rows require an exact byte hash/count.
The fixed owner emits null byte metadata for held rows and binds their original
record as the independent proof subject. An excluded row requires its exact
decision ID and remains present. A decision ID alone does not prove that the
competent semantic owner accepted that exclusion.

`verify_partitions` checks existing `SourceRegion1` and optional `SourceSpan1`
records over the same actual held bytes for every included verified source.
Regions retain source/byte order and partition the complete payload without
gaps, overlap or omitted tails. Empty sources need no region. Rule, decision,
span, source and combined byte budgets remain enforced. Foreign, held or
excluded sources cannot supply partition bytes. Optional spans verify original
byte bounds and hashes without changing statement offsets or newlines.

Parsing an entry or verifying its partition does not accept extraction meaning,
grant source access, authenticate an initiating instruction/claim or qualify a
selected policy/common gate. Relevant held sources and unresolved regions still
require the enclosing corpus/host decision. These APIs emit no ready or admitted
status.
