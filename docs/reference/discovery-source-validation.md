# Discovery source validation

The read-only discovery validator verifies exact captured source, shard and line
span bindings. It does **not** verify normative entailment, source authenticity,
freshness, confidentiality clearance, complete policy extraction or permission.
Success always returns `promotable: false`. It neither signs nor activates packs.

## Run with explicit inputs

```sh
python -m rigor_foundry.discovery_source_cli \
  --root /absolute/capture-directory --manifest manifest.json \
  --max-total-bytes 1048576 --max-file-bytes 262144 \
  --max-sources 32 --max-shards 8 --max-candidates 100 --max-spans 400
```

These are example parser budgets, not policy defaults. All six are mandatory
positive exact integers at most 2**31 - 1. Total bytes include the manifest and
each declared capture once. The validator does not enumerate unrelated files.
Use `DiscoveryLimits` from `rigor_foundry.discovery_source_schema` and
`validate_discovery_sources(root, manifest_name, limits=...)` from
`rigor_foundry.discovery_source_validation` for the equivalent Python API.

Exit zero means declared-snapshot integrity only. Exit two means invalid input;
exit one means unreadable input or unavailable platform support. Failures emit
a bounded content-free diagnostic, never a partial success receipt. The API
raises `DiscoveryValidationError` or `DiscoveryReadError`, respectively.
It never executes source text, follows URLs, searches repositories or writes.

## Capture schema

Every JSON object has exactly the documented fields. Duplicate keys, unsupported
versions/status, extra fields, invalid UTF-8 and nesting deeper than sixteen are
rejected. JSON must not have a BOM. Records have bounded portable identifiers
and lowercase SHA-256 digests.

A manifest contains:

```json
{
  "schema_version": "discovery-source-closure.v1",
  "status": "discovery-only",
  "sources": [
    {"source_id": "source-a", "capture": "source-a.txt",
     "sha256": "<64 lowercase hex digits>", "bytes": 12, "lines": 1}
  ],
  "shards": [
    {"shard_id": "shard-a", "capture": "shard-a.json",
     "sha256": "<64 lowercase hex digits>", "bytes": 300, "candidates": 1}
  ],
  "candidate_count": 1
}
```

Replace the illustrative lengths and digest placeholders with exact values
from the actual captured bytes. Both collections are nonempty.

A shard contains exactly `schema_version`, `status`, `shard_id` and nonempty
`candidates`. Version/status equal the manifest's values. Each candidate has:

```json
{
  "candidate_id": "retain-evidence",
  "statement": "Retain the evidence required by the selected profile.",
  "source_spans": [
    {"source_id": "source-a", "start_line": 1, "end_line": 1,
     "sha256": "<exact span SHA-256>"}
  ]
}
```

Candidate IDs are unique across all shards. A candidate needs at least one
resolved span. Source and shard IDs are unique within their respective domains.
Repeated edges within one candidate are rejected; different candidates may cite
the same bytes. Unused inventory sources are allowed and listed in the receipt;
their presence does not mean their prose was extracted.

Capture filenames match `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`, excluding trailing
dots and Windows reserved device basenames. All are flat filenames under the
explicit absolute root. Each capture name, including the manifest, is allocated
once. Absolute capture paths, nested paths, URI locators and traversal are not
accepted. The root and its components must not be symlinks; captures must be
single-link regular files. This version requires no-follow POSIX descriptor
support, including nonblocking opening to reject FIFOs promptly.

## Exact lines and receipts

Only LF separates source lines. Line numbers are one-based and inclusive.
Original terminators remain in span bytes; CRLF, bare CR, Unicode, a text-source
BOM and an unterminated final line are not normalized. A trailing LF does not
add an extra line. Empty sources have zero lines and cannot support a span.
Both whole-source and span hashes bind the exact original bytes.

A receipt includes the exact manifest digest, sorted source/shard identities
and digests, candidate/span counts, unused source IDs, supplied limits, and a
`receipt_digest` over its canonical body. The assertion class is
`declared-snapshot-integrity-only`. It omits source prose, timestamps and local
paths. Identical bytes and limits reproduce identical stdout. Reformatting JSON
changes the raw capture digest even when its parsed meaning is equivalent.

Reads check per-file stability and close descriptors on all paths. This is not
a filesystem-wide atomic snapshot or trusted acquisition receipt. The caller
owns capture provenance, semantic interpretation and separate policy approval.
Legacy format conversion must preserve unresolved source references rather than
guessing them. Private policy corpora must not become public package fixtures.
