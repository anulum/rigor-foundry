# Verified external source provenance

RigorFoundry schema 1.0 records and verifies exact externally cited advisories,
versions, standards, and content digests. It is deliberately split into four
content-addressed records:

1. `ExternalSourceClaim` states the exact subject, predicate, expected value,
   HTTPS source, and extraction procedure.
2. `SourceRetrievalPolicy` declares allowed hosts, redirect boundaries,
   timeout, byte limit, media types, and freshness.
3. `SourceCapture` binds retained raw response bytes to acquisition metadata,
   the retrieval policy, and the declared retriever identity.
4. `SourceVerification` exists only after deterministic offline verification
   succeeds against those exact retained bytes.

Changing a claim changes its verification. Changing retrieval policy changes
the capture and therefore its verification. These relationships are registered
in the [digest dependency graph](digest-dependencies.md).

## Epistemic boundary

A canonical HTTPS URI and response digest prove which bytes were reviewed.
They do not prove publisher authorship, uncompromised DNS or TLS, or universal
truth. `SourceVerification.authority_scope` is consequently fixed to
`retrieval-policy-only`. A genuine publisher signature requires a separate
signature-verification record; TLS capture must never be represented as one.

The capture command performs no network access. It records response bytes
already retained by an explicitly authorised retriever. Network authority,
proxy policy, private-address rejection, credentials, decompression, and
redirect execution therefore remain outside deterministic offline
verification. The record preserves declared retriever name, semantic version,
and executable SHA-256 without inventing executable attestation.

No claim or verification grants permission to modify a repository, accept a
risk, suppress a vulnerability, or promote an audit candidate.

## Claim methods

`advisory`, `version`, and `standard` claims require `json-pointer` extraction.
The selector must be a non-empty RFC 6901 pointer resolving to one exact JSON
scalar. Parsing is UTF-8 only, rejects non-finite numbers and duplicate object
keys, and preserves scalar types: JSON `true` cannot satisfy numeric `1`.

`content-digest` claims require predicate `sha256`, method
`whole-payload-sha256`, an empty selector, and one lowercase SHA-256 value.
They verify raw retained bytes without parsing or redistributing licensed or
paywalled content.

## Retained-payload workflow

Record one retained response:

```bash
rigor source-capture \
  --policy source-policy.json \
  --payload advisory-response.json \
  --requested-uri https://advisories.example.test/CVE-2026-52869.json \
  --final-uri https://advisories.example.test/CVE-2026-52869.json \
  --redirect-count 0 \
  --http-status 200 \
  --media-type application/json \
  --retrieved-at 2026-07-17T08:00:00Z \
  --retriever-name curl \
  --retriever-version 8.10.1 \
  --retriever-executable-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output source-capture.json
```

Verify offline against the same payload:

```bash
rigor source-verify \
  --claim source-claim.json \
  --capture source-capture.json \
  --payload advisory-response.json \
  --verified-at 2026-07-17T08:30:00Z \
  --verifier auditor/one \
  --output source-verification.json
```

The payload reader performs component-wise no-follow traversal, requires a
single-link regular file, derives size and SHA-256 from one stable descriptor
pass, enforces the policy byte limit, and fails closed if the file changes.
Output parents must already exist.

## Public Python API

These top-level imports are provisional:

```python
from rigor_foundry import (
    ExternalSourceClaim,
    SourceCapture,
    SourceRetrievalPolicy,
    SourceVerification,
    read_source_payload,
    source_provenance_to_json,
    verify_external_source,
)
```

Use `build`, `record`, `from_dict`, or `verify_external_source`; direct
success-shaped dataclass construction is unavailable. Parsers require exact
fields, recompute derived digests, reject unsupported schema versions, and
reject source URI, verified-value, type, or freshness contradictions across a
verification record. `SourceVerification.from_dict` cannot replay extraction
because records omit retained payload bytes. At an evidence trust boundary,
retain the payload and call `verify_external_source` again; an internally
consistent parsed record alone is not extraction proof.
