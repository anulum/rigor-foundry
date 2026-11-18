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

## Offline scan with signed distribution evidence

`rigor scan-provenance` binds separately versioned provenance to the
existing static audit report. The output contains the unchanged
`audit_report` object and a `rigor.provenance-scan.v1` provenance companion. The companion binds the
audit digest, Git head and tree, unchanged tracked lock blob, caller-profile
SHA-256 and individual pieces of observed evidence. The regular `rigor scan`
entry point keeps its existing output contract.

Local evidence uses bounded, stable single-link reads on POSIX and local
NTFS. Each implementation retains the relevant path components while it reads.

Provide a local schema 1.0 profile from an independently authenticated
source and its expected SHA-256:

```sh
rigor scan-provenance --root /path/to/project \
  --profile /path/to/evidence/profile.json \
  --profile-sha256 "$EXPECTED_PROFILE_SHA256" \
  --output /path/to/evidence/scan-provenance.json
```

A profile has `schema_version`, `lock`, `distributions` and `scorecard`
fields. The lock names a tracked UTF-8 Python requirements file whose bytes
match the committed blob. Set `eol=lf` in `.gitattributes` for a lock committed
with LF line endings so a Windows checkout retains those bytes.
Each selected distribution specifies these values:

| Field | Meaning |
| --- | --- |
| `project`, `version`, `sha256` | Pinned package and authorised distribution hash from the tracked lock |
| `artifact` | Exact distribution filename under the profile directory |
| `predicate` | Expected PyPI Publish v1 or SLSA Provenance v1 predicate URI |
| `identity`, `issuer` | Independently expected signing certificate identity and OIDC issuer |
| `source_commit` | Exact GitHub source commit from the signing certificate's source repository digest, required for SLSA and optional for PyPI Publish |
| `bundle`, `bundle_sha256` | Retained producer evidence and its expected digest |
| `root`, `root_sha256` | Explicit local Sigstore trust material and its expected digest |

Install the optional `provenance` extra for signature verification.
For a source checkout, provision the interpreter using the bootstrap
and provenance locks before installing the repository:

```sh
python -m pip install --require-hashes -r requirements/bootstrap.txt
python -m pip install --require-hashes --no-build-isolation -r requirements/provenance.txt
python -m pip install --no-build-isolation --no-deps .
```

For a Cryptography source build on Intel macOS, provision the Xcode command-line
tools, Rust and OpenSSL before installing the locks. Set `OPENSSL_DIR` to
the local OpenSSL installation when the compiler cannot discover it.
The bootstrap lock installs the Python build requirements before pip
builds the hash-locked source distribution.

The ordinary native CI matrix exercises the installed provenance command and
the signed distribution fixtures on Windows and Intel macOS with the same
hash-locked verifier profile.

The verifier uses `sigstore 4.5.1` and `pypi-attestations 0.0.31`
with the explicit local trust input, without fetching metadata. The supported
PyPI Publish profile uses a provenance object holding one signed
attestation with a single distribution subject. The SLSA profile uses
one Sigstore DSSE bundle and matches the required subject among distinct
signed names. Verification checks the distribution name, version, hash,
predicate and identity before returning verified statement evidence.

Use null for all four bundle/root fields when the evidence is unavailable.
The companion reports unavailable when the signed evidence or optional
verifier is absent, unsupported for other predicates, and refused when
supplied evidence cannot be verified. Profiles with inconsistent lock hashes, a changed
repository snapshot, or invalid Scorecard selection fail the command.

Set `scorecard` to null or supply `path`, `sha256`, `repository` and
producer `version`. The importer compares the retained response with the
current scan commit and emits each named check. Unavailable observations
are explicit and scores remain probe evidence. The output is informational
and does not select, adjudicate or promote audit candidates.
