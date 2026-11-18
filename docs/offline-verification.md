# Offline evidence verification

`rigor verify` is the stable free verification boundary for signed
RigorFoundry evidence. It reads only caller-supplied local files. It contains
no network client, service discovery, telemetry, fleet authority, or paid
service dependency.

```bash
rigor verify \
  --bundle evidence-bundle.json \
  --trust-policy trust-policy.json \
  --at 2026-07-20T12:00:00Z \
  --output verification-result.json
```

`--at` is mandatory and must be UTC. An explicit evaluation time makes expiry
and revocation results replayable instead of depending on an ambient clock.
Without `--output`, the result is written to stdout. Output creation is
exclusive and never overwrites an existing path.

The command returns:

- `0` only when every bundle entry is `verified`;
- `1` for a parseable result containing `invalid`, `stale`, or `unavailable`
  evidence;
- `2` for malformed, unsafe, oversized, or unsupported input.

## Use verification in CI

On a Linux runner, install the RigorFoundry wheel using the release and hashes
approved for the repository. Stage the evidence bundle and the separately
approved trust policy as local files. Supply the UTC evaluation time from the
gate or evidence-replay request.

```bash
set -eu
attempt_dir="$(mktemp -d "${RUNNER_TEMP}/rigor-verify.XXXXXX")"
rigor verify \
  --bundle "$RIGOR_EVIDENCE_BUNDLE" \
  --trust-policy "$RIGOR_TRUST_POLICY" \
  --at "$RIGOR_VERIFY_AT" \
  --output "$attempt_dir/verification.json"
```

Make later CI steps depend on verification success. Retain the result with the
identity of the bundle, trust policy and evaluation time. Give each attempt a
fresh output path so an invalid or stale run preserves the previous verified
receipt.

For evidence replay, use the retained bundle and trust policy with the original
evaluation time and compare the new result with the retained receipt. For a
rollback decision, verify the selected evidence against the current approved
trust policy at the rollback evaluation time and apply the operator's rollback
policy. The repository's distribution workflow exercises these file and exit
boundaries through the installed wheel outside the checkout.

## Caller-selected trust

The trust policy is a separate input, not part of the untrusted evidence
bundle. Replacing the bundle therefore cannot silently replace its trusted
keys. Policy schema 1.0 binds each unique Ed25519 key and public-key digest to
`valid_from`, `valid_until`, and an optional `revoked_at` instant. Duplicate key
IDs and public-key aliases are rejected.

Verification distinguishes:

- `unknown`, `not-yet-valid`, and `revoked` keys as invalid;
- an expired key as stale evidence;
- a key that was not active at the evidence signing time as invalid.

Report, review, and model-alias signatures bind a signing time. The existing
StandardPack signature has no signing-time field, so pack verification proves
the native signature under a key active at the explicit evaluation time; it
does not reconstruct historical key status.

## Bundle records

Bundle schema 1.0 contains a sorted, unique set of evidence entries. Every
available entry embeds its strict production protocol document and exact
digest. Every unavailable entry preserves the expected digest and a non-empty
reason without inventing document bytes.

Supported kinds are:

| Kind | Verification contract |
| --- | --- |
| `audit-report` | Reparse the complete report and every nested digest, then verify a time-bounded signature in `rigor-foundry.audit-report.v1`. |
| `review` | Reparse the review and reviewer attestation, bind the review digest and decision, and verify the existing reviewer-attestation domain and expiry. |
| `standard-pack` | Reparse the pack, controls, native PackSignature, payload digest, and the existing standard-pack domain. |
| `model-aliases` | Reparse provider, exact-model, family, operator, and run identities; recompute transitive alias collapse; then verify `rigor-foundry.model-aliases.v1`. |

The review decision mapping is fixed: `valid` to `pass`, `invalid` to `fail`,
`accepted-boundary` to `accepted-risk`, and `needs-evidence` to
`needs-evidence`. Contradictory signed decisions are invalid.

Report and model-alias envelopes sign a canonical payload digest containing
the schema, evidence kind, Ed25519 algorithm, protocol domain, key ID, exact
artifact digest, signing time, and expiry. A signature from another domain
cannot be relabelled or replayed.

The aggregate report is itself content-addressed. It binds the evaluation
time, selected trust-policy digest, input bundle digest, ordered per-evidence
results, bounded details, aggregate status, and report digest. Status
precedence is `invalid`, `stale`, `unavailable`, then `verified`; partial
evidence can never be upgraded.

## Input boundary

Bundle and trust-policy inputs must be single-link regular files opened with
no-follow semantics. Symbolic links, hard links, concurrent identity changes,
invalid UTF-8 or JSON, and documents above 16 MiB fail closed. This is a local
file-verification boundary, not a repository mutation command.

## Assurance boundary

A verified result proves only that the supplied bytes satisfy the declared
schemas, digests, signatures, key lifecycle, expiry, review binding, and alias
relations under the caller-selected trust policy. It does not prove:

- that a report is current for a live repository or that its candidates are
  defect verdicts;
- that the selected trust policy is authoritative for another organisation;
- model independence beyond the explicit correlation declarations;
- remediation success, fleet admission, regulatory conformity, or universal
  software safety.

Assurance campaigns, enforcement, fleet views, and remediation authority stay
outside this free verification path.
