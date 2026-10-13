# Dispatch permit candidates

The provisional module-level Python API
`rigor_foundry.instruction_dispatch_permit_v2` parses and verifies one signed
candidate decision. Its wire schema is `instruction-dispatch-permit.v2.1` and
its signature domain is `rigor-foundry.instruction-dispatch-permit.v2.1`.
Legacy v1 and earlier v2 domains are refused. The named schema declaration is
version-pinned in the provisional schema inventory; the frozen 1.0 contract,
package-level exports and CLI remain unchanged.

## Public API

| Surface | Responsibility |
| --- | --- |
| `RuleChainV2PermitTrustRoles.build(chain=..., permit_issuers=...)` | Rebuild caller-selected policies and require six distinct signing roles. |
| `DispatchPermitBodyV2.from_dict(value)` / `to_dict()` | Validate the exact body and canonical payload digest. |
| `SignedDispatchPermitV2.build(body=..., signature_hex=...)` | Bind external signature bytes to a rebuilt body and envelope digests. |
| `SignedDispatchPermitV2.from_dict(value)` / `to_dict()` | Parse exact wire fields or export retained fields. |
| `verify_signature(roles=..., now=...)` | Rebuild the envelope and policies, then check the actual Ed25519 signature and key lifecycle with caller-supplied UTC time. |

`build` and `from_dict` reject invalid structure with `ValueError`.
Signature verification returns `False` for invalid candidate values, reused
roles, wrong signature domain, inactive issuer or an invalid time window.
Envelope export rechecks the body; complete envelope validation occurs in
`from_dict` and `verify_signature`, including directly constructed instances.

## Exact signed decision

The body contains exactly these fields:

- `schema_version`, `object_kind`, `signature_domain`, `algorithm`, `signer_role`;
- `permit_id`, `key_id`, `issued_at`, `not_before`, `expires_at`;
- `lock_digest`, `rule_projection_digest`, `request_digest`,
  `grant_snapshot_digest`, `current_state_proof_digest`, `adapter_custody_digest`,
  `route_digest`, `effect_target_digest`, `effect_operations_digest`,
  `operations_digest`.

The constants are respectively `instruction-dispatch-permit.v2.1`,
`instruction-dispatch-permit`, the domain above, `ed25519` and `permit-issuer`.
The permit ID must be canonical UUID text, excluding all-zero and all-one IDs.
Every decision digest is a lowercase 64-character SHA-256 representation.
No unknown or missing fields receive defaults.

The signed envelope adds `payload_digest`, `signature_hex`,
`signature_digest` and `permit_digest`. The signature is 64 bytes represented
by 128 lowercase hex characters. Digests bind canonical body and envelope
bytes; parsing their consistency does not establish signature validity.

## Six separate policies and bounded time

The permit issuer must be distinct from pack issuer, project selector, lock
resolver, semantic author and semantic reviewer. Reuse is refused by both key
ID and public key bytes, including a semantic-author key enrolled under a new
permit ID. Verification repeats role composition, so directly constructing a
role dataclass cannot bypass separation. The underlying chain also retains its
semantic author/reviewer identity checks.

All body timestamps use canonical UTC representations. Issuance cannot follow
the start; the start must be within five seconds of issuance. The positive
validity window is at most 300 seconds. Verification requires
`issued_at <= not_before <= now < expires_at` and an active issuer at issuance,
start and the supplied current time. The expiry endpoint is excluded.

A consumer with an externally signed wire candidate and explicitly selected
policies can use:

```python
from rigor_foundry.instruction_dispatch_permit_v2 import (
    RuleChainV2PermitTrustRoles,
    SignedDispatchPermitV2,
)

roles = RuleChainV2PermitTrustRoles.build(
    chain=selected_chain_policies,
    permit_issuers=selected_permit_issuer_policy,
)
candidate = SignedDispatchPermitV2.from_dict(signed_wire_mapping)
valid_signature = candidate.verify_signature(roles=roles, now=selected_utc_time)
```

The names supplied to this example are consumer inputs. The library does not
select policies, enroll keys, produce signatures or authenticate the clock.

## Host admission remains separate

A valid signature binds the supplied decision digests without proving that
they describe the current host. A qualified host must select protected trust
and current state, authenticate its own clock, verify applicability and
atomically consume the permit ID before any registered effect. This candidate
API performs no handler execution and supplies no admission or consumption
method. The [selected dispatch applicability API](selected-dispatch-applicability.md)
and [permit consumption ledger](permit-consumption-ledger.md) are separate
components; this module does not compose an executable dispatch path.
