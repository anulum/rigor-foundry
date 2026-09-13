# Instruction-scoped dispatch

`instruction_dispatch.dispatch_instruction_action` resolves host-authenticated
instructions before invoking a registered operation. It is a cooperative Python
integration API, not a deployed policy service, sandbox or signed grant parser.

`ActionScope` binds actor, runtime, project, task, effect, exact target and the
provider/account/cost/privacy route. `InstructionScope` selects exact values;
`None` explicitly leaves a dimension unrestricted. Targets are opaque identifiers:
the owning adapter must canonicalise paths and retain filesystem custody. There
is no prefix matching, path expansion or inferred provider fallback.

Supply `InstructionPolicy` from trusted host composition. Its issuer order is
highest-first, and its explicit grantors may issue permission. Documents, roles
and request fields cannot create that authority. Instructions sharing a subject
are resolved by applicable scope, explicit same-subject supersession and issuer
precedence. Equal-authority contradictions and override cycles refuse the affected
action. Independent subjects remain constraints. A surviving `permission` allow
from an authorised grantor is mandatory; absence of a prohibition is not a grant.
Existing audit-profile deny/waiver rules and independent remediation approval are
unchanged. Different action scopes can resolve independently.

Construct an immutable `DispatchRequest` with exact actions, existing `AdapterLock`,
route and payload bytes. A trusted state factory acquires a `DispatchLease` for
that exact request. It must authenticate policy, verify the registered adapter's
effects from the payload, observe current availability and retain resource/target
custody. Matching advertisement is necessary but is not effect verification.
The lease binds the actual handler, not an arbitrary callback supplied by a caller.

Dispatch requires matching advertised and verified adapter locks, identical
verified effects, identical route, and available OS capability. After resolution,
the host's `revalidate` checks current expiry, revocation, resource allowances and
executable/target identity immediately before invocation. The handler receives the
same immutable payload used in preparation. The host holds its lease until the
handler returns or fails. Suppressed errors become an explicit failure, not a
successful empty result. No automatic account or billing fallback is attempted.

## Evidence and limits

Never expose the state factory, policy ordering, grantor set, verified effects or
handler registration as unauthenticated request inputs. This API cannot certify
truthfulness of host assertions, contain hostile same-process code, authenticate
a general signed dispatch grant, enforce arbitrary resource budgets itself or
cancel an already admitted operation. Use the existing native sandbox and trusted
executable custody where applicable. The signed campaign permit remains specific
to campaign creation and cannot authorise these general operations.

Tests exercise actual local file writes and reads, including forbidden writes
leaving bytes unchanged. They verify the in-process composition contract, not a
hosted provider, remote publication or cross-process enforcement deployment.
The documentation gate checks every declaration in this maintained cohort,
including private/nested/test definitions. Presence checks do not prove meaningful
documentation; review still owns that judgement.

The maintained acceptance cohort names all fourteen ratified boundary cases. It
uses real local file bytes and a loopback HTTP service to observe forbidden
transport independently of decision text. These tests establish the cooperative
dispatch contract only; they do not certify a hosted Git provider, production
consumer registration, deployment or rollout.

## Signed operation and policy binding

`signed_instruction_dispatch.dispatch_signed_instruction_action` composes the same
dispatcher with a dedicated `SignedDispatchPermit`. The permit binds
`dispatch_request_digest(request)` and `instruction_policy_digest(policy)`, issuer
and explicit issuance/expiry times. Sign its `payload_digest` using the existing
Ed25519 encoder and `DISPATCH_SIGNATURE_DOMAIN`. Campaign or report signatures
cannot substitute. Request identity includes actual payload bytes by digest and
all effect, adapter and route fields. Policy identity includes every source,
selector, override edge, grantor and the semantically ordered issuer list.

The host supplies a fresh context containing `SignedDispatchState`: its registered
lease, the permit, dedicated `OfflineTrustPolicy` and current revoked permit
payloads. The wrapper first performs existing dispatch checks, then calls the
host's custody revalidation. Immediately afterwards it checks exact bindings,
the real signature and current issuer/permit validity, before invoking the handler.
Its clock and state/trust configuration must not come from untrusted request data.
No default validity interval, cached permission or silent trust fallback exists.

This proves the dedicated issuer approved these exact request and policy bytes.
It does not independently authenticate every referenced policy document or verify
the adapter's effect claims. Registered production providers still own truthful
effects, current resource availability, executable/target custody and isolation.
The signed API adds no wire parser or automatic production consumer cutover.

## Opt-in native audit consumer

`native_dispatch.dispatch_native_audit` is the first concrete consumer of the
signed boundary. A trusted host registers a canonical built-in adapter profile,
canonical source and allocation paths, the exact tracked-content digest, runtime
generation, Git policy, and previously authorised version/audit invocation
identities. `NativeAuditOperation.request` derives every repository read,
workspace write and cleanup, and Git, Bubblewrap, and adapter execution effect;
callers cannot omit one while retaining the same signed payload.

Admission completes before snapshot allocation or any process launch. The same
host lease then compares the actual descriptor-held version and audit identities
and rechecks custody, signature, expiry, revocation, and runtime state immediately
before each process. Only tracked profile inputs enter the explicit host-owned
allocation, and successful return means the unique owned workspace was removed.
The receipt binds the request and policy digests, runtime generation, cleanup
disposition, and the existing source-linked adapter result.

This API is opt-in and does not change the legacy CLI or generic argv adapter.
The existing executor enforces tracked-input, per-file, output, and timeout bounds.
Hosts must enforce any additional CPU, RAM, process, provider, or billing limit
inside their retained state lease, or refuse the operation. This local consumer
does not by itself claim remote publication, provider transport, production
rollout, or completion of the wider tool-authority acceptance programme.
