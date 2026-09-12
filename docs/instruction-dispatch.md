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
