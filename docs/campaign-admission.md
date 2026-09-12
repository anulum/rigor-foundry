# Campaign admission boundary

`rigor_foundry.campaign_admission.create_admitted_campaign` wraps the existing
campaign creation workflow in a trusted host-provided admission context. It is
an opt-in integration API, not an activated CLI gate or an authentication service.

Construct a frozen `CampaignCreation` with an absolute repository root and the
same explicit inputs accepted by `create_campaign`: policy path, audit root,
project, campaign ID, actor, expected runs and optional promotion/Git-trust inputs.
The provider receives that exact request before storage or scanning starts.

Supply `admission` from trusted application composition. It must return a context
manager that validates the applicable current authority and runtime facts before
entry, then holds any required synchronization through campaign creation. Failure
to acquire permission must raise; operation exceptions must not be suppressed.
A provider that suppresses failure causes an explicit `RuntimeError`, never a
successful-looking empty return. The wrapper does not cache decisions.

On success the returned path and `AuditCampaign` come from the real existing
workflow and can be read with `campaign_store.load_campaign`. Underlying Git and
filesystem checks still apply. An absolute path avoids ambient current-directory
selection; it is not itself a filesystem identity lock.

## Trust and compatibility limits

Do not install a provider supplied by an untrusted request. A callback, context
manager, role string or successful health check is not evidence of permission.
The host owns authentication, policy resolution, exact effect/target binding and
freshness. This cooperative Python boundary does not sandbox hostile same-process
code, prevent calls to the original local API, or cancel work following revocation
after admission. There is no new serialized grant schema, automatic schedule,
publication permission or implicit CLI cutover.

The focused integration tests use real temporary Git repositories and observe
storage/refusal and release behavior. They do not establish the correctness of an
external policy provider or a complete cross-process enforcement deployment.

## Signed permits

`signed_campaign_admission.SignedCampaignAdmission` implements the lease interface
using an exact-request `SignedCampaignPermit`. Sign its `payload_digest` through
the existing domain-separated Ed25519 message encoder with
`CAMPAIGN_PERMIT_SIGNATURE_DOMAIN`; a report or pack signature cannot substitute.
The digest covers every creation argument, issuer and explicit issue/expiry times.
No signing key, default lifetime or account is embedded in the library.

Trusted host composition supplies a fresh context manager containing
`CampaignAdmissionState`: the current permit, dedicated `OfflineTrustPolicy` for
authorised campaign issuers, and revoked permit payload digests. It also supplies
a trusted timezone-aware clock. The provider verifies the signature, checks the
key at issuance and current admission time, checks the permit interval/revocation,
then yields to the existing campaign operation. A state context that suppresses
admission failure cannot turn it into permission. The context must retain its
required synchronization through the operation; the provider caches no decision.

Never accept issuer policy, clock or state factory from an untrusted request.
Use a dedicated issuer policy: a key trusted for reports is not automatically a
campaign grantor. These are in-process contracts with no added wire parser or
CLI activation. Authentication does not establish truthful runtime capabilities,
complete policy precedence or filesystem identity. Those checks remain host
integration obligations; do not deploy this alone as a complete ecosystem gate.
