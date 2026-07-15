# Configuration

Without an adopter policy, RigorFoundry uses portable defaults and emits a
governance candidate explaining that the repository-specific contract is
missing.

Policy discovery is deterministic:

1. an explicit repository-relative CLI path;
2. `rigor-foundry-policy.json`;
3. `config/rigor-foundry/policy.json`.

The selected policy must be a tracked, non-symlink UTF-8 file inside the
audited repository. External, parent-relative, ignored, and symlinked policy
inputs fail closed rather than silently controlling the audit.

Repository policy controls source and test roots, production packages,
mandatory audit domains, size registries, enforcement mode, and declared native
adapters. The desired-state API adds typed adopter variables, namespaced custom
controls, applicability decisions, exact standard-pack selections, and
secret-provider references.

## Desired-state inputs

A `StandardPack` defines versioned controls, evidence contracts, remediation
contracts, licence and source metadata, a detached signature envelope, and a
content digest. A `ProjectProfile` selects exact pack versions and digests and
records project intent without copying or weakening the pack silently.

Project variables support `string`, `integer`, `number`, `boolean`, and
`string-list` values. Every variable declares project, environment, or control
scope and public, internal, or secret sensitivity. Definitions can constrain
allowed values, regular-expression matches, numeric ranges, and list sizes.
Assignments and definitions are digest-bound so a stale value cannot be
mistaken for the current contract.

Secret values do not belong in profiles or effective locks. A secret variable
contains only an opaque provider, reference, and version. Secret resolution is
an authorised adapter responsibility and the resulting bytes must not enter
reports, plans, logs, or public output.

Declared native adapters are executable policy, not passive configuration.
`gate` and `campaign-run` refuse to run them unless the operator supplies
`--allow-native-audits`. Consent still uses a fixed credential-free
environment, a no-network read-only bubblewrap sandbox, mandatory timeouts,
process-tree termination, and a streaming output hard cap.

Conditions use a bounded declarative expression tree. They can read declared
context values and combine supported comparisons and boolean operations; they
cannot import code, invoke a shell, access the network, or mutate the audited
repository. Missing references and malformed or oversized expressions fail
closed.

Profile resolution verifies exact pack pins and actual Ed25519 signature bytes
against an explicit public-key trust store, resolves typed assignments, applies
overlays and finite waivers, retains contradictions, and emits an
`EffectiveProfileLock`. The verification record binds the key, signature, pack,
and trust-store digests; a caller-supplied `valid` label is never accepted. A
lock is ready only when required inputs are complete and no blocking
contradiction remains. Stronger targets and explicit denial win over
unauthorised weakening.

Every weakening waiver is exact: control, field, previous value, new value,
and active time window must match. Risk acceptance uses a dedicated
`assessment-status` waiver from `fail` to `accepted-risk`; its identifier is
kept separate from applicability, target, and mode waiver identifiers. Those
other waiver classes cannot authorise an accepted-risk assessment.

Evidence names an exact `AdapterLock` digest whose declared domains include the
control domain. Reviewer attestations carry an Ed25519 signature over the exact
assessment body, identity, decision, and validity window. Clearance reverifies
that signature against an explicit reviewer trust store and binds that store's
digest into the assessment before counting distinct reviewer identities and
keys. Remediation and rollback argv must match the exact command digest recorded
in their adapter locks.

Local campaign records, review ledgers, and optional TODO promotion default to
`.rigor/`. The adopter must keep that directory Git-ignored; commands that
would write there fail closed when the ignore boundary is absent.

Configuration schemas are versioned. Unknown schema versions, contradictory
variables, unavailable adapters, and unresolved controls remain explicit
errors or evidence gaps.

The desired-state records are currently a Python API. Stable CLI profile
import/export and an authorised remediation executor remain roadmap work.
