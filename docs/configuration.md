# Configuration

Without an adopter policy, RigorFoundry uses portable defaults and emits a
governance candidate explaining that the repository-specific contract is
missing.

Policy discovery is deterministic:

1. an explicit CLI path;
2. `rigor-foundry-policy.json`;
3. `.rigor/policy.json` for ignored local policy;
4. `config/rigor-foundry/policy.json`.

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

Conditions use a bounded declarative expression tree. They can read declared
context values and combine supported comparisons and boolean operations; they
cannot import code, invoke a shell, access the network, or mutate the audited
repository. Missing references and malformed or oversized expressions fail
closed.

Profile resolution verifies exact pack pins and detached signature evidence,
resolves typed assignments, applies overlays and finite waivers, retains
contradictions, and emits an `EffectiveProfileLock`. A lock is ready only when
required inputs are complete and no blocking contradiction remains. Stronger
targets and explicit denial win over unauthorised weakening.

Every weakening waiver is exact: control, field, previous value, new value,
and active time window must match. Risk acceptance uses a dedicated
`assessment-status` waiver from `fail` to `accepted-risk`; its identifier is
kept separate from applicability, target, and mode waiver identifiers. Those
other waiver classes cannot authorise an accepted-risk assessment.

Evidence names an exact `AdapterLock` digest whose declared domains include the
control domain. Reviewer attestations bind the exact assessment body and count
distinct reviewer identities and distinct keys. Remediation and rollback argv
must match the exact command digest recorded in their adapter locks.

Local campaign records, review ledgers, and optional TODO promotion default to
`.rigor/`. The adopter must keep that directory Git-ignored; commands that
would write there fail closed when the ignore boundary is absent.

Configuration schemas are versioned. Unknown schema versions, contradictory
variables, unavailable adapters, and unresolved controls remain explicit
errors or evidence gaps.

The desired-state records are currently a Python API. Stable CLI profile
import/export and an authorised remediation executor remain roadmap work.
