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

## Candidate anchor schemas

Candidate-anchor schema 1.0 is a strict discriminated union:

- `tracked-blob` binds a canonical path, inclusive line span, scanned Git blob
  identity, and content SHA-256;
- `repository-tree` binds a path locus, fixed state span `1:1`, HEAD tree
  identity, and complete tracked-content SHA-256.

Report schema 1.3 requires one anchor on every candidate and records
`git_object_format`. Scanner version 0.3.0 verifies all anchors against the
inventory that produced the report. Campaign schema 1.5 carries the object
format into independent-run input comparison. Campaign schema 1.8 additionally
binds ignored inventory, campaign purpose, witness requirements, and explicit
inference identity. Earlier report or campaign
records must be regenerated; unknown or mixed anchor fields have no
compatibility fallback.

Repository policy controls source and test roots, production packages,
mandatory audit domains, size registries, enforcement mode, and declared native
adapters. The desired-state API adds typed adopter variables, namespaced custom
controls, applicability decisions, exact standard-pack selections, and
secret-provider references.

## Declared ignored inventory

Policy schema 1.1 accepts an `ignored_inventory` array sorted by
`evidence_id`, `path`, and `capture`. Every declaration contains a unique
portable `evidence_id`, a unique exact normalised repository-relative path,
and either `presence` or `file-sha256`. Globs, absolute paths, parent traversal,
tracked paths, and paths outside Git ignore rules are rejected.

Collection never recursively inventories a directory and never records file
content, symlink targets, environment values, or undeclared paths. Evidence is
limited to `observed`, `missing`, or `unavailable`, the observed entry kind, a
regular-file byte size, an optional SHA-256 for `file-sha256`, and a bounded
reason. No-follow descriptor walks prevent parent or final symlink traversal.
Concurrent mutation or replacement becomes unavailable evidence. Missing and
unavailable observations are evidence gaps, not automatic control failures.

## Git executable trust

Git bootstrap trust is runtime configuration, not repository-controlled policy:
the audited repository cannot choose which executable reads its own index. By
default, RigorFoundry searches the basename `git` only in fixed platform roots,
never in ambient `PATH`. The default supported interval is Git 2.35.2 or newer
and lower than 3.0.0.

Every Git-using CLI command accepts the same controls:

```bash
rigor scan --root /workspace \
  --git-executable /opt/toolchain/bin/git \
  --git-trust-root /opt/toolchain/bin \
  --git-min-version 2.43.0 \
  --git-max-version-exclusive 3.0.0
```

`--git-trust-root` is repeatable and ordered. Roots must be normalised absolute
directories. An absolute executable requires at least one explicit root; a
relative executable must be one basename and is searched only below the roots.
The root, intervening components, and executable must not be symlinks.
The executable must be a single-link regular file; POSIX mode checks also
reject group/world-write, set-user-ID, and set-group-ID bits.
Each Git invocation overrides repository-local `core.fsmonitor` and
`core.hooksPath`. Hooks are redirected to a reserved absent directory below the
selected trust root; if that reserved path exists, execution fails closed.
Execution also fails closed on platforms that cannot execute the already
validated open descriptor.
`campaign-run` must receive the same explicit options used by
`campaign-create`; otherwise frozen Git provenance diverges and the run is
rejected. It must also receive explicit provider, exact-model,
model-correlation-family, and operator identities. These values are evidence,
not labels inferred from a session or agent name. Operator declarations must be
authenticated by the surrounding deployment; the campaign record does not
claim a cryptographic operator signature.

Python callers pass `GitTrustPolicy` through the keyword-only
`git_trust_policy` argument of `scan_repository`, `load_git_inventory`, campaign
workflow functions, ignored-path storage, or TODO promotion. The durable report
records `GitExecutableProvenance`: resolved path, selected root, parsed version,
executable SHA-256, complete versioned trust policy, derived policy SHA-256,
and its own identity digest. Portable policy JSON uses canonical forward-slash
POSIX or Windows absolute paths and can be verified on another host. The trust
root is an operator assertion and must be protected from untrusted writers.
Campaign storage and TODO promotion reproduce the report or campaign identity
before using Git ignore rules; a different policy-compliant binary is still
treated as input divergence.

## Classified coverage residuals

Repository self-governance uses the tracked `coverage-residuals.json` manifest.
It is separate from adopter audit policy because it describes this tool's own
test-evidence boundary, not a finding in the repository being audited.

Each residual must identify one exact source symbol and guard, bind the
symbol's SHA-256, use one of `platform-primitive`, `runtime-invariant`, or
`race-window`, name an accountable owner, cite public regression tests, list
specific revisit triggers, and expire no later than 90 days after review. A
source edit, removed guard, missing test, expired review, unknown field, or
duplicate identifier fails validation.

The manifest also contains preregistered regular-expression searches over
explicit test owners. Their expected result is empty. They currently reject
private production-helper calls, `object.__new__` construction, monkeypatched
production internals, and direct use of the private preflight runner.

Validate the contract directly with:

```bash
rigor residuals-check --root .
```

`python -m tools.audit`, `make audit`, local preflight, and the CI quality job
run the same validator. Residuals never count as covered lines and do not lower
the aggregate branch-coverage threshold.

Repository guard CLIs print only fixed pass/fail status. Precise diagnostic
strings remain available to trusted in-process callers, while validation
exceptions also fail closed without a traceback. Neither enters shared logs,
because repository paths and metadata can be attacker-controlled. The secret
guard additionally replaces every programmatic path with its full SHA-256
identifier.

## Desired-state inputs

A `StandardPack` defines versioned controls, evidence contracts, remediation
contracts, licence and source metadata, a detached signature envelope, and a
content digest. A `ProjectProfile` selects exact pack versions and digests and
records project intent without copying or weakening the pack silently.

Standard-pack schema 1.1, signature-envelope schema 1.0, and pack-verification
schema 1.0 require and bind the `rigor-foundry.standard-pack.v1` signature
domain. Reviewer-attestation schema 2.0 requires
`rigor-foundry.reviewer-attestation.v1`. Both sign the public
`ed25519_signature_message()` encoding: the fixed
`RIGOR-FOUNDRY-ED25519\0v1\0` prefix, a two-byte big-endian domain length, the
ASCII domain, and the 32 payload-digest bytes. Earlier pack schema 1.0,
unversioned reviewer records, missing domains, and raw-digest signatures must be
regenerated and re-signed; the parser and verifier provide no legacy fallback.

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
process-tree termination, disabled nested user namespaces, and a streaming
output hard cap. Native execution currently requires the Debian-family
`/usr/bin/bwrap` and `/usr/bin/dpkg-query` surfaces, a root-owned single-link
launcher and query executable without group/world-write, set-user-ID, or
set-group-ID bits, Bubblewrap version 0.9.0 or newer and lower
than 1.0.0, an installed `bubblewrap` package,
and every option named by `BubblewrapCompatibilityPolicy`. Missing dpkg
association, an unsupported version, option drift, or identity change during
an adapter run fails closed. Gate and campaign records embed the complete
policy and observed secret-free package-database evidence. The dpkg fields do
not prove repository signatures or installed-payload checksums; the executable
SHA-256 identifies the bytes inspected and executed.

Conditions use a bounded declarative expression tree. They can read declared
context values and combine supported comparisons and boolean operations; they
cannot import code, invoke a shell, access the network, or mutate the audited
repository. Missing references and malformed or oversized expressions fail
closed.

Profile resolution verifies exact pack pins and actual domain-separated
Ed25519 signature bytes against an explicit public-key trust store, resolves
typed assignments, applies overlays and finite waivers, retains contradictions,
and emits an `EffectiveProfileLock`. The verification record binds the key,
signature domain, signature, pack, and trust-store digests; a caller-supplied
`valid` label is never accepted. A lock is ready only when required inputs are
complete and no blocking contradiction remains. Stronger targets and explicit
denial win over unauthorised weakening.

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
Campaign creation validates and prepares that ignored storage root before
freezing the repository input projection, so the tool's own durable storage
cannot create a post-freeze ignored-inventory divergence.

Diagnostic campaigns may use one model witness. Promotion campaigns require at
least two expected runs, at least two correlation witnesses, and at least two
declared operator identities. Repeated runs from one model family or the same
provider/exact-model pair remain useful for repeatability evidence but join one
transitive correlation component and count as one promotion witness.
Witness schema 1.2 stores each provider/exact-model pair and forbids families
or exact pairs from appearing in more than one durable comparison component.

Configuration schemas are versioned. Unknown schema versions, contradictory
variables, unavailable adapters, and unresolved controls remain explicit
errors or evidence gaps.

The desired-state records are currently a Python API. Stable CLI profile
import/export and an authorised remediation executor remain roadmap work.
