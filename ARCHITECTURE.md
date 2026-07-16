# Architecture

## System boundary

RigorFoundry is a local-first Python library and CLI. Its core input is a Git
repository path. The portable scanner does not require network access and does
not modify the audited repository.

The executable boundary is narrow:

```text
CLI/API
  -> Git inventory
  -> portable candidate collectors
  -> content-addressed report
  -> evidence review
  -> enforcement or explicit promotion
```

Independent campaigns wrap this path with frozen inputs, per-run attestations,
append-only ignored storage, and disagreement comparison.

## Responsibilities

### Inventory

`git_provenance.py` owns a separate bootstrap trust boundary for Git. It never
uses the ambient `PATH`: a basename is searched only below ordered, explicit
trust roots, while an absolute executable must already be contained by a
declared root. Roots, path components, and the executable must not be
symlinks. Multi-link executables are rejected; POSIX mode checks also reject
group/world-write, set-user-ID, and set-group-ID bits. The runner binds the
resolved path, selected root, semantic version,
SHA-256 executable digest, complete versioned trust policy, and derived policy
digest, then revalidates file
identity and bytes before and after every command. Unsupported versions and
replacement fail closed. POSIX hosts with `/proc/self/fd` or `/dev/fd` execute
the already validated open descriptor, preventing a concurrent pathname swap
from selecting replacement bytes; platforms without a descriptor execution
path fail closed. Every repository-facing invocation overrides
`core.fsmonitor` to `false` and redirects `core.hooksPath` to a reserved absent
path below the protected trust root, so repository-local configuration cannot
execute a monitor or hook during inventory. If that reserved path exists, the
runner fails closed.

Every snapshot and execution descriptor is opened by walking absolute path
components relative to already opened directories with no-follow semantics.

`git_inventory.py` uses that runner to resolve the repository root, HEAD, tree,
Git object format, branch, tracked paths, dirty tracked paths, symlinks,
gitlinks, binary content, content digests, and the Git blob identity of the
exact bytes scanned. A dirty worktree file is hashed with Git's canonical
`blob <size>\0<payload>` framing without writing an object, so candidate
evidence cannot attest a stale index blob. Regular content is opened without
following symlinks; one descriptor and one pass derive both SHA-256 and Git
object identity. Exact byte count, descriptor metadata, and pathname identity
must remain stable through the read or inventory construction fails. Container
ownership mismatch is handled with a process-local `safe.directory` limited to
the explicit audited root after discovery. Global and system Git configuration,
credentials, terminal prompts, replacement objects, optional locks, and
ambient `GIT_*` variables are excluded
from the plumbing environment. Repository-local filesystem monitors and hooks
are disabled per invocation; Git configuration is never changed persistently.
Missing Git state and unsafe path states fail closed.

### Candidate collection

- `architecture.py` collects Python import-cycle, layer, facade, ownership, and
  duplication signals.
- `polyglot_architecture.py` collects relative-cycle and dedicated-test-owner
  signals for non-Python tracked languages.
- `godfiles.py` collects responsibility-size candidates and policy-registry
  drift without equating line count with a defect.
- `test_authenticity.py` identifies skips, exclusions, private-helper testing,
  assertion gaps, and production-surface replacement signals.
- `domains.py` reports missing applicability decisions and missing native
  evidence across mandatory audit domains.

Every signal is a candidate. None is permission to edit code.

`candidate_anchor.py` owns the strict candidate-evidence boundary:

- `TrackedBlobAnchor` binds one canonical repository path, an inclusive line
  span, the Git blob identity of the exact scanned bytes, and their SHA-256.
- `RepositoryTreeAnchor` binds one repository-relative locus to the exact HEAD
  tree plus the complete tracked-content SHA-256. It represents missing policy,
  missing registries, missing test ownership, gitlinks, and other
  repository-wide or negative-search state without inventing a blob.
- Candidate identifiers bind the complete anchor. The scanner verifies every
  anchor against the same inventory before building report schema 1.2.
- Human-readable evidence is whitespace-normalised and capped at 512 UTF-8
  bytes. Large cycle and duplicate-owner sets retain their count, full set
  SHA-256, and a deterministic bounded prefix.

Cross-file findings use a deterministic primary blob anchor while the report's
tracked-content digest binds the complete inventory participating in the
finding. Negative searches use repository-tree anchors because their evidence
depends on the absence of a matching tracked owner, not only on source bytes.

The portable inventory is deliberately Git-tracked-only. A rule may reason
about the tracked tree, but it must not infer that an ignored or untracked
artefact does not exist. Any control whose meaning depends on that wider local
reality must consume the explicit policy-declared ignored inventory or remain
`needs-evidence`; tracked-only absence cannot become a failure verdict.
`ignored_inventory.py` validates exact non-tracked Git-ignored paths, walks
parents and final entries with no-follow descriptors, and emits content-free
`observed`, `missing`, or `unavailable` evidence. Missing or unavailable
evidence is not itself a failed control. Concurrent replacement or mutation
fails closed as unavailable evidence and can never produce a mixed digest.

### Evidence records

`rules.py` defines the versioned portable rule registry.
`audit_primitives.py` owns protocol versions, canonical digests, strict field
validators, and shared type contracts. `candidate_anchor.py` defines candidate
and anchor records. `models.py` defines policy, report, adapter, and review
records while preserving the original public primitive imports. Callers must
verify digests during load; silent repair is not permitted. Report schema 1.3
includes `GitExecutableProvenance`, the Git object format, ignored-inventory
evidence, and strict anchored candidates; changing any bound input changes the
report digest. Review-ledger
schema 1.0 is independent and remains unchanged.
`digest_dependencies.py` publishes schema 1.2 of the machine-readable graph of
unconditional identity bindings and its own canonical digest. The graph
includes ignored inventory, Git provenance, and toolchain identities in
addition to the tracked inventory, policy, rule-pack, desired-state, report,
review, campaign, comparison, task, and closure records. Policy and review
records expose one canonical identity each. Rule-pack version 1.1.0 binds its
schema, registry version, ordered
definitions, and definition fields into the pack digest. Conditional
comparison inputs and deliberate stable non-edges are documented explicitly
rather than presented as full bindings.

### Review, enforcement, and promotion

`review.py` validates reviewer identity, decision state, evidence, timestamps,
report binding, and duplicate prevention. Promotion rescans the repository and
rejects changed HEAD, content, policy, Git provenance, ignored evidence, or
candidate identity.

`enforcement.py` supports observe, ratchet, and zero modes. A command-line mode
may strengthen but cannot weaken the repository policy.

### Native audit adapters

`adapters.py` executes only declared argv. External executables are resolved
before execution; the `{python}` token preserves the active virtual-environment
launcher so native controls cannot silently escape the locked toolchain.
Shells are disabled, timeouts are mandatory, outputs are bounded, and results
include executable and input identity. `sandbox_provenance.py` defines the
versioned Bubblewrap compatibility and dpkg-database association record;
`trusted_executable.py` performs no-follow component walks, descriptor-pinned
execution, streaming output bounds, deadlines, and process-group termination.

### Independent campaigns

`campaign_identity.py`, `campaign_evidence.py`, `campaign_models.py`,
`campaign_inputs.py`, `campaign_store.py`, `campaign_workflow.py`,
`campaign_compare.py`, and `campaign_promotion.py` freeze campaign inputs,
inference identities, Git and sandbox provenance, independent toolchains, and
limitations, and preserve disagreement. Campaign schema 1.7 requires every run
to reproduce the complete
frozen input projection: repository root, HEAD, tree, branch, tracked-content
identity, Git object format, dirty paths, tracked-file count, policy, rule pack,
scanner, required domains, Git provenance, and toolchain. One canonical validator is called by
attestation construction, storage, durable reload, and comparison; a different
trusted binary or omitted adapter is divergence, not an equivalent unrecorded
substitution. The ignored-storage check that persists a campaign, run, or
comparison must also reproduce that frozen identity.
Majority agreement is not converted into truth.

Distinct session or agent labels do not prove independent inference. Each run
attestation binds the provider, exact model, correlation family, and operator.
Runs are joined into one witness transitively when they share either a declared
correlation family or the same provider and exact model. A changed family label
therefore cannot multiply one exact model into independent evidence. Promotion
campaigns require at least two resulting witnesses and at least two declared
operators. Operator labels are retained evidence, not cryptographic identity
proof; deployments must authenticate who may submit them. Promotion reloads
and reconstructs the durable comparison and
requires the selected report and review digests to be members of that exact
eligible comparison.

### Classified coverage residuals

`coverage_residuals.py` validates the tracked
`coverage-residuals.json` contract. A residual is permitted only for an
explicit fail-closed race window, platform primitive, or runtime invariant
that cannot be exercised honestly through the supported public boundary. Each
entry binds the exact owning symbol digest and guard text, names public
regressions around the boundary, records an owner and concrete revisit
triggers, and expires within 90 days.

The same manifest preregisters negative searches that prohibit private
production-helper calls, `object.__new__` construction, and monkeypatched
production internals in the security-sensitive owner tests. Repository audit,
local preflight, and CI validate the manifest. Residuals are visible technical
debt, not coverage credit, waivers, or permission to lower the aggregate CI
threshold.

## Write boundary

The `scan`, review-template validation, and gate paths are read-only unless an
output path is explicitly supplied. Finding promotion requires `--apply` and
writes only the explicitly selected canonical TODO. Campaign writes require a
Git-ignored audit root and use symlink-safe atomic storage.

No command may write credentials, secret variable values, or opaque aggregate
scores into public output.

## Target profile model

The typed desired-state API separates:

```text
StandardPack
  + ProjectProfile
  -> EffectiveProfileLock
  + observed evidence
  -> ControlAssessment
  + declared target
  -> TargetGap
  -> RemediationPlan
```

Conditions are bounded and side-effect-free. Custom procedures are declarative
dependency graphs of argv-only adapter steps. Pack sources, licences,
signatures, and digests are locked. Unsupported evidence remains
`needs-evidence` or `blocked`.

### Signature domains

Ed25519 signs one versioned binary message, never the bare 32-byte payload
digest:

```text
ASCII("RIGOR-FOUNDRY-ED25519") || 0x00 || ASCII("v1") || 0x00
|| uint16_be(len(domain)) || ASCII(domain) || bytes.fromhex(payload_digest)
```

The two accepted domains are `rigor-foundry.standard-pack.v1` and
`rigor-foundry.reviewer-attestation.v1`. The domain length prefix makes the
encoding unambiguous, and both protocol payloads also bind their exact domain.
Using one public key in both protocols therefore does not make either
signature valid in the other protocol.

The standard-pack envelope is schema 1.1 with a pack-signature envelope at
schema 1.0; its external verification evidence is also schema 1.0 and binds the
signature domain. Unchanged nested control, evidence, and remediation records
remain at schema 1.0. Reviewer attestations are schema 2.0. Earlier pack schema
1.0, unversioned reviewer records, envelopes without a domain, and signatures
over a raw digest are rejected. Migration requires regenerating the canonical
payload digest and signing the framed message; there is no legacy verification
fallback.

`model_primitives.py` owns typed variables, constraints, sensitivity labels,
and opaque versioned secret references. `condition_language.py` owns the
bounded, non-executable condition tree. `standard_pack.py` defines versioned
controls and their evidence and remediation contracts. `project_profile.py`
records adopter intent, exact pack selections, overlays, applicability, and
finite authorised waivers.

`profile_resolution.py` combines those inputs into the records in
`effective_profile.py`. Resolution is fail-closed: exact pack pins must match,
secret material is never resolved into the lock, deny and stronger targets
cannot be silently weakened, expired waivers do not apply, and contradictions
remain first-class evidence.

`control_assessment.py` binds outcomes to one effective lock, fresh evidence,
exact adapter-lock digests, and independent reviewer identities and keys
attesting the exact assessment body. Accepted risk requires its own exact,
active `fail` to `accepted-risk` waiver; an applicability, target, or mode
waiver cannot be reused. `remediation_plan.py` and `_remediation_graph.py`
create advisory target gaps and dependency-ordered lanes with exact write sets,
semantic read dependencies, serialization keys, resource ceilings, rollback
contracts, and argv digests matching exact adapter locks. Parent/child path
overlap is a conflict. Only an independently approved plan can expose
deterministic conflict-safe execution batches. The package does not currently
execute those batches autonomously.

## Work lifecycle

`internal_storage.py` supplies path-confined, Git-ignored, symlink-safe,
crash-durable create and replace operations plus exclusive locks.
`work_models.py` defines digest-bound tasks, append-only state events, evidence,
and ownership. `work_closure.py` binds one immutable task definition to the
exact independently verified closed-event chain; a later archive retains the
original closure identity. Proposal and revalidation events must also reproduce
the task baseline, candidate, and source-report bindings. This protocol is the
durable coordination boundary for future worktree and agent-fleet execution;
it is not itself a process supervisor or permission grant.

## Error boundaries

- Invalid or stale external records raise typed validation errors at load or
  command boundaries.
- Git executable discovery, version, replacement, and command failures remain
  explicit runtime errors without falling back to ambient `PATH`.
- Timeouts, missing executables, symlink escapes, digest mismatches, and
  unsupported schemas fail closed.
- Filesystem operations do not use retry loops blindly. Atomic replace and
  directory synchronisation provide crash safety; retry is appropriate only
  for explicitly classified transient operations.

## Packaging

The package uses a `src/` layout, a typed-package marker, Hatchling, an installed
`rigor` entry point, and the `cryptography` runtime dependency for Ed25519. CI
tests Python 3.11–3.13, builds wheel and source distributions, installs the
wheel outside the source tree, and verifies its metadata and CLI.
