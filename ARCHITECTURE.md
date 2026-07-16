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
branch, tracked paths, dirty tracked paths, symlinks, gitlinks, binary content,
and content digests. Container ownership mismatch is handled with a
process-local `safe.directory` limited to the explicit audited root after
discovery. Global and system Git configuration, credentials, terminal prompts,
replacement objects, optional locks, and ambient `GIT_*` variables are excluded
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

The portable inventory is deliberately Git-tracked-only. A rule may reason
about the tracked tree, but it must not infer that an ignored or untracked
artefact does not exist. Any control whose meaning depends on that wider local
reality must consume an explicit, policy-declared ignored-inventory evidence
extension or remain `needs-evidence`; tracked-only absence cannot become a
failure verdict.

### Evidence records

`rules.py` defines the versioned portable rule registry.
`audit_primitives.py` owns protocol versions, canonical digests, strict field
validators, and shared type contracts. `models.py` defines policy, candidate,
report, adapter, and review records while preserving the original public
primitive imports. Callers must verify digests during load; silent repair is
not permitted. Report schema 1.1 includes `GitExecutableProvenance`; changing
the executable, version, path, root, or embedded trust policy changes the
report digest. Review-ledger schema 1.0 is independent and remains unchanged.

### Review, enforcement, and promotion

`review.py` validates reviewer identity, decision state, evidence, timestamps,
report binding, and duplicate prevention. Promotion rescans the repository and
rejects changed HEAD, content, policy, Git provenance, or candidate identity.

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

`campaign_models.py`, `campaign_store.py`, `campaign_workflow.py`, and
`campaign_compare.py` freeze campaign inputs, Git and sandbox provenance,
independent toolchains, and limitations, and preserve disagreement. Campaign
schema 1.2 requires every run to reproduce the frozen Git identity and retain
complete native-adapter provenance; a different trusted binary or omitted
adapter is divergence, not an equivalent unrecorded substitution. The
ignored-storage check that persists a campaign, run, or comparison must also
reproduce that frozen identity.
Majority agreement is not converted into truth.

Distinct session or agent labels do not prove independent inference. Promotion
campaigns must record model/provider identity, treat correlated same-model runs
as one witness, and include at least one independently operated model family.

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
ownership, and closure records. This protocol is the durable coordination
boundary for future worktree and agent-fleet execution; it is not itself a
process supervisor or permission grant.

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
`rigor` entry point, and no third-party runtime dependency. CI tests Python
3.11–3.13, builds wheel and source distributions, installs the wheel outside
the source tree, and verifies its metadata and CLI.
