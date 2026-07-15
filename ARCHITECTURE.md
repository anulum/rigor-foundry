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

`git_inventory.py` resolves the Git executable, repository root, HEAD, tree,
branch, tracked paths, dirty tracked paths, symlinks, gitlinks, binary content,
and content digests. Container ownership mismatch is handled with a
process-local `safe.directory` limited to the explicit audited root after
discovery; Git configuration is never changed persistently. Missing Git state
and unsafe path states fail closed.

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
not permitted.

### Review, enforcement, and promotion

`review.py` validates reviewer identity, decision state, evidence, timestamps,
report binding, and duplicate prevention. Promotion rescans the repository and
rejects changed HEAD, content, policy, or candidate identity.

`enforcement.py` supports observe, ratchet, and zero modes. A command-line mode
may strengthen but cannot weaken the repository policy.

### Native audit adapters

`adapters.py` executes only declared argv. External executables are resolved
before execution; the `{python}` token preserves the active virtual-environment
launcher so native controls cannot silently escape the locked toolchain.
Shells are disabled, timeouts are mandatory, outputs are bounded, and results
include executable and input identity.

### Independent campaigns

`campaign_models.py`, `campaign_store.py`, `campaign_workflow.py`, and
`campaign_compare.py` freeze campaign inputs, record independent toolchains and
limitations, and preserve disagreement. Majority agreement is not converted
into truth.

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
- Git and adapter process failures retain return code and bounded diagnostics.
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
