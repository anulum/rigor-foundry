# Cross-repository dependency campaigns

A cross-repository campaign freezes several repositories at exact commits so an
audit can be replayed historically across a dependency graph, without touching
any operator's working tree.

## Repository snapshots

Each repository is captured as a `RepositorySnapshot`, which is either:

- **available** — carrying every frozen digest (head commit and tree object
  identifiers, and the policy, rule-pack, adapter-lock, and toolchain digests) so
  the exact historical state can be replayed; or
- **unavailable** — carrying only a reason and no digests, for a historical
  state that could not be resolved (for example a pruned commit).

The two kinds are mutually exclusive: an available snapshot may not carry an
unavailable reason, and an unavailable snapshot may not carry any frozen digest.
This is what keeps an unresolved historical dependency from ever being mistaken
for a resolved one.

## Dependency graph

`InterRepositoryEdge` records a directed `from_repository → to_repository`
dependency with a neutral relationship label and a rationale. A
`CrossRepositoryCampaign` collects one snapshot per repository plus the edges,
and validates that:

- repository identifiers are unique;
- every edge references repositories present in the campaign;
- edges are unique and never self-referential;
- the dependency graph is acyclic.

## Detached, read-only replay

The campaign only ever references detached git objects and content digests —
never a working-tree path — so replaying it never changes a checkout. The frozen
instant is recorded in `frozen_at`, and the whole set is content-addressed with a
`campaign_digest`.

## Capturing real Git objects

`capture_cross_repository_campaign()` resolves the commit and tree fields from
real local Git object databases. Every `RepositoryCaptureRequest` must name:

- one absolute, canonical Git worktree root that contains no symlink component;
- one full SHA-1 or SHA-256 commit object identifier; and
- the policy, rule-pack, adapter-lock, and toolchain identities selected for
  later replay.

The operation is bounded to 128 explicitly listed roots. It never discovers
another repository from an edge, creates a worktree, checks out a revision,
runs an adapter, writes a campaign record, or grants remediation authority. A
single content-verified Git executable reads every root with repository hooks,
filesystem monitors, credential prompting, replacement objects, and optional
locks disabled by `GitRunner`.

Capture records the source checkout's HEAD, tree, tracked and non-ignored
untracked status, and root identity before resolving an object, then requires
the same state after the read. The requested object may be older than the
checkout's current HEAD. Only its detached commit and tree identities enter
`RepositorySnapshot`; dirty tracked files and non-ignored untracked files in
the operator checkout are neither read as historical content nor changed.

A missing commit becomes an `unavailable` snapshot with no frozen digests. An
invalid root, object-format contradiction, tag object supplied instead of its
commit, Git operational failure, or concurrent checkout change aborts the
capture. Those conditions do not become availability results.

Capture remains an input, not an audit verdict. Historical static scanning is a
separate execution control described below; persistence and external campaign
adjudication remain outside both surfaces.

## Executing captured historical trees

`CrossRepositoryExecutionPlan.build()` binds the exact capture digest, campaign
digest, ordered request digests, one repository-relative policy path per
repository, and a deterministic dependency-first execution order. The plan is
content-addressed. Execution reconstructs it from the supplied capture,
requests, and policy paths before any temporary repository is created; an
altered order, target, policy path, request, campaign, or plan digest is rejected
as stale or substituted.

`execute_cross_repository_campaign()` then processes one repository at a time:

1. verify that the captured commit still exists in the explicitly named source
   object database;
2. initialise a fresh temporary repository using the captured SHA-1 or SHA-256
   object format;
3. fetch only the exact captured commit through the attested Git executable;
4. check it out detached and run the production static scanner against the
   historical policy path; and
5. remove the complete temporary campaign workspace before returning evidence.

The source checkout's HEAD, tree, full tracked/non-ignored status, and root
identity must be byte-for-byte equal before and after the campaign. A temporary
parent, when supplied, must be an absolute canonical real directory that neither
contains nor sits inside any source repository. A policy symlink that escapes
the detached tree remains a scan failure; external bytes are not imported.

The runtime and every successful report are checked against the frozen
toolchain, Git provenance, commit, tree, policy, rule-pack, and complete native-
adapter declaration digest. Successful reports must come from a clean detached
`HEAD`. This execution surface calls only the static scanner: it does not run
native adapters, repository-defined commands, remediation, persistence,
publication, or fleet activation.

### Cancellation and failure semantics

`CampaignCancellation` is cooperative at repository boundaries, including the
boundary after historical materialisation and before scanning. Every planned
repository receives an outcome even when cancellation was already requested;
temporary rollback and source-state equality are still mandatory.

Per-repository status is one of:

- `succeeded` — a complete, integrity-checked historical static report exists;
- `unavailable` — capture was unavailable, the historical object was pruned, or
  a required dependency did not produce evidence;
- `failed` — materialisation, scanning, or frozen-input validation failed; or
- `cancelled` — cancellation was observed before that repository's scan.

The aggregate resolution is `succeeded` only when every repository succeeded.
Mixed success and non-success is `partial`; all-unavailable is `unavailable`;
no-success failures are `failed`; and any cancellation makes the campaign
`cancelled`. None of these states is a correctness verdict, and missing or
divergent evidence is never converted into a pass.

```python
from pathlib import Path

from rigor_foundry.cross_repository_execution import CrossRepositoryExecutionPlan
from rigor_foundry.cross_repository_runtime import execute_cross_repository_campaign

plan = CrossRepositoryExecutionPlan.build(
    capture=capture,
    requests=requests,
    policy_paths=tuple("rigor-foundry-policy.json" for _request in requests),
)
execution = execute_cross_repository_campaign(
    plan=plan,
    capture=capture,
    requests=requests,
    temporary_parent=Path("/absolute/disjoint/temporary-parent"),
)
execution.resolution  # succeeded, partial, unavailable, failed, or cancelled
```

The example assumes `capture` and `requests` were produced by the explicit real
Git-object capture flow above. The executor does not discover either value.

## Resolution

A campaign distinguishes an unavailable dependency from a passing result:

```python
from rigor_foundry.cross_repository_campaign import (
    CrossRepositoryCampaign,
    InterRepositoryEdge,
    RepositorySnapshot,
)

campaign = CrossRepositoryCampaign.build(
    campaign_id="release-audit",
    frozen_at="2026-07-15T10:00:00Z",
    snapshots=(app_snapshot, library_snapshot),
    edges=(InterRepositoryEdge.build(
        from_repository="app",
        to_repository="library",
        relationship="depends-on",
        rationale="shared library",
    ),),
)
campaign.resolution()               # "complete" or "unavailable"
campaign.unavailable_dependencies() # dependency targets that could not be frozen
```

`resolution()` returns `complete` only when every snapshot is available;
otherwise it returns `unavailable`, and `unavailable_dependencies()` names the
dependency targets that could not be frozen. A campaign is a frozen replay input,
never a verdict — an unavailable dependency is surfaced, not silently passed.
