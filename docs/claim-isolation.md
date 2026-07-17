# Claim isolation and fleet views

Concurrent RigorFoundry execution — running remediation lanes across repositories
and campaigns at the same time — is governed by an execution-claim isolation gate
and observed through a read-only fleet view. Neither grants any execution
authority; they prove disjointness and report state.

## Execution claims

An `ExecutionClaim` binds one repository, campaign, and remediation lane to a
disjoint write set and a set of serialization keys, with an explicit expiry:

- **Repository-bound.** A claim never grants cross-repository authority. Two
  claims in different repositories never conflict, even on the same path.
- **Disjoint write sets.** Two claims that hold at the same instant in one
  repository may not write equal, parent, or child paths.
- **Serialization keys.** Two holding claims in one repository may not share a
  serialization key; shared keys force serial execution.
- **Repository-relative paths only.** Absolute paths and `..` traversal are
  rejected.
- **Lifecycle.** A claim is `active`, then terminal — `completed`, `cancelled`,
  or `rolled-back`. Only an active claim may transition, and a terminal claim
  holds nothing.
- **Stale recovery.** An active claim past its expiry is stale and recoverable:
  it no longer holds resources, so a fresh overlapping claim is admitted.

```python
from datetime import datetime, UTC
from rigor_foundry.claim_isolation import ExecutionClaim, admit_claim

claim = ExecutionClaim.build(
    claim_id="c1",
    repository_id="repo-a",
    campaign_id="campaign-1",
    lane_id="lane-1",
    claimant="operator",
    write_set=("src/pkg/a.py",),
    serialization_keys=("build",),
    claimed_at="2026-07-15T10:00:00Z",
    expires_at="2026-07-15T11:00:00Z",
)
active = admit_claim((), claim, datetime(2026, 7, 15, 10, 30, tzinfo=UTC))
```

`assert_claim_isolation(claims, instant)` proves that every claim holding at the
instant is mutually isolated per repository, that prerequisites resolve within
the same repository, and that the prerequisite graph is acyclic. `admit_claim`
checks a candidate against the holding set and recovers stale claims implicitly.

## Fleet views

`fleet_view(claims, instant)` returns a deterministic, read-only `FleetView`
snapshot across repositories and campaigns. Unlike the gate, the view **reports**
conflicts rather than rejecting them, so an operator can see contention:

- repositories and campaigns with a holding claim;
- holding claim ids grouped by repository and by campaign;
- stale (recoverable) and terminal claim ids;
- overlapping same-repository write conflicts;
- serialization keys held by more than one claim;
- prerequisite dependency edges.

```python
from rigor_foundry.fleet_view import fleet_view

view = fleet_view(all_claims, instant)
print(view.write_conflicts, view.serialization_contention, view.stale_claim_ids)
```

The view is content-addressed and never mutates a claim. Both surfaces are
reachable via submodule import (`rigor_foundry.claim_isolation` and
`rigor_foundry.fleet_view`).
