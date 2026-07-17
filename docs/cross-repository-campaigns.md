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
