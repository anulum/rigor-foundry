# Context source models

These provisional module APIs describe general tasks, context-producer contracts
and independent repository states. They preserve exact source identities for a
consumer that checks actual retained sources and installed ownership. Parsing a
document checks its structure and digest; it does not authenticate a user task,
install a producer or authorize an operation.

These records use schema `1.0`, distinct `object_kind` values, closed fields
and a digest over every other field, including both headers. Their `reference()`
methods return a versioned `typed-object-ref` with an independent `ref_digest`.
An object ID is an identity rather than a filesystem locator. Directly created
instances are revalidated when serialized or referenced.

## General task definitions

`task_definition.TaskDefinition1` contains the declared task ID and revision,
actor IDs, project, owning group, root IDs, statement and lifecycle. Actor and
root sets are nonempty, sorted and unique. Parsing and building require an
explicit [policy read budget](policy-source-inputs.md).

```python
from pathlib import Path

from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.task_definition import TaskDefinition1

# Supply the explicit PolicyReadBudget1 selected by the calling application.
task = TaskDefinition1.from_dict(
    read_policy_document(Path("task.json"), budget=budget), budget=budget
)
identity = task.identity_digest(actor_id="maintainer", root_id="application", budget=budget)
```

The independent task identity includes the exact definition reference, actor,
project, group and root. Membership in a definition remains declared source
data. The installed consumer separately verifies the initiating instruction,
current registry relation and event. General work does not require an invented
remediation task, finding, review or closure record.

## Producer contracts

`context_producer_contract.ContextProducerContract1` binds a producer ID and
class, implementation ID and digest, supported source formats, subject kinds,
exact fact names and inline `ContextRootBinding` records. These descriptors
have no callback, executable, import path or enrollment field.

| Fixed implementation ID | Owner class | Source inputs |
| --- | --- | --- |
| `builtin.task-definition.v1` | `task` | Task definition and project registry |
| `builtin.project-registry.v1` | `registry` | Project registry |
| `builtin.maintained-inventory.v1` | `inventory` | Repository state, project registry and optional configured inventory domain |
| `builtin.context-facts.v1` | `fact` | Outputs of the task, registry and inventory owners |

The parser restricts descriptions to these domains. A description does not
establish that an implementation is installed or qualified. Registry sources
retain their original `gotm-project-registry.v1` or `project-registry.v2`
versions and owning parsers. Source pairs, subjects and fact names are sorted
and unique. Fact names are exact; wildcards and inferred descendant absence
are refused. Identity-only contracts may have an empty fact domain.

Root bindings retain project/group IDs, an exact normalized relative path and
a configured-scope digest. The installed consumer must compare them with the
actual registry and complete configured roots. A task's chosen root cannot
reduce the complete maintained-root, language or role domain.

## Repository states and preimages

`repository_state.RepositoryState1` binds the project/root, registry generation
and digest, full baseline/head/tree Git object IDs, and independent digests for
baseline files, index, worktree, untracked/generated files and configured roots.
All Git IDs use the same full 40- or 64-character object format. The record
contains no enclosing inventory, owner-proof or task-context digest.

`repository_inventory_rows.RepositoryFileRow` is an inline eight-field file
preimage: path, kind, mode, object ID, byte digest/count, language and role.
Nullable fields remain present. Regular and symlink observations require exact
bytes; deleted files retain no present bytes; gitlinks retain a commit identity.
Unknown language/role and unsupported file observations remain explicit data
that cannot establish maintained-scope completeness.

`parse_repository_file_rows(value, budget=budget)` requires sorted, unique paths.
`repository_file_rows_digest(rows, budget=budget)` hashes their complete exact
array. Empty arrays represent observed empty sets.

`RepositoryIndexState` contains exact index entries and the complete sorted
`unmerged_paths` union. Entries retain path, mode, object ID and every stage
from zero through three. `parse_git_index_state(payload, budget=budget)` decodes
actual `git ls-files --stage -z` bytes, including conflicts, with byte and row
ceilings before conversion. It performs no Git process or repository discovery.
Its `digest(budget=budget)` includes all entries and unmerged paths. Contradictory
stage-zero/unmerged combinations, duplicates and mixed Git formats are refused.

An inventory consumer still needs the actual complete preimages, selected code,
source retention and closing validation. Equal self-digests alone cannot prove
that an observation is current or that its source domain is complete.

## Configured inventory domains

[`inventory_domain.InventoryDomain1`](inventory-domains.md) supplies the original
configured-root and classification-rule preimage. Its digest is compared with
each matching `ContextRootBinding.configured_scope_digest` by the actual
selected-source Git-root observer. Parser acceptance alone does not enrol a
root or prove completeness; unmatched classifications remain explicit nulls.
