<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — task context and original remediation sources
-->
# Task contexts and original remediation sources

The provisional module APIs join the [complete maintained inventory and source facts](maintained-context.md)
to an explicit general task and declared event. Their fixed source composer
revalidates the actual original task/registry/inventory entries and optional
retained remediation files. The result verifies source identity; an enclosing
host must authenticate the initiating user, event, claim and audit request
before deciding whether an operation is allowed.

## Complete task data

`task_context.TaskContext1` uses schema `1.0` and object kind `task-context`.
It contains the original general task reference and task proof, actor, project,
owning group, root, registry generation/digest, task lifecycle, declared event,
full maintained inventory, fact context, nullable claim proof and remediation
binding, independent task identity and final context digest.

The independent task identity hashes only schema `1.0`, object kind
`task-identity`, task ID/definition, actor, project, group and root. It precedes
the task proof, facts and final context, so no enclosing hash becomes its own
input subject. Original task, registry and full inventory facts must agree with
these fields. The context requires one registry observation identity and
distinct task/registry/inventory owners, exact proof membership and every known
mandatory source domain. Matching labels alone cannot authenticate a source.

Accepted declared events are `claim`, `start`, `scope-change`,
`dependency-change`, `mutation`, `verification`, `review`, `commit`,
`publication`, `process`, `closure` and `audit`. These are data labels.
A `publication` context does not grant publication authority.

`build`, `from_dict` and direct immutable instances enforce the same closed
field/version/relationship contract. The explicit parser budget bounds the
aggregate nested roots, surfaces, proofs, observations and array values before
nested model allocation. Direct instances also obey the hard reference ceiling.
Parsing verifies data integrity and relationships; actual source verification
remains required.

## Original remediation records

General work uses a real `TaskDefinition1` without inventing an audit report or
review. A task explicitly connected to an existing remediation can additionally
carry `remediation_task_binding.RemediationTaskBinding1`: the original work-task
reference, nullable complete record and closure references, and its binding
digest. A closure requires its original complete record; all references name
the same original task.

`work_context_sources` supplies fixed adapters for the existing `WorkTask`,
`WorkRecord` and `WorkClosure` models. Existing task and closure source bytes
retain their original schema `1.0` and definition/closure digests. Their public
owning parsers remain responsible for validation.

The original `WorkRecord` has no public wire serializer or complete record
digest. `WorkRecordSource1` therefore owns an explicit retained-source
projection with exactly `schema_version`, `object_kind=work-record`, the
original `task` mapping and complete `events` array. Its reference digest binds
that entire projection, including the task definition; the latest event digest
alone is insufficient. This adapter preserves original `WorkRecord.build`
semantics and exposes the same serialisation/reference interface as other
retained sources. Its parser limits are held separately from source identity.

| Fixed source kind/version | Actual parser and identity |
| --- | --- |
| `work-task / 1.0` | Original `WorkTask.from_dict`; original definition digest |
| `work-record / 1.0` | Complete `WorkRecordSource1` projection rebuilt through original task/event parsers and `WorkRecord.build`; full projection digest |
| `work-closure / 1.0` | Original `WorkClosure.from_dict`; original closure digest |

Unknown pairs refuse before lookup. These kinds are available through the
existing fixed `parse_context_source_target` and `RetainedContextSource`
interfaces. Data never chooses a loader, callback, path or executable.

`RemediationSources` borrows actual retained task, optional record and optional
closure selections. `observe(budget=...)` reads and revalidates their fixed
types, complete task-definition equality and original event/closure binding,
then repeats the original source reads. The host keeps the leases open through
the enclosing task consumer and closes them afterward. No source is closed or
replaced by the binding API.

## Actual source composition

`source_task_context.observe_source_task_context` accepts exact installed
`TaskRegistrySourceOwners` and `InventorySourceOwner` entries, the original
actor/root, declared event and explicit budget. Optional `RemediationSources`
must be actual borrowed entries. It derives current complete source facts,
independently observes the task and inventory, builds the context and verifies
the original owners before returning.

`verify_source_task_context` rebuilds the complete context from those actual
entries and the separately supplied declared event. Another owning entry,
changed source or different declared event cannot reuse earlier context data.
The composer emits a null claim proof. Caller-supplied claim metadata cannot
become an authenticated claim by passing through this source-only entry.

`evaluate_source_task_condition` verifies the whole context before and after
calling the original three-valued condition evaluator. It returns
`ConditionTruth.TRUE`, `FALSE` or `UNKNOWN`; Boolean coercion remains forbidden.
Missing exact facts stay unknown, invalid known operands refuse, and no decisive
sibling excuses an incomplete maintained inventory.

These APIs do not select a policy generation, authenticate initiating authority,
verify a live claim, admit a root or execute an effect. Selected policy still
owns which events require a claim and every other admission obligation.
Package-root exports and the installed CLI retain their existing contracts.
