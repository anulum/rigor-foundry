<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — maintained inventory and source-derived fact context
-->
# Maintained inventory and source facts

These provisional module APIs connect the [actual baseline/state observer](inventory-baselines.md)
and [fixed task/registry owners](context-source-ownership.md) to complete maintained
surface records and source-verified condition facts. They are called by trusted
host composition with actual retained sources and fixed owner entries.

## Complete maintained scope

`maintained_surface.MaintainedSurface1` and
`maintained_inventory.MaintainedInventory1` use schema `1.0`. A surface retains
its exact root-relative path, declared role/language, effective byte digest,
nullable earlier byte digest and inventory proof. The enclosing inventory binds
project/registry identities, independently derived repository/baseline digests,
every declared root, every maintained surface, change/completeness proofs and
its final digest. Parsing these records verifies integrity and relationships;
it does not authenticate their issuer or their physical sources.

Roots are sorted and unique. Surfaces are sorted by `(root_id, relative_path)`
with no duplicate root/path. Empty roots remain declared. Before/current unions
retain deleted files and both sides of a move. Overlapping configured roots
retain their own complete surface observations; selecting a task root does not
discard other roots. All actual Git index stages and directory topology remain
bound by the independent repository state and original captures.

The change proof and every surface proof bind the independent repository-state
subject. The completeness proof binds the independently retained baseline.
Both proofs must name the same inventory owner, contract and snapshot. Their
subjects precede the enclosing inventory digest, so there is no digest cycle.
Byte/count/depth and aggregate root/surface/proof budgets remain explicit.

## Actual fixed inventory owner

`inventory_source_owner.InventorySourceOwner` receives the host-selected
physical monorepo root, actual retained domain/registry/inventory-contract/
baseline/repository-state sources, complete package/interpreter observation,
trusted Git runner and read budget. Persist and independently select a
repository-state record obtained through the actual observer before creating
this entry. The owner compares that retained state with freshly observed roots.

`observe()` returns `OwnedMaintainedInventory`: the full inventory, independently
generated change/completeness observations and proofs, and the full original
`RepositoryStateObservation`. `verify(value)` recomputes the actual selected
sources, root state and complete inventory; matching caller metadata alone
cannot substitute for the original entry. Another entry has another snapshot
identity. `close()` revalidates actual state and closes the entry, while the
host retains ownership of the borrowed source leases.

Current regular-file bytes and raw symlink target bytes retain their actual
identities. A deleted file uses its explicitly retained earlier bytes, never
invented current content. Staged divergence participates in changed paths even
when worktree bytes equal the baseline. Unknown language/role, unsupported byte
history, an unresolved merge index or a newly staged file with no remaining
worktree/baseline bytes holds the ready inventory. Such inputs remain present
in the original complete captures; they are never silently filtered. A gitlink
commit identity does not become a fabricated file-content digest.

Declared path classifications are distinct from content-language validation,
generator lineage and native toolchain acceptance. The owner verifies the full
selected declared domain; enclosing host policy still owns which roots must
be declared and the right to read them. Agreeing bounded reads do not establish
an atomic snapshot, uninterrupted physical-root lease or effect permission.

## Closed fact data

`fact_context.FactObservation1` retains an exact dotted reference, explicit
state/value, independent subject, nullable provenance and final digest.
Known null and empty arrays remain observed values. Authoritative absence
requires a matching proof; unknown requires null value and null provenance.
Missing an exact reference never manufactures absence for it or descendants.
Finite scalar identities preserve Boolean/number distinctions.

`FactContext1` binds the independent task identity, current registry generation
and digest, complete inventory digest, sorted unique producer proofs and sorted
unique observations. Every nonunknown observation must belong to its selected
proof set. Contradictory observed parent/child references refuse. Structural
parsing grants no producer authentication.

## Source-verified evaluation

`source_fact_context.observe_source_fact_context` accepts only actual fixed
`TaskRegistrySourceOwners` and `InventorySourceOwner` entries, an actor/root and
explicit budget. It derives the original seven task, eight registry and five
inventory facts from those owners. Missing producer domains, conflicting project/
root/registry selections or overlapping owner identities refuse. Complete
task/registry root bindings must match every actual inventory root, physical
path, owning group and configured-domain digest. Matching root labels alone
cannot substitute another selected path or scope. Each actual
owner revalidates its original observations before the context is returned.

`verify_source_fact_context` compares a complete supplied context with actual
new source-owner observations. `evaluate_source_fact_condition` performs that
verification before and after existing `ConditionExpression1.1` tri-state
evaluation. It returns `ConditionTruth.TRUE`, `FALSE` or `UNKNOWN`; implicit
Boolean conversion remains forbidden. Missing facts stay unknown, invalid
known operand domains refuse, and no decisive sibling excuses incomplete
maintained scope.

Source identity verification does not authenticate the initiating user, event,
claim or audit request. These APIs do not implement enclosing task admission,
selected rule generation, runtime revocation/effects or native permission.
Their new result models do not expand the fixed retained-source parser table,
frozen package-root exports or installed CLI.
