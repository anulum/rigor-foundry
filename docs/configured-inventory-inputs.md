<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — configured inventory input collection
-->
# Configured inventory input collection

The provisional module API
`configured_inventory_inputs.observe_configured_inventory_inputs` captures
every root in an actual retained [inventory-domain declaration](inventory-domains.md).
Its Git baseline set contains sorted `InventoryGitBaseline(root_id, head)`
records for every and only declared Git root. There is no request path filter.

The caller supplies an already authorised monorepo root, actual borrowed domain,
registry and inventory-contract leases, a prior complete package/interpreter
observation, an actual trusted `GitRunner` and explicit `PolicyReadBudget1`.
The shared `inventory_source_selection.read_inventory_domain_selection`
compares original source values, complete contract root bindings, project/group
ownership and configured-scope identity. That comparison does not itself inspect
the package or authenticate a host. Both the single-Git-root observer and this
complete declared-root collector retain their actual code/source checks.

Git roots are collected first through the [actual Git/file input
APIs](repository-file-inputs.md). Every original baseline row, index stage,
nonignored untracked path and current observation remains represented.
Directory roots follow, and returned roots retain declaration order.
Missing or unsafe declared roots refuse; they never become fabricated empty
observations or silently disappear.

## Actual directory inputs

`directory_file_inputs.observe_directory_file_inputs` captures every current
leaf and subdirectory through descriptor-relative no-follow traversal. Empty
subdirectories remain explicit. Regular files retain exact SHA-256, byte count
and executable mode. Symlinks retain only their link bytes, without reading the
target. Other leaf types remain explicit unsupported rows and are not opened.

Two complete traversals must agree, each directory's names and object metadata
must remain stable, and the final root pathname must identify the retained root.
Non-UTF8 paths and Git administration entries refuse instead of being omitted.
This is agreement across bounded reads, not an atomic filesystem snapshot.

`DirectoryFileInputs` retains the selected root, its observed device/inode,
ordered file rows, directory paths and actual `source_bytes_read`. It contains
no fabricated Git identity or historical baseline. Capturing a root declared
`generated` does not prove its generator, provenance or reproducibility.

For an `ignored` root, the collector additionally requires a declared containing
Git root. The nearest such root supplies the actual ignore check. Current index
entries beneath that directory refuse, including force-added files.
Actual `git check-ignore --quiet --no-index` must succeed before and after the
directory capture. The declaration's `source_kind` text alone is insufficient.

## Shared classification and nested roots

`inventory_classification.classify_inventory_file_rows` applies the same exact,
longest-suffix and whole-component-prefix rules to actual Git or directory
rows. It preserves every byte observation and explicit unknown. The existing
Git-backed wrapper and complete collector share its compiled classifier; no
artificial Git state is constructed for a directory. These are path labels, not syntax verification
or adapter qualification.

`InventoryFileClassifier` validates the whole domain once and freezes its
selector maps for repeated row groups. The complete collector shares that
instance across roots, so adding roots does not repeatedly parse the complete
declaration. Each row group still receives its original path and row checks.

Nested roots preserve their complete original observations. Repeated current
file observations must agree on kind, mode and byte identity; an auxiliary Git
blob ID and root-specific labels are kept in their original records.
A directory cannot replace an observed regular file. A Git observer's explicit
unsupported directory leaf may receive a separate actual directory capture.

The ordered `InventoryPathOwner` table names the longest declared root
containing each observed monorepo-relative path. This is an explicit namespace
relation, not an authenticated owner proof. Parent rows and index data are
retained even when a more specific declared root owns the path.

## Resource accounting and limits

The collector shares the original total capture-byte and current-entry
ceilings across roots. It counts complete Git command outputs, both baseline/
current file passes, directory file/link bytes and every opening/closing UTF-8
name enumeration, plus ignore-command output. Directory entries count alongside
file observations. Path-owner references have their own original ceiling.

`maximum_paths` on the Git file API, and `maximum_total_bytes`/
`maximum_entries` on the directory API, may only tighten their original
ceilings. Zero remaining allowance permits an actual empty capture; it cannot
filter a nonempty tree into an empty result. A further Git observation still
needs its actual metadata-byte allowance.

Complete package/interpreter and retained configuration reads each keep their
own explicit source budgets. They are separate from the combined root-capture
counter; enclosing whole-host resource and source-access guards remain required.

`ConfiguredInventoryInputs` retains all root inputs, namespace ownership, typed
domain/registry/contract references, source-selection identity and the actual
combined `file_source_bytes_read`. Its source-selection digest binds code and
selected source references, not an independently authenticated fact about the
returned file data.

All declared roots being captured does not prove that the host selected every
required maintained root. Directory baselines, generated lineage, authenticated
repository-state/inventory/fact/task owners, uninterrupted source lifetimes,
revocation, effects, durable journals and adoption require their separate owning
contracts. These module APIs extend neither the frozen root exports nor the
installed CLI.
