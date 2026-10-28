<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — retained inventory baselines and actual repository states
-->
# Inventory baselines and repository states

These provisional module APIs connect the [complete configured collector](configured-inventory-inputs.md)
to independently retained before-images and the existing `RepositoryState1`
record. They inspect actual selected sources and file inputs. Their results
remain observational data, with no owner-proof, task admission or effect permit.

## Explicit earlier inputs

`inventory_baseline.InventoryBaseline1` uses schema `1.0` and object kind
`inventory-baseline`. Its closed fields are `baseline_id`, `project_id`,
`domain_reference`, `registry_reference`, `roots` and `baseline_digest`, alongside
the two headers. Its digest binds every other field. Typed domain and registry
references preserve their original identities and formats.

Each inline `InventoryBaselineRoot` retains its complete `InventoryDomainRoot`,
`git_head`, `files` and `directories`:

- A Git root has an explicit full commit and every original baseline file row,
  including blob or gitlink identities. No directory list is invented for Git.
- An ignored or generated directory has no Git commit or object IDs. Its rows
  retain earlier observed byte identities and modes; all directories, including
  empty ones, remain explicit. Unsupported leaves and unknown classifications
  remain visible.

Roots and paths must be sorted and unique. File/directory collisions, a file
used as a parent, missing directory parents and inconsistent history fields
refuse. Parsing bounds root counts and aggregate root/file/directory references
before retaining their contents. The source reader additionally applies its
actual byte and JSON-depth ceilings. These are allocation limits, not execution
or source-access authority.

## Actual baseline capture

`repository_state_observations.capture_inventory_baseline` calls the existing
complete collector with the actual retained domain, registry and inventory
contract, complete package/interpreter observation, trusted Git and explicit
read budget. `baselines` supplies an `InventoryGitBaseline` for every and only
declared Git root. `baseline_id` names the resulting source record.

The returned Git before-images come from those explicit commits. Directory
before-images come from the actual agreeing directory reads at capture time.
Persist and independently select this record before the subsequent change.
Capturing the current directory again after an edit cannot recover its earlier
state or prove generator lineage.

The fixed typed-source parser supports `inventory-baseline` format `1.0`.
Only the inventory producer's format domain accepts that source kind. As with
other [retained sources](context-source-ownership.md), the host independently
selects the exact path, typed reference and original raw SHA-256 before opening
`RetainedContextSource`. A valid self-digest alone establishes no historical
authenticity or right to access the named files.

## Actual repository-state observation

`repository_state_observations.observe_repository_state` receives that actual
`baseline_source` and the same host-selected capture inputs. The inventory
contract must explicitly include the selected baseline format. The observer
captures every current declared root and compares the complete before/current
root selection, project, domain and registry identities. Each Git before-image
must reproduce the selected commit's actual original blobs.

`root_id` selects the declared Git root whose baseline/head/tree fields name the
returned `RepositoryState1`. It never filters the remaining roots. Missing or
directory-only selections refuse. Selecting another Git root preserves the
same complete input domain and independent inventory/index/worktree identities.

The observer derives and retains:

- The full explicit baseline identity, including earlier directory preimages.
- Every current index stage across all Git roots.
- Every current file row, directory topology and actual Git head/tree/status
  and executable provenance.
- Actual nonignored untracked paths and their current rows.
- Complete current generated-directory observations and the configured domain.

Deleted Git files retain their original baseline rows alongside explicit current
deletions. Removed directory files and directories remain in the independently
retained before-images. Current observations cannot rewrite their history.
Unknown language/role and unsupported entries participate in the state;
they do not become evidence of complete maintained-language qualification.

`RepositoryStateObservation` returns `state`, the full original `inputs`, the
retained `baseline` and `source_snapshot_digest`. The last value binds the
actual configured-source selection, retained baseline reference/lifetime and
derived state, plus the device/inode of each captured directory root. Replacing
a directory with equal bytes can preserve its content state while changing this
source-snapshot identity. A final baseline read rejects an edit during the Git/file
observation, even if all current-root reads themselves completed successfully.

Domain or registry changes require explicit history reconciliation. This
observer refuses mismatches instead of dropping old roots, replacing an earlier
baseline with current bytes, or assuming an empty history.

Agreement across these bounded observations is not an atomic cross-root
snapshot or uninterrupted physical-root lease. Required host-root selection,
generator provenance/reproducibility, revocation, authenticated inventory/fact/task
owners and runtime admission retain their separate contracts. These APIs change
neither frozen package-root exports nor the installed CLI.
