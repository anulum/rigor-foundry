<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — repository file input observations
-->
# Repository file input observations

The provisional module API `observe_repository_file_inputs` combines
[actual Git inputs](repository-git-inputs.md) with complete baseline blob reads
and current file observations within that Git path domain. The caller supplies
an exact, already authorised worktree root, full baseline commit, actual
`GitRunner` and explicit `PolicyReadBudget1`.

`RepositoryFileInputs` retains its bounding `RepositoryGitInputs`, plus sorted
`baseline_files` and `current_files` arrays of
[`RepositoryFileRow`](context-source-models.md#repository-states-and-preimages).
Current paths are the complete union of baseline paths, every index stage and
nonignored untracked paths. Deleted or renamed baseline paths remain present;
staged blob IDs remain distinct from actual current file-byte identities.

Baseline blobs are read by their full object IDs. The API computes both their
SHA-256 and Git blob identity from those actual bytes, refusing content that
does not match the requested Git object. Baseline gitlinks retain commit
identities without being coerced into file bytes. Regular current files use
the existing descriptor-relative stable reader, with explicit byte bounds and
no-follow parent traversal. Symlinks retain their link bytes without following
targets. Missing paths are explicit deleted rows. Directories, including
submodule worktrees, and other unsupported leaf types remain unsupported rows;
their separate maintained-root owner is still required.

All rows keep null language and role until an independent owner classifies
them. No unknown row is discarded or declared outside maintained scope.

The transaction counts the actual standard-output/error bytes of its first
Git observation, then both complete file observations, and supplies only the
remaining byte budget to the closing Git observation. Each Git observation
includes its own two matching reads. Baseline/current file
observations must agree, bounding Git state must agree, and the root pathname
must still name the retained directory object. Unique path count, path depth,
individual file bytes and aggregate bytes are bounded. Refusal returns no
partial inventory or alternate root.

The returned `source_bytes_read` counts the complete actual transaction,
including the closing Git observation. It is auxiliary accounting and does not
change semantic equality. An enclosing collector may supply `maximum_paths`
to tighten the original source/reference ceiling, including zero for an actual
empty Git tree. See [Configured inventory inputs](configured-inventory-inputs.md)
for combined Git/directory capture accounting and shared classification.

These are source observations, not an atomic Git/filesystem snapshot or an
authenticated maintained inventory. Configured ignored/generated/disjoint
roots, complete classification, task/fact contexts and admission remain the
enclosing installed owner's responsibilities. Existing source-access and
snapshot/lifetime permission must already be held. Git provenance is not a
network sandbox. Retained-directory Git execution requires Linux
`/proc/self/fd`; no Windows or other native-host qualification is implied.
