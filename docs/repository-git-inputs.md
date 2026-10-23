<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — repository Git input observations
-->
# Repository Git input observations

The provisional `observe_repository_git_inputs` Python API reads an explicitly
selected Git worktree with a full baseline commit ID, an actual `GitRunner` and
an explicit `PolicyReadBudget1`. It retains a no-follow directory descriptor
during the read. Git runs from that retained directory, rather than discovering
a containing repository from an arbitrary caller path. A subdirectory or symlink
root refuses.

The returned `RepositoryGitInputs` keeps the baseline commit and tree, current
HEAD and tree, SHA-1 or SHA-256 object format, complete recursive baseline modes
and object IDs, every current index stage, nonignored untracked paths, original
NUL-delimited status output and executable provenance. Unresolved index stages
remain visible. They are not coerced into a stage-zero inventory. Deleted or
renamed baseline paths remain in the baseline entries.

Each command enforces a streaming output ceiling. The transaction also counts
all command outputs against its total byte budget. Two complete observations
must agree, and the canonical root must still name the retained directory
object. These checks detect disagreement; they do not establish an atomic
filesystem snapshot.

`source_bytes_read` counts actual standard-output/error bytes across both
complete Git reads. It supports enclosing transaction accounting and is
excluded from semantic observation equality. This resource counter supplies
no source-authentication or snapshot authority.

This API observes Git inputs only. It does not read or classify every current
file, enrol ignored/generated roots, authenticate a task, grant source access,
prove maintained-inventory completeness, or authorise an effect. Those remain
the enclosing installed owner's responsibilities. The caller must already hold
source-access permission and the applicable snapshot/lifetime guards. No
missing input triggers an alternate repository or scan fallback.

The retained-directory execution path currently requires Linux `/proc/self/fd`.
No Windows qualification is implied by parsing a portable Git object identity.

`parse_git_baseline_entries` and `parse_git_untracked_paths` expose the same
bounded format contracts for retained original Git output. They parse bytes
without invoking Git or accessing a repository; malformed, incomplete,
duplicate or over-budget entries refuse.
