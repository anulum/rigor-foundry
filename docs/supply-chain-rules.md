# Supply-chain rules

Rule-pack `rigor-foundry/1.9.0` adds a bounded supply-chain category (prefix
`SC`) of high-precision rules over tracked Python requirement files. Like every
RigorFoundry rule, each `SC` finding is an anchored **needs-evidence candidate**,
never a verdict: it marks a real dependency-integrity surface for review, not a
proven compromise. The rules are deliberately narrow to keep false positives
low; breadth is not an acceptance metric.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `SC001-unhashed-pinned-requirement` | a pinned (`==`) requirement in a hash-mode lock file that carries no `--hash=` digest | high |
| `SC002-vcs-url-requirement` | a dependency installed from a VCS checkout (`git+`, `hg+`, `svn+`, `bzr+`) or a PEP 508 direct URL (`name @ https://…`) | high |

`SC001` activates only for a requirement file that already demonstrates hash
mode — at least one line carries a `--hash=` digest — and then flags any pinned
requirement in that file with no accompanying hash. Such a gap means the
artefact is installed without verification against tampering or index
substitution. It is near-zero false-positive by construction: `pip-compile
--generate-hashes` output hashes every entry, so a missing hash is a genuine
integrity hole and not a stylistic choice. `SC002` flags a dependency resolved
outside the package index and its recorded hashes — a mutable, unverified
artefact.

Both rules parse requirement lines, joining backslash-continued blocks, and skip
comments and index-configuration options: `--index-url https://…`,
`--extra-index-url`, and `--find-links` are configuration, not dependencies, and
are not flagged. Scope is limited to files named `requirements*.txt` /
`requirements*.in` or any `.txt` / `.in` file under a `requirements/` directory;
`.in` source inputs are never subject to `SC001` because they carry no hashes by
design, but a VCS or URL dependency in an `.in` is still a real `SC002` concern.

Each candidate carries a repository-tree anchor (path, line, content SHA-256), a
neutral rationale, and a concrete verification procedure — for `SC001`,
recompile the lock with `--generate-hashes` so every pin carries a digest; for
`SC002`, pin the dependency to an immutable released version from the index with
a recorded hash, or vendor and audit the exact revision if a direct source is
genuinely required.

## Precision and applicability

The rules match on requirement structure, not on arbitrary text, so a URL inside
a comment or a non-requirements file is not flagged, and a fully hashed lock
produces no candidate. The category contributes a portable control toward the
`supply-chain` audit domain over the tracked requirement surface, so a
repository that declares that domain required is now covered by a portable rule
as well as any wired native adapter (for example a Trivy or Grype profile).

## Calibration

False-positive calibration against real repositories is deliberately separate
work: these rules ship with safe-and-vulnerable fixtures and precise
requirement parsing, but adjudicated false-positive and reviewer-effort evidence
across adopter repositories is the maturity-lifecycle step that promotes a rule
from candidate breadth to calibrated enforcement.
