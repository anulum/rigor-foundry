# Architecture

RigorFoundry treats a repository audit as an evidence pipeline, not a verdict
generator.

1. A fixed-root Git trust policy selects one non-symlink executable and binds
   its path, root, version, executable digest, and policy digest.
2. Git inventory freezes the exact tracked paths, objects, tree, object format,
   and dirty state; an optional declared ignored inventory separately records
   bounded content-free local evidence through no-follow descriptors.
3. Portable scanners emit candidates anchored to the exact scanned blob or
   repository tree; declared native adapters emit bounded execution evidence.
4. Review records bind decisions to exact report and policy digests.
5. Desired-state profiles resolve adopter rules and typed project variables.
6. Gap records become dependency-ordered remediation plans only after evidence
   and approval gates pass.

Portable scanner scope is projected from one typed language-capability
registry. The registry separately records unreadable-content scope,
responsibility metrics, polyglot ownership, dependency-parser families, and
deterministic extensionless/index resolution order. This keeps deliberate
differences explicit: YAML is scope-only; Python, stubs, and shell participate
in responsibility review but not polyglot ownership; native languages without
a relative-import parser still participate in dedicated-test ownership.

Repository-relative source roots use whole-component prefix containment and
choose the most specific overlapping owner. Test roots use whole contiguous
components at any repository depth. Common test names are shared, while
singular and plural native suffixes are a deliberate polyglot-only extension.
Resolved filesystem containment is available for non-security-sensitive path
classification; descriptor-bound no-follow inventory remains authoritative at
filesystem trust boundaries.

Pack resolution and reviewer clearance cross an explicit cryptographic trust
boundary. Detached Ed25519 signatures cover a versioned framed message with a
length-prefixed protocol domain and canonical digest bytes. Standard packs use
`rigor-foundry.standard-pack.v1`; reviewer attestations use
`rigor-foundry.reviewer-attestation.v1`. Public keys live in integrity-bound
trust stores, and every clearance path reverifies the signature rather than
trusting serialized booleans or proof labels. Raw-digest signatures and
domainless legacy envelopes are not accepted.

The records stay separate so that missing evidence, accepted risk, failed
controls, and completed remediation cannot be collapsed into a misleading
boolean. The normative design and module map are maintained in
[ARCHITECTURE.md](https://github.com/anulum/rigor-foundry/blob/main/ARCHITECTURE.md).
The [digest-dependency graph](digest-dependencies.md) defines every
unconditional identity edge, its stable non-edges, and the production mutation
proofs required for a schema change.

The tracked classified-residual contract records fail-closed race windows,
platform primitives, and runtime invariants that cannot be exercised honestly
through supported public surfaces. Every entry binds an exact symbol digest,
guard, owner, public regressions, revisit triggers, and a maximum 90-day review
window. Preregistered negative searches prevent those residuals from becoming
an excuse to restore private-helper tests or monkeypatched production
internals. Repository audit and CI enforce the contract.

## Candidate evidence boundary

Tracked-blob anchors contain the repository-relative path, inclusive line span,
exact Git blob identity of the bytes inspected, and their SHA-256. For dirty
tracked files, Git's canonical blob framing is computed over the worktree bytes
without writing an object; the stage-zero index identity is not substituted.
This applies to text, binary, non-UTF-8, symlink, and oversized tracked content.
Regular files use one no-follow descriptor and one pass for SHA-256 and Git
blob hashing. A changed byte count, descriptor snapshot, or pathname identity
aborts inventory construction rather than emitting a mixed anchor.

Repository-tree anchors contain a repository-relative locus, fixed state span
`1:1`, exact HEAD tree identity, and the complete tracked-content SHA-256. They
are used for missing policy, missing registries, missing test owners, gitlinks,
and other absence or repository-wide findings. They never claim that an absent
path has a blob.

Candidate identifiers bind the complete anchor. Report schema 1.3 also records
the Git object format and digest-bound ignored evidence, so SHA-1 and SHA-256 repositories cannot be
reinterpreted. Every anchor is checked against the same inventory before report
construction. Human-readable excerpts remain separate, whitespace-normalised,
and limited to 512 UTF-8 bytes; large member sets carry a full count and
SHA-256 with a bounded deterministic prefix.

## Isolation boundary

Git plumbing never resolves from ambient `PATH`. The default platform policy
uses fixed installation roots; operators can replace it with explicit absolute
roots and a bounded supported-version interval. Symlinked paths, version drift,
and executable replacement fail closed. Repository-local filesystem monitors
and hooks are disabled for plumbing calls, and report/campaign digests retain
the observed executable identity plus its complete versioned trust policy.
No-follow descriptor-relative component walks bind validation to hashing and
execution; a platform without descriptor execution fails closed.

Native tools execute with resolved binaries, argv-only invocation, bounded
output, and timeouts. Bubblewrap itself crosses a separate host-trust boundary:
a versioned policy constrains its fixed path, owner/mode/link state, semantic
version, dpkg-reported package association/version/architecture/status,
package-query executable, and required option surface. The dpkg fields are not
a repository-signature or payload-checksum proof; the executable SHA-256 is the
observed binary identity. Enforcement and campaign artifacts retain the
complete provenance, and pre/post execution inspection rejects drift. The
sandbox disables nested
user namespaces in addition to unsharing the initial network and mount state.

On GitHub's Ubuntu 24.04 runners, the path-specific AppArmor profile only
permits `/usr/bin/bwrap` to create the initial user namespace while the global
restriction remains enabled. `flags=(unconfined)` is an explicit compatibility
attachment, not a claimed confinement layer; the attested Bubblewrap arguments
define the native-audit sandbox.

Remediation work is designed for exact path claims and independent worktrees
so non-conflicting procedures can proceed concurrently without sharing a
mutable staging area.

## Campaign promotion boundary

Campaign schema 1.8 binds every run to an explicit provider, exact model,
model-correlation family, and operator. Comparison groups all runs with one
correlation family or one provider/exact-model pair into transitive connected
components. Each component is one witness and binds the exact participating
attestation, report, review, and witness digests. A promotion campaign is
eligible only when it is otherwise resolved and contains at least two witnesses
and two declared operator identities. Operator labels are declarations; access
control or a future signature layer must authenticate the submitting operator.
Witness schema 1.2 preserves canonical provider/exact-model pairs, and strict
comparison parsing rejects any family or exact pair shared by two components.

Promotion reloads the ignored durable campaign, runs, reviews, and comparison;
opens every path through no-follow directory descriptors, requires single-link
bounded record files, revalidates schema and campaign relations, reconstructs
the comparison, and admits only a report and review that participated in that
exact comparison. Diagnostic campaigns, same-family repetition, and exact-model
aliasing cannot authorise promotion.
