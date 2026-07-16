# Architecture

RigorFoundry treats a repository audit as an evidence pipeline, not a verdict
generator.

1. A fixed-root Git trust policy selects one non-symlink executable and binds
   its path, root, version, executable digest, and policy digest.
2. Git inventory freezes the exact tracked paths, objects, tree, and dirty
   state with that continuously revalidated executable.
3. Portable scanners and declared native adapters emit review candidates.
4. Review records bind decisions to exact report and policy digests.
5. Desired-state profiles resolve adopter rules and typed project variables.
6. Gap records become dependency-ordered remediation plans only after evidence
   and approval gates pass.

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
