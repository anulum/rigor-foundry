# Architecture

RigorFoundry treats a repository audit as an evidence pipeline, not a verdict
generator.

1. Git inventory freezes the exact tracked paths, objects, tree, and dirty
   state.
2. Portable scanners and declared native adapters emit review candidates.
3. Review records bind decisions to exact report and policy digests.
4. Desired-state profiles resolve adopter rules and typed project variables.
5. Gap records become dependency-ordered remediation plans only after evidence
   and approval gates pass.

Pack resolution and reviewer clearance cross an explicit cryptographic trust
boundary. Detached Ed25519 signatures cover canonical digest bytes, public keys
live in integrity-bound trust stores, and every clearance path reverifies the
signature rather than trusting serialized booleans or proof labels.

The records stay separate so that missing evidence, accepted risk, failed
controls, and completed remediation cannot be collapsed into a misleading
boolean. The normative design and module map are maintained in
[ARCHITECTURE.md](https://github.com/anulum/RIGOR-FOUNDRY/blob/main/ARCHITECTURE.md).

## Isolation boundary

Native tools execute with resolved binaries, argv-only invocation, bounded
output, and timeouts. Remediation work is designed for exact path claims and
independent worktrees so non-conflicting procedures can proceed concurrently
without sharing a mutable staging area.
