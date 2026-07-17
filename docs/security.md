# Security

Treat repository names, paths, file content, configuration, native-tool output,
and archive members as adversarial input.

- Inventory resolves Git only from fixed or operator-declared trust roots,
  rejects symlinked roots/components, enforces a half-open version interval,
  hashes the executable, pins the validated descriptor where the platform
  exposes descriptor execution, and detects replacement before and after every
  command. Platforms without a descriptor execution path fail closed.
  Multi-link executables are rejected; POSIX mode checks also reject
  group/world-writable and elevated-ID executables at validation and hashing.
  Snapshot and execution opens walk every absolute component through no-follow
  directory descriptors, so a post-validation intermediate symlink cannot
  become the trusted baseline.
- Git plumbing receives a minimal environment without ambient configuration,
  credentials, prompts, replacement objects, or optional index locks. The
  runner disables repository-local filesystem monitors and redirects hooks to
  a reserved absent path under the trust root. The declared trust root must
  itself be protected from untrusted writers; an occupied reserved hook path
  fails closed.
- Native processes require explicit consent and use fixed-root executable
  resolution, argv-only invocation, a credential-free environment, a
  no-network read-only bubblewrap sandbox, mandatory timeouts, process-tree
  termination, disabled nested user namespaces, and a streaming aggregate
  output hard cap. Bubblewrap must satisfy a versioned compatibility policy;
  evidence records its semantic version, executable digest, dpkg-reported
  package association/version/architecture/status, package-query executable
  digest, required-option surface, and policy identity, then verifies the same
  identity after execution.
- Gate and campaign artifacts retain native execution digests, bounded counts,
  and structured secret-free sandbox provenance; raw argv, environment values,
  source excerpts, command output, and package-manager output are excluded.
  The dpkg association is package-database evidence, not proof of a repository
  signature or installed-payload checksum; the executable digest identifies
  the inspected and executed binary bytes.
- Repository policies must be tracked, non-symlink UTF-8 files inside the
  audited root, and Git index modes and object ids bind every tracked entry.
- Bootstrap writes walk existing parents through retained no-follow directory
  descriptors, create single-link regular files with exclusive creation,
  synchronize file and parent metadata, and revalidate root, parent, path, and
  Git tracked/ignored state before returning. A review ledger present at either
  validation sample is rejected; absence is not an atomic reservation, so a
  concurrent creator can populate the declared path after the final sample. A
  failed two-file attempt preserves any file it created as incident evidence:
  pathname-based rollback is intentionally forbidden because POSIX cannot
  atomically prove an inode identity and unlink that same inode. Concurrently
  replaced data is never deleted by bootstrap.
- Writes require an explicit command and a validated ignored destination.
  Campaign persistence and TODO promotion require the ignored-path check to
  reproduce the executable provenance already bound to the durable evidence.
- Missing evidence never becomes pass.
- External source capture records declared HTTPS acquisition metadata and exact
  retained bytes; it is not publisher-signature or source-authority proof.
  Verification runs offline, is scoped to the explicit retrieval policy, and
  grants no remediation, waiver, suppression, or promotion authority.
- SARIF export validates every supplied review against the exact report and
  retains unreviewed or `needs-evidence` candidates as review results. Only a
  completed `valid` review supplies defect severity. Repository-relative paths
  are URI-encoded while exact anchor paths and object identities remain in the
  RigorFoundry property bag.
- Pack and reviewer clearance requires real Ed25519 verification against an
  explicit integrity-bound public-key trust store. The signed message includes
  a versioned length-prefixed protocol domain, so standard-pack signatures
  cannot replay as reviewer attestations even when a key is shared. Legacy
  raw-digest signatures and domainless envelopes fail closed. Key identifiers
  and raw public keys must both be unique, so aliases for one underlying key
  cannot satisfy independent-review quorum; labels and digest-shaped strings
  do not establish trust.
- CI actions, Python dependencies, and the base image are immutably pinned.
- Package publication uses a protected OIDC environment rather than a stored
  package credential.

## GitHub-hosted AppArmor boundary

Ubuntu 24.04 mediates unprivileged user namespaces and requires applications
that need them to be explicitly allowed by an AppArmor profile. The CI runner
therefore retains a path-specific `/usr/bin/bwrap` profile with
`flags=(unconfined)` and one `userns,` rule. This profile is deliberately not
claimed as the native-audit sandbox: it is only the compatibility attachment
that lets the root-owned Bubblewrap executable create the initial namespace.
The audited Bubblewrap argument contract supplies the read-only, no-network,
credential-free boundary and disables nested user namespaces. See Ubuntu's
[unprivileged user namespace restriction](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/#apparmor-unprivileged-user-namespace-restrictions)
and Bubblewrap's
[sandbox security contract](https://github.com/containers/bubblewrap#sandbox-security).

CI remains pinned to the Ubuntu 24.04 runner family, asserts that the global
restriction is still enabled, loads only the path-specific profile, records
the installed package/version, and executes the same compatibility flags in a
smoke sandbox. Regression tests reject a global sysctl disable, additional
AppArmor permissions, profile removal, or omission of nested-userns disabling.
A compromised runner administrator, kernel, root-owned package database, or
root-owned launcher is outside this boundary; RigorFoundry detects identity or
package drift during an audit but does not claim to withstand a compromised
host root.

Do not disclose a suspected vulnerability in a public issue. Follow the
[security policy](https://github.com/anulum/rigor-foundry/security/policy) and
use private vulnerability reporting.
