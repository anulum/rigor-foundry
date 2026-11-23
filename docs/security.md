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
- Built-in profiles copy only exact clean tracked regular files into a bounded
  read-only snapshot, mount the analyser from a retained descriptor, and bind
  executable, configuration, input, version-output, output, and profile
  digests. Ignored/untracked files, symlinks, gitlinks, hard links, concurrent
  replacement, malformed output, timeouts, truncation, and analyser errors
  cannot become clean evidence. The offline Trivy profile claims only
  misconfiguration and secret scanning, never CVE or supply-chain coverage.
  The offline OSV profile requires an exact tracked database manifest, verifies
  every externally supplied official-layout archive without following links,
  and mounts only the verified snapshot into the no-network sandbox. Missing,
  mutated, linked, malformed, unsafe, or oversized database content is
  unavailable evidence, never a clean result. OSV matches do not establish
  reachability, exploitability, remediation priority, or an adjudicated verdict.
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
- CI actions, Python dependencies, the base image, downloaded executables,
  CodeQL bundle, BuildKit image, and local Docker-action images are immutably
  pinned. Project-controlled release downloads verify the retained manifest
  and final executable or archive before use.
- GitHub-hosted `ubuntu-24.04` and official `setup-python` provisioning retain
  a bounded provider-managed manifest residual. Runner labels, action commits,
  and Python patch releases are exact; cache identity is repository- and
  lockfile-scoped. [Issue 9](https://github.com/anulum/RIGOR-FOUNDRY/issues/9)
  tracks the remaining per-artifact identity gap.
- The consumer Action pins its nested action and hash-locks build/runtime
  installation. Inputs cross the shell boundary only through quoted
  environment values. Output targets must be absent, and in-repository targets
  must be untracked and ignored. The system pre-commit hook requires a
  separately hash-locked RigorFoundry installation. Both defaults are
  observe-only and carry no promotion or remediation command.
- Package publication uses a protected OIDC environment rather than a stored
  package credential. The rebuilt wheel and source distribution must match the
  same-named published GitHub Release assets before signing.

## Dependency advisory audits

The Security workflow audits all ten hash-locked Python profiles (bootstrap,
build, CI, fuzz, native, provenance, runtime, security, test and test-windows) and
the VS Code extension's committed npm lock on every push and pull request to `main`.
The isolated Semgrep lock is the one committed lock outside this audit; see
[Semgrep outside the dependency audit](#semgrep-outside-the-dependency-audit). Python audits
require hashes, avoid installation and fail when dependency collection fails.
The npm audit includes development dependencies and uses the default failure
threshold. Advisory findings and registry errors block the jobs.

The repository's dependency-waiver guard also checks the actual Git-visible
lock inventory, exact scanner commands, event enrolment and the aggregate
`security-gate`. Both scanner jobs must succeed, including when one is skipped
or cancelled. Adding another lock requires explicit audit enrolment; an
unsupported lock fails the guard. The guard names the isolated Semgrep lock as
the only exception. The current waiver set must remain empty; the
guard rejects a nonempty set and any `--ignore-vuln` workflow option.
These source checks do not prove that hosted branch protection requires the
gate or that the current head has passed a hosted audit.

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

Report suspected vulnerabilities through a private channel listed in the
[security policy](https://github.com/anulum/rigor-foundry/security/policy).


## Security-tool lock maintenance

The security lock pins Bandit, pip-audit and PyYAML. Semgrep has its own
isolated lock, `requirements/semgrep.txt`, which pins Semgrep `1.184.0`.
Both retained generation headers name `pip-compile` on Python 3.11, matching
the repository lock target. Use a Python 3.11 environment with the `pip-tools`
version pinned in `requirements/ci.txt` and retain the complete CI constraints
and SHA-256 hashes. Regenerate from the repository root:

```sh
python3.11 -m piptools compile --allow-unsafe --generate-hashes --strip-extras \
  --upgrade --constraint requirements/ci.txt \
  --output-file requirements/security.txt requirements/security.in
python3.11 -m piptools compile --allow-unsafe --generate-hashes --strip-extras \
  --upgrade --constraint requirements/ci.txt \
  --output-file requirements/semgrep.txt requirements/semgrep.in
```

Keep the canonical seven-line licence header above the generated header.
After regeneration, run the strict audit and install the entire hash-locked
security profile in a fresh environment, then run pip check and Bandit.

### Semgrep outside the dependency audit

Semgrep `1.184.0` runs outside `pip-audit`. Every Semgrep release up to
`1.186.0` pins `mcp==1.29.0`, the OpenTelemetry `1.37` line and `wcmatch` `8.x`,
and no compatible release resolves their advisories. The repository refuses
audit waivers, so the owner decided on 2026-11-23 to keep Semgrep and the
packages only it needs out of every audited profile instead.

- **The repository policy scan** runs the official image
  `docker.io/semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed`
  without network access, with a read-only root and a read-only workspace, an
  explicit finite stack limit, and metrics and the version check off:

  ```sh
  docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --ulimit stack=8388608:8388608 --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --env SEMGREP_SEND_METRICS=off --env SEMGREP_ENABLE_VERSION_CHECK=0 \
    --volume "$PWD:/src:ro" --workdir /src \
    docker.io/semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed \
    semgrep scan --error --metrics off --config .semgrep.yml src tools
  ```

- **The scanner tests** use the hash-locked `requirements/semgrep.txt`,
  installed into its own environment at `$pythonLocation/rigor-semgrep-venv`.
  The `semgrep` and `pysemgrep` entry points are copied into
  `$pythonLocation/bin` as regular files with mode `0755`, so the trusted
  executable checks and the adapter sandbox are the same as for any other
  installed tool. The audited interpreter cannot import Semgrep, and
  `python -m tools.check_semgrep_isolation` refuses a virtual environment, an
  importable `semgrep` module and any distribution that only the isolated
  lock pins.
- **One version in both places.** The dependency audit guard requires the image
  tag to equal the isolated lock's Semgrep pin, the image to carry a digest,
  and no audited lock to pin Semgrep. Move the image digest and the isolated
  lock in the same change.

The security job uses Python `3.15.2` and installs the hash-locked security and
test profiles and the isolated Semgrep environment. Before dependency audits,
it exercises the actual clean scan, both repository-rule refusals and a missing
scanner through `tests/test_semgrep_runtime.py`, requiring 100% coverage of that
complete test owner. The dependency-waiver guard requires this unconditional
step, the isolation guard and the image policy scan.
The dependency audit checks the optional provenance verifier lock with
the same hash verification and blocking result as the runtime lock.

The launcher requires a finite host soft
stack limit and lowers its own hard stack to that same value before replacing
itself with the installed scanner. This bounds Semgrep's native child-process
stack on Python 3.15 without changing the caller's limits or system settings.
An unlimited soft stack or missing scanner fails before scanning; findings and
scanner errors retain their original nonzero exit status. The arguments and
repository rules are unchanged. The local lock qualification does not establish
hosted CI or runtime admission.
