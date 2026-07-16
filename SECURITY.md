# Security Policy

## Reporting

Do not disclose suspected vulnerabilities in a public issue. Email
[protoscience@anulum.li](mailto:protoscience@anulum.li). When GitHub private
vulnerability reporting is enabled for the repository, its
[advisory form](https://github.com/anulum/RIGOR-FOUNDRY/security/advisories/new)
is also accepted.

Include the affected command or API, repository state, expected safety
boundary, observed behaviour, and a minimal reproducer that contains no secret
or private repository content.

## Supported versions

No public version has been released. Security reports against the public
development branch are accepted, but there is no published support guarantee.
Support policy will be versioned before the first release.

## Threat model

RigorFoundry processes adversarial repository paths and content. Security
reviews prioritise:

- shell injection and executable substitution in native adapters;
- path traversal, symlink escape, gitlink handling, and writes outside ignored
  audit roots;
- unsafe parsing, unbounded file/process output, denial of service, and archive
  expansion;
- stale evidence, digest substitution, policy weakening, and cross-repository
  promotion;
- secret leakage in reports, logs, profiles, pack variables, and remediation
  output;
- forged or replayed pack and reviewer signatures, unknown signing keys, and
  trust-store substitution;
- action, package, base-image, and release supply-chain integrity.

## Security invariants

- Scanner input is the fail-closed Git-tracked inventory.
- Git's container ownership exception is process-local and narrows to the exact
  audited root; no persistent or normal-operation wildcard is configured.
- Native audits require explicit operator consent and run argv-only with
  `shell=False` inside a no-network bubblewrap sandbox. The repository and
  runtime are read-only, the child runs as an unprivileged user, and only a
  fixed credential-free environment reaches it.
- Native output is streamed into a hard aggregate byte cap; raw command text,
  environment values, and output are never serialized. Timeout or output-cap
  breaches terminate the process tree and fail closed.
- Native evidence binds specification, executable, command, environment, the
  complete Bubblewrap argument contract, compatibility policy, executable
  SHA-256, semantic version, and dpkg-reported association to the exact report
  and gate digest. The dpkg fields are package-database evidence, not a
  repository-signature or installed-payload checksum; the executable digest is
  the observed binary identity.
- Missing evidence cannot become pass.
- Writes require an explicit command and stay within validated ignored paths.
- Secret profile variables store provider references, never secret values.
- CI actions are pinned to full commit SHAs and third-party dependencies are
  hash locked.
- Dependency exceptions are advisory-, package-, version-, command-, and
  expiry-bound in `.github/dependency-waivers.json`; repository audit fails on
  drift or expiry.
- Container package installation uses the exact Debian snapshot associated with
  the pinned base-image digest; vulnerability findings block rather than
  silently selecting newer mutable packages.
- Release publication requires an exact version tag and owner-published
  release, and uses OIDC rather than a stored package credential.
  Required-reviewer environment protection remains a separate promotion gate.

## Current toolchain exception

`PYSEC-2026-2132` affects `click.edit`. Semgrep 1.170.0 requires Click 8.1.8,
while the advisory is fixed in a version outside Semgrep's declared range.
RigorFoundry permits only the fixed, non-interactive repository scan command;
the ephemeral security environment does not call `click.edit`. The exact
exception expires on 2026-08-14 and blocks CI and repository audit if the lock,
command, advisory, or date drifts. It must be removed as soon as the upstream
constraint admits a fixed Click release.

## Coordinated disclosure

The maintainer will acknowledge a complete report, assess severity and affected
versions, coordinate a fix and advisory, and credit reporters who request
credit. Public disclosure timing is agreed with the reporter after a fix or
mitigation is available.
