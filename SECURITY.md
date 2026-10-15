# Security Policy

## Reporting

Do not disclose suspected vulnerabilities in a public issue. Email
[protoscience@anulum.li](mailto:protoscience@anulum.li). When GitHub private
vulnerability reporting is enabled for the repository, its
[advisory form](https://github.com/anulum/rigor-foundry/security/advisories/new)
is also accepted.

Include the affected command or API, repository state, expected safety
boundary, observed behaviour, and a minimal reproducer that contains no secret
or private repository content.

## Supported versions

Security reports are accepted for the latest published release and the public
`main` development branch. Determine the published version from the
[release history](https://pypi.org/project/rigor-foundry/#history), separately
from the source version in `pyproject.toml`. Superseded patches are assessed
when the reported issue also affects the latest release; they do not receive
a separate backport guarantee. No long-term support line is designated.

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
- Ed25519 signatures cover a versioned framed message with a length-prefixed
  protocol domain and canonical payload digest. Standard-pack and reviewer
  domains are distinct; raw-digest signatures, absent domains, and legacy
  envelopes fail closed without compatibility verification.
- Writes require an explicit command and stay within validated ignored paths.
- Secret profile variables store provider references, never secret values.
- CI actions are pinned to full commit SHAs. Runtime-fetched executable assets,
  bundles, and container images are content-addressed; third-party Python
  dependencies are hash locked.
- GitHub-hosted runner and official `setup-python` provisioning retain a
  provider-managed manifest residual with exact release selectors and
  repository/lockfile-scoped caches; public issue 9 tracks closure.
- The consumer Action passes all caller inputs through quoted environment
  variables, installs the exact checked-out source with hash-locked build and
  runtime dependencies, refuses existing or Git-controlled output targets, and
  exposes no promotion or remediation operation. The distributed system
  pre-commit hook requires a separately hash-locked installation and defaults
  to a staged observe gate without native-audit consent.
- `.github/dependency-waivers.json` must contain an empty waiver set. The
  repository guard rejects advisory exceptions, ignored vulnerability findings,
  disabled scanner commands and missing blocking lock-audit enrolment.
- Container package installation uses the exact Debian snapshot associated with
  the pinned base-image digest; vulnerability findings block rather than
  silently selecting newer mutable packages.
- Release publication requires an exact version tag and owner-published
  release, and uses OIDC rather than a stored package credential. The manual
  recovery path accepts the named tag or the repository default branch as its
  dispatch ref, then checks out the fully qualified release tag and verifies
  its published release. Package content always comes from that tag.
  Required-reviewer environment protection remains a separate
  promotion gate.

## Toolchain dependency policy

The current security lock selects Semgrep `1.180.0` and Click `8.4.2`, with
SHA-256 hashes and the complete CI constraints. The waiver manifest is empty
and its guard requires that state. Earlier dated validation records describe
their original dependency sets; they do not authorise an exception today.

The Security workflow audits every committed dependency lock and runs the
repository Semgrep policy with errors blocking the job. The actual locks,
waiver guard and workflow define this policy; their presence does not prove a
current hosted audit result or the absence of vulnerabilities. See the
[dependency audit and regeneration contract](docs/security.md#dependency-advisory-audits).

## Coordinated disclosure

The maintainer will acknowledge a complete report, assess severity and affected
versions, coordinate a fix and advisory, and credit reporters who request
credit. Public disclosure timing is agreed with the reporter after a fix or
mitigation is available.
