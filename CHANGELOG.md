# Changelog

All notable changes to RigorFoundry are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Package publication now grants release-asset write access only to the
  protected publication job so Sigstore bundles can be attached. Owner-confirmed
  recovery may run from the named tag or the repository default branch, but
  always validates and builds its fully qualified tag ref with checkout
  credential persistence disabled. Signing bundles are moved out of the
  distribution directory before attestation and PyPI upload. The signing
  action's broad native release uploader is disabled; one repository-controlled
  step attaches only the two validated bundle paths. Default-branch recovery
  uses a time-bounded PyPI environment policy that is removed after the run.

## [0.1.1] - 2026-07-16

### Fixed

- Package publication now gates automated release events on the repository
  owner actor rather than the workflow-created draft author. An owner-only,
  explicitly confirmed recovery dispatch binds its Git ref to the requested
  tag and verifies the published release before entering the protected PyPI
  environment.
- CI, release assembly, and PyPI publication now inspect the real built wheel
  and reject package identity drift, missing registry/install guidance, and
  pre-publication status text.
- Public status and installation documentation now distinguish the immutable
  GitHub/GHCR-only `v0.1.0` release from registry-verified Python packages.
- CI-facing repository guards and the composed self-audit now emit only fixed
  pass/fail status, including when validation raises. Secret findings retain
  full SHA-256 path identifiers for trusted in-process consumers without
  exposing candidate values, adversarial filenames, or tracebacks through
  guard output.

## [0.1.0] - 2026-07-16

### Added

- Standalone Apache-2.0-licensed repository, package, CLI, documentation, tests, and
  build configuration recovered from the originating audit lane.
- Evidence-bound candidate, review, enforcement, promotion, and independent
  campaign records.
- Reproducible hash locks, strict repository guards, non-root container image,
  focused local hooks, and CI-owned Python 3.11–3.13 coverage gates.
- SHA-pinned CodeQL, OpenSSF Scorecard, dependency, Semgrep, documentation,
  container, release, provenance, signing, and OIDC publication workflows.
- A repository-owned 14-domain audit policy, executable self-audit controls,
  retained CI evidence, and a dependency-free local-only data guard.
- Digest-bound standard packs, typed project profiles, bounded conditions,
  fail-closed effective-profile resolution, evidence-bound control assessments,
  and advisory remediation plans.
- Typed public/internal/secret variables with opaque provider references,
  finite authorised waivers, contradiction evidence, and exact pack pins.
- Crash-durable ignored internal storage and digest-bound work lifecycle records
  for independent verification and closure.
- Dedicated risk-acceptance waiver identities, exact assessment-body reviewer
  attestations, adapter-domain evidence binding, and command-bound remediation
  and rollback plans.
- Fixed-root Git executable trust policy, version and replacement enforcement,
  and content-addressed Git provenance with its complete verifiable policy in
  reports and campaign contracts.
- A versioned Bubblewrap compatibility policy and structured, secret-free
  provenance binding executable SHA-256, semantic version, required options,
  trusted `dpkg-query` identity, and dpkg-reported package-database fields.
- A component-safe trusted-executable runner with descriptor-pinned execution,
  streaming aggregate output limits, deadlines, and process-group termination.
- A public versioned Ed25519 message encoder with distinct standard-pack and
  reviewer-attestation domains and cross-protocol replay regressions.
- A versioned machine-readable digest-dependency graph, first-class policy and
  review identities, and a strict task-definition-bound work-closure record.
- An expiring classified coverage-residual manifest, public validation command,
  source-symbol binding, public-regression references, and preregistered
  negative searches that prohibit simulated security-boundary coverage.

### Changed

- Product identity, imports, entry points, rule-pack identity, and public
  documentation now use RigorFoundry rather than the originating adopter
  repository.
- The container package source is frozen to an exact Debian snapshot in
  addition to the digest-pinned base image.
- Shared audit primitives and remediation-graph validation were separated from
  their record facades so every production source module remains below the
  repository's 700-line authoring threshold.
- Report and campaign schemas advance to 1.1 so executable provenance is a
  required, integrity-bound input rather than optional metadata. The unchanged
  review-ledger schema remains at 1.0.
- Campaign persistence and TODO promotion require ignored-path checks to
  reproduce the evidence-bound Git identity.
- Enforcement schema 1.1 and campaign schema 1.3 require complete structured
  sandbox provenance, reject unknown envelope fields, and compare full native
  adapter evidence including missing, extra, and duplicate results.
- Campaign schema 1.3 binds tracked-file count, scanner identity, the complete
  Git provenance record, and toolchain identity through one validator used by
  attestation build, durable store/load, and comparison.
- Digest-dependency schema 1.1 adds Git provenance and toolchain identities,
  including their direct report, campaign, comparison, and effective-profile
  propagation contracts.
- GitHub native-audit jobs use Ubuntu 24.04 explicitly and verify the compatible
  Bubblewrap version, dpkg association, option surface, initial sandbox, and
  nested-userns denial.
- Standard packs advance to schema 1.1; pack signatures and verification
  evidence gain schema 1.0 domain envelopes; reviewer attestations advance to
  schema 2.0. Unchanged nested pack components remain at schema 1.0.
- The built-in rule pack advances to version 1.1.0. Its digest now binds an
  explicit schema and pack-version envelope in addition to every ordered rule
  definition; older report identities must be regenerated without fallback.

### Fixed

- Release-tag validation now uses only the Python standard library, allowing
  release, container, and package-publication jobs to validate exact version
  metadata before the project package is installed.

### Security

- Git plumbing ignores ambient `PATH` and `GIT_*` state, rejects symlinked
  executable roots and paths, enforces a supported version interval, and
  revalidates executable identity and SHA-256 before and after every command.
  Repository-local filesystem monitors and hooks are disabled for plumbing
  calls.
- Pack and reviewer Ed25519 verification signs a versioned, length-prefixed
  protocol-domain message. Legacy raw-digest signatures and domainless records
  are rejected rather than accepted through a compatibility fallback.

- Native repository commands execute validated argv with the active locked
  Python environment, mandatory timeouts, bounded output, and no shell.
- Bubblewrap and `dpkg-query` are opened without following path components,
  validated and hashed through retained descriptors, and executed through
  those exact descriptors. Dpkg fields attest database association only, not a
  repository signature or installed-payload checksum.
- Ubuntu 24.04 CI retains the targeted `flags=(unconfined) { userns, }`
  compatibility attachment while keeping global user-namespace mediation
  enabled; the complete Bubblewrap argv, not that AppArmor attachment, defines
  and is bound into the sandbox identity.
- Native Python controls preserve the active virtual-environment launcher
  instead of resolving its symlink to an ambient system interpreter.
- Local preflight subprocesses enforce explicit hard wall-clock timeouts and
  report timeout exit status `124`.
- Git, Bubblewrap, trusted-executable, adapter, rule-pack, digest, and preflight
  tests use public APIs and real process/filesystem behavior; intentionally
  unreachable fail-closed guards are explicit expiring residuals rather than
  monkeypatched coverage claims.
- Release publication produces a draft for human approval and the publish job
  remains protected by the PyPI environment and OIDC.
