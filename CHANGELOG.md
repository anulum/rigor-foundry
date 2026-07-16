# Changelog

All notable changes to RigorFoundry are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
- Enforcement schema 1.1 and campaign schema 1.2 require complete structured
  sandbox provenance, reject unknown envelope fields, and compare full native
  adapter evidence including missing, extra, and duplicate results.
- GitHub native-audit jobs use Ubuntu 24.04 explicitly and verify the compatible
  Bubblewrap version, dpkg association, option surface, initial sandbox, and
  nested-userns denial.
- Standard packs advance to schema 1.1; pack signatures and verification
  evidence gain schema 1.0 domain envelopes; reviewer attestations advance to
  schema 2.0. Unchanged nested pack components remain at schema 1.0.

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
- Release publication produces a draft for human approval and the publish job
  remains protected by the PyPI environment and OIDC.
