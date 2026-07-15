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

### Changed

- Product identity, imports, entry points, rule-pack identity, and public
  documentation now use RigorFoundry rather than the originating adopter
  repository.
- The container package source is frozen to an exact Debian snapshot in
  addition to the digest-pinned base image.
- Shared audit primitives and remediation-graph validation were separated from
  their record facades so every production source module remains below the
  repository's 700-line authoring threshold.

### Security

- Native repository commands execute validated argv with the active locked
  Python environment, mandatory timeouts, bounded output, and no shell.
- Native Python controls preserve the active virtual-environment launcher
  instead of resolving its symlink to an ambient system interpreter.
- Local preflight subprocesses enforce explicit hard wall-clock timeouts and
  report timeout exit status `124`.
- Release publication produces a draft for human approval and the publish job
  remains protected by the PyPI environment and OIDC.
