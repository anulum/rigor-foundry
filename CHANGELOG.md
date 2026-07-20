# Changelog

All notable changes to RigorFoundry are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- A digest-bound proposed-1.0 compatibility contract classifies and ratchets
  the stable package-level Python imports, every installed CLI command with its
  option and positional spellings, and 59 explicitly inventoried schema
  versions. An AST completeness guard rejects any unclassified non-private
  production schema declaration. `rigor contract` emits the exact manifest
  without repository or network access; incompatible wire changes require a
  new schema identifier and explicit migration rather than reinterpretation.

- Optional policy schema 1.4 explicitly activates CR001–CR006 CRA readiness
  candidates over tracked CVD policy and a locked append-only CRA evidence
  snapshot. A bounded no-follow directory manifest and post-replay digest
  prevent mixed-state reports; schema 1.3 and absent/not-applicable scope
  remain inert. Fixed-vulnerability advisory revisions are prepare-only, the
  externally keyed `cra-pack` command emits a real signed StandardPack, and the
  built-in CRA crosswalk preserves supporting, partial, and unsupported
  relations without a compliance claim. All CR rules enter maturity probation.

- Imported-only CRA component inventories validate bounded CycloneDX 1.5/1.6
  and SPDX 2.3 JSON profiles, retain exact source bytes and operator-declared
  coverage, bind Git tree and tracked-content identity, and append explicit
  drift evidence. A complete offline OSV adapter finding can supply exact
  awareness evidence to an explicit `vuln-register` invocation, but never
  substitutes for separately supplied active-exploitation evidence.
- A stable no-network `rigor verify` path verifies signed audit reports,
  reviews, StandardPacks, and model-alias declarations against a separate
  caller-selected key-lifecycle policy. Schema-1.0 bundles and replayable
  results preserve tamper, wrong-domain, revocation, expiry, alias-collapse,
  stale, and unavailable-evidence states without granting assurance, fleet, or
  remediation authority.
- A schema-1.0 content-addressed report-diff record partitions exact candidate
  identities into retained, appeared, resolved, and anchor-changed evidence.
  Deterministic replay binds both reports; compatibility changes and ambiguous
  relocations require explicit operator declarations. The CLI supports
  integrity-verified historical rule packs without treating candidate drift as
  correctness, chronology, regression, or remediation proof.
- An offline CRA Article 14 preparation lane stores strict content-addressed
  product and event records, computes separate vulnerability and severe-
  incident clocks, prepares deterministic stage and user-notice payloads,
  binds operator-supplied receipts and explicit already-provided skips, and
  replays ignored append-only state through eight installed CLI commands. It
  contains no network client and makes no legal, conformity, authority-
  acceptance, or successful-submission claim.
- An API-compatibility rule compares literal module-level Python `__all__`
  declarations with a strict tracked root manifest. Missing, dynamic,
  mismatched, unrecorded, stale, malformed, and non-text states remain anchored
  digest-only review candidates in maturity probation; the rule never infers a
  breaking change from arbitrary source edits.
- A performance/reproducibility rule flags import-bound wall-clock calls in
  Python test assertions unless a local freeze or dominating monkeypatch makes
  the timestamp explicit. It remains an anchored review candidate in maturity
  probation.
- Operations rules flag builtin output in Python library owners and
  credential-named expressions passed to import-bound logging calls. Both
  remain anchored review candidates in maturity probation.
- Scientific/numerical rules flag direct float-literal equality in Python
  tests and supported stochastic APIs used without deterministic local seeds.
  Both remain anchored review candidates in maturity probation.
- Documentation rules flag missing SPDX source headers and explicit public
  package-version guidance that drifts from static PEP 621 metadata. Both emit
  anchored review candidates and remain in maturity probation.
- A workspace-scoped VS Code extension displays structurally checked audit
  evidence and review sources, opens exact tracked-blob spans, runs scans only
  on explicit commands, and delegates canonical review validation to the real
  `rigor` CLI. Strict TypeScript unit tests, a real Extension Development Host
  test, and a hash-pinned VSIX build keep the editor layer outside remediation
  and promotion authority.
- A per-rule maturity schema keeps every rule in probation until an explicit
  adopter policy is met by source-bound completed reviews, distinct repository
  and reviewer declarations, positive adjudications, bounded false-positive
  rate, and retained reviewer-effort references. A real-file case manifest and
  CLI command derive the content-addressed assessment without universal
  threshold claims.
- A deterministic SARIF 2.1.0 exporter exposes every audit candidate, optional
  evidence-review verdict, stable rule/result identity, exact Git anchor, and
  review-derived severity without treating an unreviewed candidate as a defect.
- A tracked module-size decision registry records cohesive responsibility,
  direct production and test-support dependencies, exact lines, and explicit
  reopen triggers for every repository test owner above the policy threshold.
- An explicit descriptor-bound `rigor bootstrap` command creates a trackable
  adopter policy and ignored canonical TODO exactly once. It requires declared
  policy, TODO, review-ledger, source-root, and test-root paths and starts every
  audit domain required rather than inferring applicability.
- API-stability schema 1.1 provides a machine-readable top-level inventory
  that classifies every `rigor_foundry.__all__` name as stable, provisional, or
  deprecated and enforces stable runtime identities, replacement, and
  deprecation-window contracts.
- A first-repository tutorial documents safe bootstrap, policy review, and the
  first read-only scan.
- Policy schema 1.1 can declare a sorted, unique inventory of exact Git-ignored
  paths for bounded `presence` or `file-sha256` capture. Evidence records only
  status, kind, regular-file size, optional SHA-256, and a bounded reason; raw
  content, symlink targets, environment values, and recursive members are
  never retained.
- Every audit candidate now carries a strict machine-verifiable anchor. A
  tracked-blob anchor binds the exact scanned Git blob, content SHA-256, and
  inclusive line span; a repository-tree anchor binds absence and
  repository-wide searches without fabricating a blob identity.
- Candidate excerpts are limited to 512 UTF-8 bytes. Large deterministic
  member sets retain their complete count and SHA-256 identity plus a bounded
  prefix.
- Promotion campaigns now carry content-addressed provider, exact-model,
  correlation-family, and operator identities. Correlated runs collapse to
  one witness, and promotion requires at least two model-family witnesses and
  two operators bound to the durable comparison, reports, and reviews.

### Changed

- The normative digest-dependency graph advances to schema 1.8 and binds
  verification-key policy, caller trust policy, model aliases, detached
  evidence signatures, review evidence, bundles, per-entry results, and the
  aggregate offline verification report.
- Ratchet and zero enforcement require an exact maturity report. Candidates
  from probationary rules remain counted and identified in the gate artifact
  but cannot silently become blocking debt. Repository policy schema 1.2 binds
  the exact calibration-policy digest so an operator cannot weaken enforcement
  with an unbound probation report; enforcement schema advances to 1.3 and the
  normative digest graph advances to 1.3.
- CLI integration construction and cross-command rejection routing now have
  separate bounded test owners instead of one oversized mixed test module.
- `rigor --version`, package `__version__`, and distribution metadata now share
  the import-safe `version.py` owner.
- Report schema 1.3 and scanner version 0.3.0 bind ignored-inventory evidence
  and its digest in addition to anchored candidates and the repository Git
  object format. Campaign schema 1.5 freezes the same evidence and rejects
  mutation during native adapters; promotion rejects stale ignored evidence.
- Digest-dependency schema 1.2 adds the ignored-inventory identity and its
  unconditional report and campaign bindings.
- Dirty tracked files are anchored to the exact worktree bytes inspected by
  the scanner, including binary, non-UTF-8, symlink, and oversized content,
  rather than to a stale stage-zero index object.
- Regular files are read through one no-follow descriptor. SHA-256 and Git
  blob identities are derived in the same pass, and concurrent content,
  pathname, identity, or size changes abort the scan.
- Tracked regular files replaced by dangling symlinks now fail closed, and a
  deleted size-registry owner emits repository-tree GF005 evidence rather than
  attempting to construct an unavailable blob anchor.
- Campaign and comparison schemas advance to 1.8 and model-witness schema to
  1.2. Witnesses store canonical provider/exact-model pairs, derive their
  projections, and reject repeated families or exact pairs across components.

### Fixed

- Canonical review validation rejects severity on every non-`valid` decision,
  so review validation, SARIF export, enforcement, and campaign consumers share
  one fail-closed verdict/severity relation.
- Test-authenticity residual schema 1.2 structurally blocks private static
  imports and offers an explicit high-assurance policy for reserved dynamic
  import and code-generation syntax; it makes no runtime-reachability claim.
- Package publication now grants release-asset write access only to the
  protected publication job so Sigstore bundles can be attached. Owner-confirmed
  recovery may run from the named tag or the repository default branch, but
  always validates and builds its fully qualified tag ref with checkout
  credential persistence disabled. Signing bundles are moved out of the
  distribution directory before attestation and PyPI upload. The signing
  action's broad native release uploader is disabled; one repository-controlled
  step attaches only the two validated bundle paths. Default-branch recovery
  uses a time-bounded PyPI environment policy that is removed after the run.

### Security

- The security-tool audit now carries three exact, machine-validated,
  30-day waivers for MCP server-only vulnerabilities that are unreachable from
  RigorFoundry's fixed `semgrep scan` invocation. At the 2026-07-16 review,
  latest Semgrep 1.170.0 hard-pinned vulnerable MCP 1.23.3; the waivers expire
  on 2026-08-15 and fail the repository audit unless removed or explicitly
  reviewed after an upstream-compatible Semgrep release.
- Durable campaign paths are traversed without following symlinks. Campaign,
  run, comparison, report, and review records must be bounded, single-link
  regular files whose file and parent identities remain stable through read.

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
