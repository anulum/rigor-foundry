# RigorFoundry

<p align="center">
  <a href="https://github.com/anulum/rigor-foundry/actions/workflows/ci.yml"><img src="https://github.com/anulum/rigor-foundry/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/anulum/rigor-foundry/actions/workflows/docs.yml"><img src="https://github.com/anulum/rigor-foundry/actions/workflows/docs.yml/badge.svg" alt="Documentation"></a>
  <a href="https://github.com/anulum/rigor-foundry/actions/workflows/fuzz.yml"><img src="https://github.com/anulum/rigor-foundry/actions/workflows/fuzz.yml/badge.svg" alt="Fuzz"></a>
  <a href="https://github.com/anulum/rigor-foundry/actions/workflows/security.yml"><img src="https://github.com/anulum/rigor-foundry/actions/workflows/security.yml/badge.svg" alt="Security"></a>
  <a href="https://github.com/anulum/rigor-foundry/actions/workflows/codeql.yml"><img src="https://github.com/anulum/rigor-foundry/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://app.codecov.io/gh/anulum/rigor-foundry"><img src="https://codecov.io/gh/anulum/rigor-foundry/branch/main/graph/badge.svg" alt="Codecov coverage"></a>
  <a href="https://pypi.org/project/rigor-foundry/"><img src="https://img.shields.io/pypi/v/rigor-foundry" alt="PyPI version"></a>
  <a href="https://pypi.org/project/rigor-foundry/"><img src="https://img.shields.io/pypi/dm/rigor-foundry" alt="PyPI downloads"></a>
  <a href="https://pepy.tech/project/rigor-foundry"><img src="https://static.pepy.tech/badge/rigor-foundry" alt="Total downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.anulum.li/"><img src="https://img.shields.io/badge/commercial%20licence-available-0a7d3c" alt="Commercial licence available"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.11--3.13-blue.svg" alt="Python 3.11–3.13"></a>
  <a href="https://reuse.software/"><img src="https://api.reuse.software/badge/github.com/anulum/rigor-foundry" alt="REUSE status"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/anulum/rigor-foundry"><img src="https://api.securityscorecards.dev/projects/github.com/anulum/rigor-foundry/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <a href="https://github.com/sponsors/anulum"><img src="https://img.shields.io/badge/sponsor-GitHub-ea4aaa?logo=githubsponsors" alt="Sponsor on GitHub"></a>
</p>

![RigorFoundry audit forge](docs/assets/rigor_foundry_repo_header.png)

Evidence-bound codebase transformation.

RigorFoundry inventories Git-tracked repository content, emits reproducible
audit candidates, binds review decisions to exact evidence, and prepares
remediation inputs without treating static heuristics as defect verdicts.

> **Current status:** standalone pre-alpha. Versioned
> [GitHub Releases](https://github.com/anulum/rigor-foundry/releases) and
> [GHCR images](https://github.com/anulum/rigor-foundry/pkgs/container/rigor-foundry)
> are published through the repository, beginning with `v0.1.0`. PyPI
> availability is established from the
> [public registry](https://pypi.org/project/rigor-foundry/), not inferred from
> a tag or workflow result. RigorFoundry has not been promoted as the GOTM
> fleet audit authority. A clean static scan is not a clean-repository claim.

## Operating contract

- `scan` is read-only and inspects only the exact Git-tracked inventory.
- Findings remain candidates until reviewed against the production surface.
- Missing evidence is explicit; it never resolves to pass.
- Reports bind repository HEAD, tree, Git object format, tracked-content,
  policy, rule-pack, and exact Git executable/version provenance.
- Every candidate binds either the exact scanned blob and inclusive line span
  or the exact repository tree and tracked-content digest for an absence or
  repository-wide search. Human-readable evidence is bounded.
- Promotion rejects stale reports, stale policies, changed Git provenance,
  duplicate findings, and mismatched repositories.
- Pack and reviewer signatures use distinct versioned Ed25519 message domains;
  legacy raw-digest signatures are rejected rather than reinterpreted.
- `rigor verify` checks caller-supplied signed evidence, explicit key lifecycle,
  expiry, unavailable records, and model-alias collapse entirely offline.
- Native audit adapters use validated argv, bounded execution time, and
  `shell=False`.
- Internal campaign records are written only below Git-ignored paths.

## Architecture

```mermaid
flowchart LR
    A[Git repository] --> B[Fail-closed inventory]
    B --> C[Portable scanners]
    B --> D[Declared native adapters]
    C --> E[Content-addressed AuditReport]
    D --> F[Adapter evidence]
    E --> G[Evidence review]
    E --> L[SARIF candidate export]
    G --> L
    F --> G
    G --> M[Adjudicated rule maturity]
    M --> H[Enforcement decision]
    G --> H
    G --> I[Verified TODO promotion]
    E --> J[Independent campaign attestations]
    J --> K[Divergence comparison]
```

The target profile model keeps five records separate:

1. `StandardPack` — versioned controls, licence, signature, and provenance.
2. `ProjectProfile` — selected controls, applicability, targets, and typed
   project variables.
3. `EffectiveProfileLock` — resolved inputs, digests, adapters, and
   contradiction evidence.
4. `ControlAssessment` — evidence-bound states such as `needs-evidence`,
   `blocked`, `fail`, `pass`, and `accepted-risk`.
5. `TargetGap` / `RemediationPlan` — the dependency-ordered difference between
   observed state and the declared target.

These records and their fail-closed resolver are implemented as a local typed
API. They do not grant execution authority, make RigorFoundry the fleet audit
authority, or prove effectiveness on an external corpus. See
[ARCHITECTURE.md](ARCHITECTURE.md).

## Install a published release

After the exact version appears in the
[PyPI release history](https://pypi.org/project/rigor-foundry/#history), install
it with:

```bash
python -m pip install "rigor-foundry==0.1.1"
```

## Quick start from source

```bash
git clone https://github.com/anulum/rigor-foundry.git RIGOR-FOUNDRY
cd RIGOR-FOUNDRY
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/ci.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/rigor --version
```

For an adopter repository, follow the explicit [first-repository
tutorial](docs/getting-started.md). Bootstrap requires the policy, canonical
TODO, review-ledger, source-root, and test-root paths; it never guesses or
overwrites them. The [consumer integration guide](docs/integrations.md)
provides immutable-SHA GitHub Action and pre-commit configurations with
explicit policy/evidence paths and no remediation authority.

## Command surface

| Command | Contract |
| --- | --- |
| `rigor bootstrap` | Create one explicit policy and ignored canonical TODO without guessing or overwrite. |
| `rigor scan` | Emit a deterministic JSON or Markdown candidate report. |
| `rigor report-diff` | Compare two exact reports as replay-verifiable candidate-transition evidence. |
| `rigor verify` | Verify signed reports, reviews, packs, model aliases, freshness, and unavailable evidence offline. |
| `rigor review-template` | Create explicit `needs-evidence` review records. |
| `rigor validate-review` | Verify reviews against one exact report. |
| `rigor sarif` | Export every candidate and optional review verdict as deterministic SARIF 2.1.0. |
| `rigor maturity-evaluate` | Derive probation or active status from explicit adjudicated review cases. |
| `rigor promote` | Preview or append one finding from a verified cross-model promotion campaign. |
| `rigor gate` | Apply observe, ratchet, or zero enforcement; non-observe modes require a maturity report whose policy digest is repository-bound. |
| `rigor campaign-create` | Freeze an independent-audit input contract. |
| `rigor campaign-run` | Execute and attest one independent run. |
| `rigor campaign-compare` | Record disagreement and unresolved evidence. |
| `rigor cra-bootstrap` | Create fresh Git-ignored offline CRA state and one operator-declared product registration. |
| `rigor vuln-register` | Append a content-addressed vulnerability or severe-incident revision. |
| `rigor vuln-timeline` | Print verified 24-hour, 72-hour, and track-specific final-report clocks. |
| `rigor cra-draft` | Prepare deterministic Article 14 JSON and Markdown without submitting them. |
| `rigor cra-receipt` | Bind operator-supplied receipt evidence without claiming authority acceptance. |
| `rigor cra-skip` | Record an explicit later-stage already-provided decision bound to an earlier receipt. |
| `rigor user-notice` | Prepare an offline Article 14(8) user-notice payload pair. |
| `rigor cra-status` | Replay all CRA records and return operational alert status. |
| `rigor advisory-draft` / `advisory-publish` / `advisory-delay` | Bind prepare-only fixed-vulnerability advisory evidence; never publish. |
| `rigor cra-pack` | Emit the CRA StandardPack signed by a caller-supplied Ed25519 key. |

`rigor --version` reports the canonical installed package version. The exact
stable/provisional top-level import inventory and deprecation policy are
documented in [Public API stability](docs/api-stability.md).

The [offline CRA preparation guide](docs/cra-reporting.md) documents the exact
operator workflow, evidence boundary, clocks, append-only storage, and exit
codes. It is a drafting aid, not legal advice, a conformity assessment, or an
external submission client.

The [content-addressed report-diff guide](docs/report-diff.md) documents strict
compatibility declarations, ambiguous anchor matching, deterministic replay,
and the boundary between candidate trends and correctness verdicts.

The [offline evidence-verification guide](docs/offline-verification.md)
documents caller-selected trust, key lifecycle, signature domains, bundle and
result schemas, exit codes, alias collapse, and the assurance boundary.

Declared native adapters run only after `--allow-native-audits` consent. They
execute in a no-network, read-only sandbox with a credential-free environment,
hard output and time bounds, process-tree termination, and structured durable
evidence. Native execution currently requires Bubblewrap at
`/usr/bin/bwrap` on a dpkg-based host, `/usr/bin/dpkg-query`, and a compatible
Bubblewrap 0.9.x installation. Passive scans and report review do not require
these native surfaces.

Verified built-in Semgrep, offline Trivy, and offline OSV lockfile profiles additionally bind the
immutable command/parser contract, exact tracked-only input snapshot,
configuration and executable bytes, tool version, structured status, and
profile evidence digest. Partial or unavailable evidence never supplies domain
coverage. See [Built-in adapter profiles](docs/adapter-profiles.md) for the
strict policy form, installation boundary, coverage limits, and benchmark.

## Module ownership

| Surface | Modules | Responsibility |
| --- | --- | --- |
| Git trust | `git_provenance` | Fixed-root executable selection, supported versions, replacement detection, and content-addressed provenance. |
| Inventory | `git_inventory` | Exact tracked paths, content kinds, scanned blob identities, and digests through the trusted Git runner. |
| Candidate anchors | `candidate_anchor` | Strict blob/tree anchor schemas, inclusive line spans, bounded excerpts, and anchor verification. |
| Candidate collection | `architecture`, `godfiles`, `polyglot_architecture`, `test_authenticity` | Static signals requiring review, each bound to a verified anchor. |
| Policy and records | `rules`, `domains`, `audit_primitives`, `policy_models`, `models` | Versioned rules, strict protocol primitives, applicability, repository policy, and content-addressed report/review records. |
| Report differences | `report_diff`, `report_diff_cli` | Replay-verifiable candidate transitions over two exact reports, with explicit compatibility and ambiguity evidence. |
| Offline verification | `verification_policy`, `offline_verification_models`, `offline_verification`, `offline_verification_report`, `offline_verification_cli` | Caller-selected key lifecycle, signed multi-protocol evidence, alias collapse, explicit unavailability, deterministic aggregate results, and a no-network CLI. |
| Review and enforcement | `review`, `enforcement` | Evidence validation, stale-state rejection, and controlled promotion. |
| Rule calibration | `rule_maturity`, `rule_maturity_manifest` | Explicit activation thresholds, source-bound adjudications, reviewer-effort evidence, and probation-safe gate input. |
| Interchange | `sarif` | Deterministic SARIF 2.1.0 projection that preserves candidate, review, and exact-anchor state. |
| Native boundaries | `adapters`, `adapter_runtime`, `adapter_profiles`, `adapter_workspace`, `osv_database`, `sandbox_provenance`, `trusted_executable` | Descriptor-pinned, time/output-bounded repository commands; immutable built-in profiles; tracked-only snapshots; verified offline OSV databases; structured evidence; and versioned Bubblewrap compatibility. |
| External sources | `source_capture`, `source_provenance` | Content-addressed advisory/version/standard/digest claims, bounded capture metadata, stable retained-file reads, and deterministic offline verification. |
| Campaigns | `campaign_identity`, `campaign_evidence`, `campaign_models`, `campaign_store`, `campaign_workflow`, `campaign_compare`, `campaign_promotion` | Inference and toolchain identity, correlated-witness collapse, durable provenance, divergence, and promotion eligibility. |
| Profile primitives | `model_primitives`, `condition_language` | Typed variables, opaque secret references, strict values, and bounded conditions. |
| Desired state | `standard_pack`, `project_profile`, `effective_profile`, `profile_resolution`, `trust` | Versioned controls, explicit Ed25519 trust stores, adopter intent, exact pack locks, contradiction evidence, and fail-closed resolution. |
| Assessment and planning | `control_assessment`, `review_attestation`, `remediation_plan`, `_remediation_graph` | Signed fresh evidence, cryptographically verified reviewer separation, target gaps, adapter-bound procedures, and conflict-safe batches. |
| Work lifecycle | `internal_storage`, `work_models` | Ignored crash-safe storage and digest-bound task/event closure records. |

## Container use

```bash
docker build -t rigor-foundry:local .
docker run --rm --read-only \
  --mount type=bind,src=/path/to/repository,dst=/workspace,readonly \
  rigor-foundry:local scan --root /workspace
```

The container runs as a non-root user and contains Git because repository
inventory is a production dependency of the CLI.

## Verification and reproducibility

- Python support is declared only for 3.11, 3.12, and 3.13 and is represented
  in the CI matrix.
- CI dependencies are resolved into a hash-locked requirements file.
- Local work uses the repository-owned `.venv` on the GOTM working disk.
- GOTM authoring policy uses focused single-file tests locally; CI owns the
  exhaustive test and coverage gate. External contributors may opt into the
  same local matrix explicitly.
- Releases, when authorised after public-repository promotion, build wheel and
  source distributions, run metadata checks, generate a CycloneDX SBOM, create
  Sigstore signatures and provenance, and publish through an owner-gated OIDC
  environment.
- Benchmark and effectiveness claims require committed methodology and measured
  evidence. No such performance claim is made by the migration baseline.

See [VALIDATION.md](VALIDATION.md) for the gate matrix and
[SECURITY.md](SECURITY.md) for the threat boundary.

## Development

```bash
make install
make lint
make typecheck
make audit
make preflight-fast
```

Run focused test files with `pytest tests/test_name.py`. GOTM operators do not
run the local full suite unless the owner explicitly authorises it for the
current session; external contributors may opt in as documented in
`CONTRIBUTING.md`.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Community

- [Issue tracker](https://github.com/anulum/rigor-foundry/issues)
- [Discussions](https://github.com/anulum/rigor-foundry/discussions)
- [Support](SUPPORT.md)
- [Security reporting](SECURITY.md)
- [Sponsor the public core](https://github.com/sponsors/anulum)

## Licence

RigorFoundry is available under the [Apache License 2.0](LICENSE). The licence
includes an explicit contribution-scoped patent grant; it does not grant rights
to use the RigorFoundry name or marks except as the licence permits.

---

<p align="center">
  <a href="https://www.anulum.li"><img src="docs/assets/anulum_logo_company.jpg" height="70" alt="ANULUM"></a>
  &nbsp;&nbsp;&nbsp;
  <img src="docs/assets/fortis_studio_logo.jpg" height="70" alt="Fortis Studio">
  <br>
  <em>Developed by <a href="https://www.anulum.li">ANULUM</a> / Fortis Studio</em>
</p>
