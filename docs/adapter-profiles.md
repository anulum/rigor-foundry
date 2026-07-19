# Built-in adapter profiles

RigorFoundry supplies three immutable repository-audit profiles. They remove
adopter-specific command reconstruction while retaining explicit consent,
tracked-input identity, tool identity, and fail-closed interpretation.

| Profile | Fixed analyser | Claimed domain | Accepted complete result |
| --- | --- | --- | --- |
| `semgrep-local-json-v1` | local Semgrep rules | `application-security` | strict JSON with at least one scanned path and no analyser errors |
| `trivy-repository-json-v1` | offline `misconfig,secret` filesystem scan | `application-security` | Trivy schema 2 JSON with at least one result target |
| `osv-lockfile-offline-json-v1` | offline lockfile scan against a verified local OSV snapshot | `supply-chain` | strict OSV JSON with at least one scanned lockfile and no scan errors |

The Trivy profile does **not** load or update a vulnerability database and
does not claim dependency-vulnerability, CVE, SBOM, licence, or supply-chain
coverage. Its fixed scanners are repository misconfiguration and secret
detection only. Use a separately specified and evidence-bound adapter when
those other domains are required.

## Policy declaration

Repository policy schema 1.3 accepts this strict profile form in
`native_audits`:

```json
{
  "name": "semgrep-local",
  "profile": "semgrep-local-json-v1",
  "configuration_path": "config/semgrep.yml",
  "target_paths": ["src", "tests"],
  "timeout_seconds": 120,
  "scope": "full",
  "working_directory": ".",
  "required": true
}
```

```json
{
  "name": "trivy-repository",
  "profile": "trivy-repository-json-v1",
  "configuration_path": "config/trivy.yml",
  "target_paths": ["."],
  "timeout_seconds": 120,
  "scope": "full",
  "working_directory": ".",
  "required": true
}
```

```json
{
  "name": "osv-lockfiles",
  "profile": "osv-lockfile-offline-json-v1",
  "configuration_path": "config/osv-database.json",
  "target_paths": ["requirements.txt", "package-lock.json"],
  "timeout_seconds": 120,
  "scope": "full",
  "working_directory": ".",
  "required": true
}
```

Profile declarations cannot override the executable, argv, parser, or domains.
The working directory is always `.`. Trivy accepts exactly one target; Semgrep
and OSV accept one or more. For OSV, `configuration_path` names a tracked strict
JSON database manifest, not an OSV TOML configuration. The manifest uses schema
1.0 and contains a sorted, unique list of ecosystem, `all.zip` byte length, and
SHA-256 records plus a canonical aggregate `database_digest`. Configuration and
targets must be canonical
repository-relative paths. The profile declaration, immutable profile, and
derived command are independently digest-bound. Run construction and durable
store/load require the ordered evidence name, required flag, specification
digest, and profile identity to match every policy adapter selected for a full
run. The context-free `AuditRunAttestation.from_dict()` parser validates record
integrity only; callers must use the campaign store boundary to validate an
imported attestation against its report policy and campaign contract. Campaign
comparison repeats the adapter-policy relation check for every supplied run;
context-invalid evidence is retained as unresolved divergence and can never
produce a promotion-eligible comparison record.

## Exact input projection

Execution requires a clean tracked worktree. RigorFoundry builds a temporary
read-only snapshot from the Git inventory and includes only the declared
configuration and target trees. Every selected entry must be a present,
single-link regular tracked file whose observed byte count, SHA-256, and Git
blob identity match the frozen inventory. Symlinks, gitlinks, ignored files,
untracked files, replacement races, empty target sets, and files larger than
32 MiB fail closed. The aggregate selected input is limited to 256 MiB.

The input digest binds HEAD, tree, Git object format, complete tracked-content
digest, configuration path and digest, ordered targets, and every copied file
record. Temporary host paths are excluded from durable identity and removed
after execution.

The OSV database bytes are deliberately outside the repository snapshot. The
operator must set `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` to an absolute host
directory containing the official cache layout
`osv-scanner/<ecosystem>/all.zip`. RigorFoundry opens every directory without
following symlinks, requires single-link regular archives, verifies exact size
and SHA-256 against the tracked manifest, rejects unsafe or unbounded ZIP
members, and copies only verified archives into the private workspace. The
tracked manifest digest binds the expected database to the profile
configuration; the sandbox repository identity additionally binds its canonical
`database_digest`. Missing or changed database bytes produce unavailable
evidence and are never fetched automatically.

## Sandbox and executable identity

The selected executable is resolved from fixed runtime roots, opened through a
retained descriptor, checked for trusted ownership and unsafe write bits, and
mounted read-only at `/run/rigor-adapter-tool`. The tracked snapshot is mounted
read-only at `/workspace`. Bubblewrap unshares the network and all namespaces,
uses UID/GID 65534, clears the environment, provides a private tmpfs, disables
telemetry and Semgrep metrics/version checks, and binds the system CA bundle's
content digest. Version output and the executable bytes are recorded and the
retained descriptor is revalidated after the scan.

Semgrep runs local configuration only:

```text
semgrep scan --config CONFIG --json --error --metrics off
  --disable-version-check --no-rewrite-rule-ids TARGET...
```

Trivy runs without update or network-backed database acquisition:

```text
trivy filesystem --config CONFIG --format json --exit-code 1
  --skip-db-update --skip-java-db-update --skip-check-update --offline-scan
  --scanners misconfig,secret --include-non-failures TARGET
```

OSV-Scanner runs only against the verified local snapshot:

```text
osv-scanner scan source --offline --format=json --verbosity=error
  --no-resolve --all-packages --lockfile TARGET...
```

These wrapped lines are descriptive; the production registry owns one exact
argv tuple and its profile digest.

## Evidence and enforcement

Adapter result schema 2.0 embeds profile-evidence schema 1.0. The nested record
binds the profile and profile digest, tool version and version-output digest,
configuration/input/output digests, finding count, scanned-target count, and a
finite status/reason pair:

| Status | Complete | Pass | Meaning |
| --- | --- | --- | --- |
| `clean` | yes | yes | Valid output, scanned targets, zero findings |
| `findings` | yes | no | Valid output with one or more findings |
| `partial` | no | no | Timeout, truncation, malformed output, analyser errors, invalid return code, or no scanned target |
| `unavailable` | no | no | Executable, trustworthy version evidence, or the exact OSV database snapshot was unavailable or invalid |

Imported records must reproduce the outer execution output digest and exact
return-code/timeout/truncation relation. Unavailable evidence has return code
126, zero output bytes, zero result counts, no tool-version claim, and neither
timeout nor truncation. These relations are validated after digest
recomputation; a self-consistent but cross-wired nested record is rejected.
Invalid-output, timeout, and truncation reasons also require zero result counts;
no-scanned-target evidence requires a zero scanned count; invalid-return-code
evidence requires scanned targets and an outer return code that contradicts the
finding-derived expected code. Scan-error evidence is valid only for Semgrep
and OSV because the Trivy parser has no corresponding production outcome.

Only complete evidence contributes declared domain coverage. A required
`findings`, `partial`, or `unavailable` result blocks enforcement; findings
remain complete evidence and are not relabelled as execution failure. Campaign
schema 1.9 retains the exact nested evidence in each run attestation.
Enforcement schema 1.4 names the profile status and reason in its blocker.
Digest-dependency schema 1.6 binds inventory to profile evidence and binds that
evidence into the run attestation; policy remains bound through the separate
campaign contract that the attestation also embeds.

## Installation and CI

Semgrep is supplied by the hash-locked Python environment. CI installs Trivy
`0.72.0` and OSV-Scanner `2.4.0` for Linux x86-64 with:

```bash
python -m tools.install_trivy
python -m tools.install_osv_scanner
```

The installer retrieves only the immutable GitHub release assets, bounds both
downloads, verifies the pinned checksum-list SHA-256, verifies the pinned
archive SHA-256, requires that the checksum list names that exact archive, and
extracts only the sole regular `trivy` member. It never calls `extractall`.
The OSV installer applies the same bounded-host, pinned checksum-document,
exact-asset SHA-256, and atomic mode-`0700` policy to the immutable Linux
binary. The resulting binaries are atomically installed. These downloaders are
source-checkout/CI tools, not part of the local-only runtime wheel. PyPI adopters
must provision the exact analyser through an independently verified deployment
step. Other platforms need an independently pinned installer before this
profile can be claimed available.

The fixed contracts follow the upstream
[Semgrep local/CLI scan guidance](https://semgrep.dev/docs/category/local-and-cli-scans),
[Trivy filesystem target](https://trivy.dev/docs/latest/guide/target/filesystem/),
and [Trivy reporting](https://trivy.dev/docs/latest/configuration/reporting/),
[OSV offline mode](https://google.github.io/osv-scanner/usage/offline-mode/),
and [OSV output](https://google.github.io/osv-scanner/output/)
interfaces. Installer pins refer to the immutable
[Trivy 0.72.0 release](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0),
and [OSV-Scanner 2.4.0 release](https://github.com/google/osv-scanner/releases/tag/v2.4.0),
not to moving latest-release URLs.

## Measured performance

`benchmarks/adapter_profiles.py` measures all three real tools through the same
descriptor-bound Bubblewrap execution path against a committed seven-file
fixture with Dockerfile, Python, requirements, and Rust targets. It emits
machine-readable JSON including
host, Python and tool versions plus minimum, median, and maximum wall time.

```bash
.venv/bin/python benchmarks/adapter_profiles.py --iterations 3
```

On 2026-07-19, one bounded integration run per profile on a non-isolated Linux 6.17 x86-64
workstation (12 logical CPUs, CPython 3.12.3) measured:

| Profile/tool | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| OSV-Scanner 2.4.0 | 2315.169 ms | 2315.169 ms | 2315.169 ms |
| Semgrep 1.170.0 | 8804.784 ms | 8804.784 ms | 8804.784 ms |
| Trivy 0.72.0 | 3270.411 ms | 3270.411 ms | 3270.411 ms |

Results are non-isolated workstation observations, not throughput guarantees.
External analyser startup dominates this orchestration boundary. There is no
native Rust implementation or polyglot counterpart of the Python control-plane
runtime to compare; the fixture includes multiple languages only to verify that
input projection is language-neutral. Adding a native runtime is a separate
architecture decision and must establish evidence-schema parity before making
performance claims.
