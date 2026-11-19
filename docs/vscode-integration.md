# VS Code integration

The RigorFoundry VS Code extension is an evidence and review surface. It does
not decide whether a candidate is a defect, edit a review ledger, apply a
remediation, or promote a rule. Those authority boundaries remain in the
versioned RigorFoundry CLI and review protocol.

## Install a built VSIX

The protected CI workflow builds `rigor-foundry-vscode.vsix` from the locked
Node dependency graph. Install that artifact from a trusted build:

```bash
code --install-extension rigor-foundry-vscode.vsix
```

The extension supports local, trusted workspace folders on VS Code 1.125 or
newer. Virtual workspaces and Restricted Mode are intentionally unsupported
because an explicit scan launches a local process and reads local Git evidence.

## Commands

| Command | Effect |
| --- | --- |
| `RigorFoundry: Scan Workspace` | Explicitly runs `rigor scan`, writes the configured report, and loads it. |
| `RigorFoundry: Load Audit Report` | Loads bounded report JSON without running a process. |
| `RigorFoundry: Load Review Ledger` | Loads review JSON and cross-binds its report and candidate identities for display. |
| `RigorFoundry: Validate Review Ledger` | Runs the canonical `rigor validate-review` command against the loaded files. |
| `RigorFoundry: Open Candidate Evidence` | Opens the inclusive line span of a tracked-blob anchor. |
| `RigorFoundry: Copy Candidate Identity` | Copies the report digest, candidate ID, and anchor locus. |
| `RigorFoundry: Refresh Evidence View` | Redraws the loaded snapshot without rescanning or changing the ledger. |

There are deliberately no remediation, ledger-writing, or promotion commands.
Loading JSON is a structural display check only. The view labels a loaded
snapshot as canonically validated only after the configured CLI exits
successfully for the exact loaded report/review bytes. Validation passes only
two private, read-only temporary input copies to the CLI and removes them when
the process closes. It checks the original files and selected owner again before
marking that same loaded pair. Changed bytes or a newer selection refuse the
completion; the command never reloads or overwrites a newer choice. Reload both
files before validating changed evidence. A later filesystem change clears the
displayed validation status.

## Configuration

The defaults are suitable for a bootstrapped adopter repository:

```json
{
  "rigorFoundry.executable": "rigor",
  "rigorFoundry.reportPath": ".rigor/report.json",
  "rigorFoundry.reviewPath": ".rigor/reviews.json",
  "rigorFoundry.policyPath": "rigor-foundry-policy.json",
  "rigorFoundry.maximumEvidenceBytes": 16777216,
  "rigorFoundry.cliTimeoutSeconds": 120
}
```

The three file settings must remain workspace-relative. An executable is run
without a shell, under a bounded timeout and output limit. Report and review
files are bounded, must resolve inside the workspace, and are read from one
stable regular-file descriptor. Use an absolute, operator-controlled executable
path when command search policy is not sufficient for the environment.
All six settings are scoped to a workspace folder, including multi-root
workspaces.
The accepted report retains its canonical repository owner. Opening or copying
evidence, loading its ledger and validating the loaded pair use that owner and
its folder settings, even when another repository is active or all editors are
closed. Removing the owner folder refuses these commands until its folder is
restored or a new report is accepted. Scan Workspace and Load Audit Report
continue to select the active repository; loading a replacement report clears
the prior ledger. The loading API refuses a ledger supplied under another root.

## Development and verification

From `editors/vscode`:

A clean checkout needs its source-matching native payload before the unit
checks, including Linux package and binding checks. Use the required CI
producer and admission described below. On Windows, maintainers can instead
run `npm run build:windows-native` after installing the locked dependencies;
the command requires MSVC and refuses to replace an existing build.

```bash
npm ci --ignore-scripts --engine-strict
npm audit
npm run check
xvfb-run -a env RIGOR_FOUNDRY_CLI=/absolute/path/to/rigor VSCODE_EXECUTABLE=/usr/share/code/code npm run test:coverage
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" TZ=UTC LC_ALL=C.UTF-8 npm run package
```

The CI packaging step sets the archive epoch to the checkout commit time and
pins UTC and the C.UTF-8 locale before building both target archives. Use the
same environment for either local package command. Byte comparisons also
require the same Node and VSCE versions, admitted native input bytes and file
permissions.

Development uses Node.js 22.23.3. `npm run check` runs typed ESLint, formatting,
both strict compiler projects, compilation, documentation validation and unit
tests. `npm run test:coverage` runs that complete check plus the real host and
requires 100% statements, branches, functions and lines for every maintained
TypeScript runtime, test and support file, development script and tool
configuration. This Linux development route can expose gaps from another
supported platform; complete supported-platform acceptance requires the CI
source union below. A unit-only result does not qualify the host or the complete
coverage gate. Raw V8 observations
and coverage reports are written below `out/` and excluded from the VSIX.

The Linux verification path also runs `npm run test:linux-filesystem`. It
compares actual CLI report bytes with real procfs and sysfs regular files,
requiring refusal when readable bytes exceed the declared size or EOF arrives
before that size. This suite explicitly requires Linux and its mounted kernel
filesystems. It also verifies actual signal termination and late output from
an inherited pipe after the original process group has exited. These tests
neither simulate kernel behavior nor certify Windows.

The public process-runner tests exercise both queued output-stream orders,
natural exit after oversized output, bounded private diagnostics and child
reaping. Unit tests invoke both complete host launchers against real Git/CLI
adopters with an actually absent editor. They require the original failure,
retained process arguments and streams, complete source files and no false
completion record or successful artifact copy. Their temporary fixtures are
removed after those assertions; these negative cases do not qualify a host run.

From the repository root, `make editor-install`, `make editor-check`,
`make editor-coverage` and `make editor-package` provide the same commands.
Wrap the coverage target in `xvfb-run -a` on headless Linux. Full
`make preflight` includes this native coverage gate; `make preflight-fast`
includes native checks and unit tests. Direct Python preflight does not run
Node or a VS Code host.

The integration test launches a real VS Code Extension Development Host against
a temporary Git repository containing complete production source and original
test files copied from the checkout, with their exact content identities.
It exercises the configured RigorFoundry CLI for
bootstrap, scan, review-template generation, and canonical review validation.
It checks the tree, evidence opening, clipboard identity, ledger preservation
and filesystem invalidation. The host must write a completion record after all
assertions pass; a zero exit from the `code` wrapper alone is insufficient.
Failure preserves the owned workspace, process traces and host profile for
diagnosis. Successful runs preserve fixture evidence and host logs under
`out/fixtures/` before removing their temporary workspace. Filesystem watcher
failures leave the native gate failed.
The owned test profile disables built-in AI features through VS Code's
[documented setting](https://code.visualstudio.com/docs/agents/reference/ai-settings#general-settings).
The host records its actual VS Code and Node versions, platform, architecture
and observed AI-feature configuration beside the fixture evidence.
The launcher enables the owned host's loopback debugging endpoint. Native tests
use Node's HTTP and WebSocket interfaces to observe real controls, select actual
evidence files, and cancel both file pickers with keyboard input. They retain
original protocol responses, screenshots and visible evidence-tree geometry.
Missing selection, executable and policy cases must produce the expected
display explanations without replacing the last accepted snapshot. These
checks use the registered commands and actual extension output channel.
A separate empty VS Code window exercises scan and copy command refusals. It
verifies that the copy command preserves evidence and the clipboard when a
candidate has no loaded report or its repository is outside the open workspace.
The runner requires the empty window’s own completion marker before launching
the single-folder test.
The journeys also cover empty and partially loaded evidence, malformed command arguments
and a stale selection after a real CLI scan under a second Git-tracked fixture
policy. The original evidence pair is restored through the public loading API.
Failed native fixture commands retain their bounded streams and a private
fixture/command locator while propagating the original failure.

`VSCODE_EXECUTABLE` accepts the host executable; the Linux CI uses
`/usr/share/code/code`. `RIGOR_FOUNDRY_SOURCE_ROOT` selects the checkout supplying
the complete fixture files when the editor is built outside its repository.
`npm run test:integration` runs just the host journey after compilation.
`npm run test:workspace` runs the multi-root owner lifecycle after compilation:
two real Git/CLI adopter repositories, active-folder changes, actual ledger
pickers, no active editor, mismatched ledger root, removed-owner refusals and
report replacement. The complete coverage command includes both host journeys.
The suite also asserts that the extension contributes no remediation or
promotion command.

## CI ownership

The editor's build, package and actual Extension Development Host steps live in
ci-vscode.yml, called from the CI coordinator at the same repository revision.
Its result is required by the CI gate alongside quality, tests, coverage and
distribution. The inventory declares its category and owner; Node/Python pins,
the exact host and the artifact name remain explicit.

The required Windows native producer builds the locked Koffi sources with MSVC,
stages their binding metadata, and uploads one native payload before any
supported host job can run. The build and analysis tools use Node.js 22.23.3.
The receipt binds every editor source input, its producer workflow and
host-installation action, the repository licence, all native payload members,
the Git revision, repository, run ID and attempt. Source fingerprints and
clean-checkout admission use the same declared paths. Windows checkout
retains the committed line endings so source hashes match the Linux checkout.
Admission checks the complete payload, compiler provenance, vendor notices,
package resolution metadata and exact source licence before writing any member.
Conflicting existing files fail without replacement. Original native build
diagnostics are retained separately even when the producer fails.

The Windows producer uses MSVC's `/d1trimfile` to remove the Koffi source root
from compiled file names and `/Brepro` to make PE timestamps deterministic.
With the same compiler, linker, SDK and locked sources, compare the SHA-256 of
`native/koffi/build/koffi/win32_x64/koffi.node` from two clean compilations in
different directories. The compiler options are recorded in native provenance,
which also keeps the unique build allocation for each run.

For local inspection of an existing genuine Windows payload, from the repository
root use an artifact directory outside the editor source tree:

```bash
node editors/vscode/scripts/native-artifact.mjs pack /absolute/owned/native-artifact
node editors/vscode/scripts/native-artifact.mjs verify /absolute/owned/native-artifact
```

These commands label the receipt as local and preserve the original native
compiler provenance. They validate transfer and bytes; they do not certify a new
Windows build or execute the image. Hosted admission requires a fresh Windows
build from the matching GitHub run and refuses a local receipt. This artifact
check supplements the native runtime and host qualification gates.

The versioned host definitions select Windows and Linux at minimum 1.125.0 and
current 1.145.2. The installation action verifies each official archive digest;
the actual executable must report its exact version, application commit and
architecture before tests begin. Each profile runs the complete check, both real
host journeys and the independent workbench cases. Linux also runs its required
kernel-filesystem cases; Windows retains its native unit cases. Actual host
observations record the embedded Node version separately from the build Node.

One required consumer admits all four host profiles and the native build.
Original V8 files and file inventories remain unchanged. Source URLs and cached
map source paths are relocated only after the exact source and emitted-code/map
hashes agree. Constructor copies need their separately retained byte-bound
source-origin witness. Script functions, ranges and hit counts are preserved.
Dependency script records retain their original URLs and counters and remain
outside the maintained-source owner set.
Resolved source maps must retain Node's null cached URL; contradictory map
metadata is refused even when its enclosing file inventory has been resealed.
Missing, duplicated, changed, stale or foreign-run producers fail admission.
The consumer's own completed V8 trace is added before c8 enforces the complete
per-file 100% gate. The resulting owner set must exactly match all maintained
sources; exclusions and missing owners fail. Linux and Windows VSIX packaging
depends on that full result. A locally passing subset does not establish that
these hosted profiles or the complete source union passed.
