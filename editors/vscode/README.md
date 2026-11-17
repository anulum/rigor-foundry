# RigorFoundry Evidence Review for VS Code

This workspace extension displays RigorFoundry audit candidates and their
review-ledger sources. It does not classify an unreviewed candidate as a defect,
and it exposes no remediation or promotion command.

The extension can:

- run `rigor scan` after an explicit **RigorFoundry: Scan Workspace** command;
- load a report and review ledger from workspace-confined, bounded JSON files;
- group candidates by audit category and show the exact report, candidate, and
  tracked-blob anchor identities;
- open a tracked source span without following evidence outside the workspace;
- run `rigor validate-review` as the canonical validation authority.

Repository-tree evidence at the root locus `.` is labelled `repository` in the
tree. Review labels retain the loaded draft decision until canonical validation
has checked the report and ledger.

The TypeScript parser performs bounded structural checks for safe display. A
green structural load is not an authenticity or canonical-validity claim. Only
the configured RigorFoundry CLI validates the complete report digest, candidate
identities, and review semantics. Validation uses temporary read-only copies of
the exact loaded bytes and removes them after the process closes. Changed files
or a newer selection refuse completion without replacing the selected evidence.

See the project documentation for installation, configuration, and the exact
trust boundary.

Development uses Node.js 22.23.3 and the committed dependency lock. Install with
`npm ci --ignore-scripts --engine-strict`, then run `npm run check` for typed
lint, formatting, strict typing, documentation and unit tests. Run
`npm run test:coverage` with a real VS Code host and RigorFoundry CLI for the
complete per-file 100% gate. On headless Linux, wrap the command in `xvfb-run -a`.
The Linux verification path includes real procfs/sysfs refusal and process-group
lifecycle tests through `npm run test:linux-filesystem` and requires mounted
Linux kernel filesystems. Unit tests also exercise both complete launchers with
real Git/CLI adopters and an absent editor, checking retained diagnostics and
the absence of false completion records.
`npm run package` produces the VSIX after verification. Failed host workspaces
and process traces remain available for diagnosis; a wrapper exit code alone
does not establish that the host tests passed.
`npm run package:windows` stages the Windows binding metadata and produces the
Windows x64 VSIX. The unchanged vendor loader resolves a private package export
to the bundled native image even when npm development dependencies are present.
The runtime checks that resolution and its digest before loading the image.
`npm run stage:windows-native` verifies an existing compiled image and stages
matching binding metadata without replacing its compiler provenance or binary.
The required CI Windows producer builds those assets once from locked compiler
inputs. Four host jobs cover Windows and Linux at the declared minimum 1.125.0
and pinned current 1.145.2. Each verifies the same native artifact before its
complete platform checks and real single-folder, multi-root and workbench
journeys. The required union checks source and emitted-code identities, original
V8 data, host versions and every maintained runtime, test, support, script and
configuration owner at 100%. Both platform VSIX packages follow that union.
Local receipts do not qualify a fresh hosted Windows build.
The pinned host profile also records a versioned CLI path when the upstream
archive places application resources beneath a commit directory. The launcher
checks that the CLI is an ordinary contained file before checking the actual
application version; legacy archives retain their original resource path.
The host journey drives the real workbench file pickers through its loopback
debugging protocol and retains screenshots, visible tree geometry and original
protocol responses. It also checks command refusals against the actual output
channel while preserving the last accepted evidence snapshot.

Loaded evidence remains bound to its report repository when editor focus changes
in a multi-root workspace. Ledger loading, validation and candidate commands
refuse an owner folder that is no longer open. Scan and report selection still
follow the active folder. `npm run test:workspace` exercises the real two-repository
owner lifecycle and is included in the complete coverage command.

`npm run test:workbench` requires `VSCODE_EXECUTABLE` to name the real installed
application and a working desktop or Xvfb display. Its independent controller
checks actual renderer replies, request deadlines, owned-application termination
and refusal of the same endpoint after closure. Profiles and original process
and protocol traces remain under `out/fixtures/`. This integration is included
in `verify`; protocol unit examples provide separate input-boundary checks.
