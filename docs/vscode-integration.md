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

There are deliberately no remediation, ledger-writing, or promotion commands.
Loading JSON is a structural display check only. The view labels a loaded
snapshot as canonically validated only after the configured CLI exits
successfully for that report/review pair. The binding includes the exact review
file content digest. The extension reloads both files after the CLI succeeds,
and a later filesystem change clears the displayed validation status.

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

## Development and verification

From `editors/vscode`:

```bash
npm ci --ignore-scripts
npm audit --audit-level=high
npm run check
npm run package
xvfb-run -a env RIGOR_FOUNDRY_CLI=/absolute/path/to/rigor npm run test:integration
```

The integration test launches a real VS Code Extension Development Host against
a temporary Git repository. It exercises the installed RigorFoundry CLI for
bootstrap, scan, review-template generation, and canonical review validation.
It also asserts that the extension contributes no remediation or promotion
command.
