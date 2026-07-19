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

The TypeScript parser performs bounded structural checks for safe display. A
green structural load is not an authenticity or canonical-validity claim. Only
the configured RigorFoundry CLI validates the complete report digest, candidate
identities, and review semantics.

See the project documentation for installation, configuration, and the exact
trust boundary.
