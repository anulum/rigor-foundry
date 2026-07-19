# Documentation, claims, and IP rules

Rule-pack `rigor-foundry/1.12.0` adds a bounded documentation category (prefix
`DC`). Each finding is an anchored **needs-evidence candidate**, not a licence
verdict, infringement claim, compatibility verdict, or proof that published
documentation is otherwise complete.

## Rules

| Rule | Signal | Confidence |
| --- | --- | :---: |
| `DC001-missing-license-header` | a tracked UTF-8 source owner under a policy-declared source root has no `SPDX-License-Identifier` declaration in its first five lines | high |
| `DC002-doc-version-drift` | an explicit distribution-version statement in a public README or documentation page differs from static PEP 621 project metadata | high |

`DC001` applies to the source suffixes already owned by the responsibility
scanner: Python, JavaScript/TypeScript, Go, Rust, C/C++, Julia, Shell, Lean,
Mojo, Verilog, and SystemVerilog. The source must be under an exact
`source_roots` prefix from the repository policy. Binary, non-UTF-8,
out-of-root, test-only, prose, and configuration files are not classified by
this rule. The five-line window admits an interpreter shebang and encoding
declaration while retaining the meaning of a leading header. The rule checks
only that an SPDX licence declaration exists; it does not decide whether the
expression is legally correct or whether separate copyright text is required.

`DC002` requires one tracked root `pyproject.toml` with static string
`[project].name` and `[project].version` fields. It recognises explicit current
guidance such as `distribution==1.2.3`, `distribution v1.2.3`, and
`distribution version 1.2.3`, including normalised `-`, `_`, and `.` name
separators and optional extras. Root README files and Markdown or reStructuredText
pages under `docs/` are in scope. Changelogs, histories, release notes,
`docs/internal/`, unrelated root prose, and other suffixes are excluded so
historical version records are not misclassified as current guidance. Missing,
dynamic, malformed, or non-static project metadata produces no `DC002`
candidate and must not be interpreted as evidence that documentation versions
agree.

## Evidence and verification

Candidates contain exact tracked-blob anchors and content digests without
copying source or documentation text into the report. `DC002` additionally
binds SHA-256 identities of the expected version and distribution name. Review
`DC001` against the repository's actual licence ownership before adding the
correct SPDX expression. Review `DC002` against `[project].version`, then
update current installation or compatibility guidance or move genuinely
historical statements to an excluded historical surface.

The family contributes a portable control to the
`documentation-claims-ip` audit domain. Both rules enter maturity probation;
safe and vulnerable fixtures establish scanner behaviour, while adjudicated
false-positive and reviewer-effort evidence across adopter repositories is a
separate activation gate.
