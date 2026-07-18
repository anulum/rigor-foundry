# Polyglot capability matrix

RigorFoundry is not a Python-only tool, and it does not claim uniform semantic
depth across languages. It scans thirteen languages at deliberately different
depths. This matrix states, per language, which analysis techniques the scanner
actually applies, so an adopter can see exactly what a green scan does and does
not establish. It is derived from the live language-capability registry, so it
cannot drift from the scanner's behaviour.

## Three technique classes

- **AST / semantic controls** — the scanner parses the language's source into an
  abstract syntax tree and reasons over it. This backs the test-authenticity
  rules (TA001–TA011) and the Python import-graph architecture rules
  (AR001–AR004, AR006). It is currently **Python only**.
- **Structural / textual heuristics** — responsibility-size ownership (GF001),
  missing-test-owner ownership (AR005 for Python, AR008 for the polyglot
  suffixes), and relative dependency-graph resolution. These apply across the
  polyglot surface without parsing a full AST.
- **Native adapters** — third-party tools (for example Semgrep for
  application-security) wired through a policy adapter profile. They are opt-in
  per repository policy and only run once their executable passes the
  trusted-executable provenance gate; they are not a per-language default.

## Matrix

| Language | AST / semantic | Size (GF001) | Ownership | Dependency graph | Structural |
| --- | :---: | :---: | :---: | :---: | :---: |
| python | ✅ | ✅ | ✅ | ✅ | ✅ |
| c / c++ | — | ✅ | ✅ | ✅ | ✅ |
| javascript | ✅† | ✅ | ✅ | ✅ | ✅ |
| typescript | ✅† | ✅ | ✅ | ✅ | ✅ |
| rust | — | ✅ | ✅ | ✅ | ✅ |
| julia | — | ✅ | ✅ | ✅ | ✅ |
| go | — | ✅ | ✅ | — | ✅ |
| lean | — | ✅ | ✅ | — | ✅ |
| mojo | — | ✅ | ✅ | — | ✅ |
| systemverilog | — | ✅ | ✅ | — | ✅ |
| verilog | — | ✅ | ✅ | — | ✅ |
| shell | — | ✅ | — | — | ✅ |
| yaml | — | — | — | — | — |

`✅` marks an applied technique; `—` marks one the scanner does not apply to that
language today. `†` marks JavaScript and TypeScript AST/semantic analysis, which
is implemented through a tree-sitter parser but requires the optional
`javascript` extra (`pip install rigor-foundry[javascript]`); without the extra a
deployment degrades to the structural controls for those languages. YAML is
scope-scannable data only — it participates in the tracked-content scope rule but
carries no size, ownership, or dependency control. Go, Lean, Mojo, and the
hardware-description languages are owned for size and ownership but have no native
dependency-family parser yet.

## Reading a scan honestly

A green scan means the applied techniques found no candidate — not that the
language was analysed as deeply as Python. JavaScript and TypeScript now have a
native AST pass (via the `javascript` extra); for the remaining non-Python
languages no AST-semantic control ran, so semantic defects that only an AST pass
would surface are out of scope until native analysis for that language lands. Go
and Rust are the next AST targets, guided by adopter evidence.

## Programmatic access

```python
from rigor_foundry.polyglot_capability_matrix import capability_matrix

matrix = capability_matrix()
row = matrix.row("typescript")
row.ast_semantic_controls        # False — no AST pass yet
row.dependency_graph_controls    # True  — relative imports are resolved
```

The matrix is content-addressed (`matrix_digest`) and reachable via submodule
import (`rigor_foundry.polyglot_capability_matrix`).
