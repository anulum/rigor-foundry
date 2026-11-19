# Polyglot capability matrix

RigorFoundry recognises thirteen language families. The matrix shows the
analysis techniques implemented for each one. The test suite checks every row
against the public language-capability API.

## Three technique classes

- **AST / semantic controls** — the scanner parses the language's source into an
  abstract syntax tree and reasons over it. This backs the test-authenticity
  rules (TA001–TA011) and the Python import-graph architecture rules
  (AR001–AR004, AR006) in the base installation. The `native` extra adds
  targeted tree-sitter rules for C/C++, Go, JavaScript, Julia, Rust, shell,
  and TypeScript.
- **Structural / textual heuristics** — responsibility-size ownership (GF001),
  missing-test-owner ownership (AR005 for Python, AR008 for the polyglot
  suffixes), and relative dependency-graph resolution. These apply across the
  polyglot surface without parsing a full AST.
- **Native adapters** — third-party tools (for example Semgrep for
  application-security) wired through a policy adapter profile. They are opt-in
  per repository policy and only run once their executable passes the
  trusted-executable provenance gate; they are not a per-language default.

## Matrix

| Language | AST / semantic | Size (GF001) | Test ownership | Dependency graph | Structural |
| --- | :---: | :---: | :---: | :---: | :---: |
| c / c++ | Native extra | Yes | Yes | Yes | Yes |
| go | Native extra | Yes | Yes | No | Yes |
| javascript | Native extra | Yes | Yes | Yes | Yes |
| julia | Native extra | Yes | Yes | Yes | Yes |
| lean | No | Yes | Yes | No | Yes |
| mojo | No | Yes | Yes | No | Yes |
| python | Built in | Yes | Yes | Yes | Yes |
| rust | Native extra | Yes | Yes | Yes | Yes |
| shell | Native extra | Yes | No | No | Yes |
| systemverilog | No | Yes | Yes | No | Yes |
| typescript | Native extra | Yes | Yes | Yes | Yes |
| verilog | No | Yes | Yes | No | Yes |
| yaml | No | No | No | No | No |

Install the optional parsers with `pip install 'rigor-foundry[native]'`.
The base installation applies the listed structural controls to those
languages. YAML participates in tracked-content scope checks.
Go, Lean, Mojo, and the hardware-description languages are owned for size and
ownership but have no native dependency-family parser yet.

## Reading a scan honestly

A green scan covers the techniques available in that run. The matrix describes
implemented controls for the language family. For a particular run, the
installed parsers and the applicable rules determine which controls can report
findings.

## Programmatic access

```python
from rigor_foundry.polyglot_capability_matrix import capability_matrix

row = capability_matrix().row("typescript")
assert row.ast_semantic_controls
assert row.dependency_graph_controls
```

For TypeScript, the AST capability is available through the `native` extra.
The matrix is content-addressed (`matrix_digest`) and reachable via submodule
import (`rigor_foundry.polyglot_capability_matrix`).
