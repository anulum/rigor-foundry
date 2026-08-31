# Jupyter notebook analysis

RigorFoundry inspects tracked `.ipynb` files without importing Jupyter,
starting a kernel, executing a code cell, or modifying the audited checkout.
The scanner consumes only the bounded UTF-8 blob captured by the normal Git
inventory.

## Supported boundary

The notebook must use nbformat 4 and declare one unambiguous `python` or
`python3` language through `metadata.language_info.name` and/or
`metadata.kernelspec.language`. Code-cell `source` may be either the standard
string form or an array of strings. Markdown and raw cells are retained in the
blob identity but are not interpreted as Python.

Each code cell is parsed independently with the supported Python AST. The
following existing rule families are applicable:

- application security, reliability, and data privacy for every Python cell;
- operations and observability when the notebook is under a configured
  production source root;
- scientific, performance, and AST-backed test-authenticity rules when the
  notebook is under a configured test root.

Architecture, package API, import-graph, and module-ownership rules are not
applied to synthetic notebook cells because a cell is not a Python module.
The older repository-wide textual test-authenticity layer remains separate and
may still identify suppression syntax in any tracked UTF-8 text, including raw
notebook JSON; those text candidates are not produced by the cell-AST bridge.

## Exact anchors and evidence

Candidate locations are translated from the cell's logical Python line back to
the physical JSON string token or tokens in the exact tracked notebook blob.
String-array fragments that jointly form one Python line produce one inclusive
notebook line span. A single JSON string containing escaped newlines remains
anchored to that exact physical JSON line. Evidence contains only blob/span
digests, the cell index, and logical source-line range; raw cell source is not
copied into the report.

## Fail-closed states

`GV005-unscanned-jupyter-notebook` is emitted when JSON is malformed, keys are
duplicated, nesting or cell-count bounds are exceeded, nbformat is unsupported,
the language is missing/conflicting/non-Python, a code-cell source shape is
invalid, or a declared Python cell cannot be parsed. Valid cells in a notebook
remain independently reviewable, but the GV005 candidate prevents an
incomplete notebook from looking clean.

The Git inventory's existing 8 MiB text bound remains authoritative. Oversize,
binary, non-UTF-8, symlink, or otherwise unreadable tracked notebooks receive
the existing `GV002-unscanned-tracked-code` candidate. Neither failure path
falls back to kernel execution or reads notebook outputs as executable code.
