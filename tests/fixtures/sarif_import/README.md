<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- © Concepts 1996–2026 Miroslav Šotek. All rights reserved. -->
<!-- © Code 2020–2026 Miroslav Šotek. All rights reserved. -->
<!-- ORCID: 0009-0009-3560-0851 -->
<!-- Contact: www.anulum.li | protoscience@anulum.li -->

# Real producer SARIF for the import tests

These files are unmodified producer output, stored as gzip as the provenance fixtures are. Decompressed, their bytes are exactly what the producing command returned, and the tests pin the SHA-256 of the decompressed bytes. The CodeQL query help inside them is the producer's text, not this project's prose, so it is kept as exact bytes rather than rewritten.

| File | Producer | Producing command | SHA-256 of the decompressed bytes |
|---|---|---|---|
| `codeql-2.26.0-actions-analysis-1496041210.sarif.gz` | CodeQL 2.26.0 in GitHub Actions, `/language:python/`, commit `a55894202bcbf357b7857629c5485a7c75102088`, one result | `gh api -H "Accept: application/sarif+json" repos/anulum/rigor-foundry/code-scanning/analyses/1496041210` | `212064146c3c44aec0737f5ddfbc7864c1f8819e9b1500c5f0596f2704928617` |
| `codeql-2.27.2-actions-analysis-2237134604.sarif.gz` | CodeQL 2.27.2 in GitHub Actions, `/language:python/`, commit `c29faa141c9a1eeebe88f993c8e9b48d3fe9e661`, no results | `gh api -H "Accept: application/sarif+json" repos/anulum/rigor-foundry/code-scanning/analyses/2237134604` | `7387a1b0bbcf793fef0f8a732b9a534163693324b142b10d9334b142791fcf67` |

The CodeQL driver lists no rules. Every rule lives in the `codeql/python-queries` tool extension, and each result
names its rule through `rule.toolComponent.index`. The rule help text inside the files comes from the CodeQL
queries, which GitHub publishes under the MIT licence.

## Semgrep and Trivy output on the producer repository

`producer-repository.json` holds the two files of the fixture repository that both producers scanned, from
`/tmp/rigor-sarif-import/producer-repo`, a neutral path, so that no internal path enters the output. The token in it
is a project-specific fixture string, not a real-secret shape. The two rule files below carry this repository's
licence header as comments, which were added after the run; the rules themselves are byte-identical to the
configuration the producers used.

| File | Producer | Producing command (run in the fixture repository's parent) | SHA-256 |
|---|---|---|---|
| `semgrep-1.186.0-producer-repository.sarif` | Semgrep 1.186.0 (`Semgrep OSS`) | `cd producer-repo && semgrep scan --config ../semgrep-rules.yaml --sarif --output ../semgrep.sarif --metrics=off --disable-version-check --quiet .` | `1ed50724f27a674e740798adcb0a387033732931002941696f585fa43f70e746` |
| `trivy-0.76.2-producer-repository.sarif` | Trivy 0.76.2 | `trivy fs --scanners secret --secret-config trivy-secret.yaml --format sarif --output trivy.sarif --quiet producer-repo` | `c9593b12d91785a3d5766437112e96cdc99b222dde9abe47b2f80bcf6faa62d8` |

## The sandboxed Semgrep JSON output

`semgrep-1.186.0-sandboxed-json-stdout.json` is the exact standard output of the Semgrep JSON profile command run in
RigorFoundry's own bubblewrap sandbox vector on the producer repository, with a relative target and
`--sarif-output=/dev/fd/N` on an inherited memory file. The SARIF written to that memory file is byte-identical to
`semgrep-1.186.0-producer-repository.sarif`. SHA-256 `d33dd9d4f22c7cb7cbfbe9a64faf7a408beed9127c6acc053a5cd134af895a52`.
