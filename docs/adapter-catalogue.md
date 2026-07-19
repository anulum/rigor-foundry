# Adapter catalogue

The adapter catalogue is a versioned registry of candidate evidence adapters
across domains. It records which third-party tools can supply which kind of
evidence, and how they are selected — never whether their output is trusted.

## What a catalogue entry is

Each `CatalogueEntry` names one tool, the evidence domain it covers, its source
of record, a neutral coverage description, its explicit exclusions, and the risk
profiles that select it. A tool's output is always signed, digest-bound evidence
interpreted through an adapter profile; it is never an automatically trusted
RigorFoundry verdict.

An entry has one of three statuses:

- **profiled** — bound to a built-in adapter profile (an exact, digest-locked
  execution and parser contract);
- **candidate** — catalogued for selection, pending a digest-locked profile;
- **superseded** — no longer developed, naming a catalogued successor; never
  selected.

## Built-in tools

| Tool | Domain | Status | Source |
| --- | --- | --- | --- |
| `semgrep` | application-security | profiled | [semgrep/semgrep](https://github.com/semgrep/semgrep) |
| `trivy` | container | profiled | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| `osv-scanner` | dependency-vulnerability | profiled | [google/osv-scanner](https://github.com/google/osv-scanner) |
| `grype` | container | candidate | [anchore/grype](https://github.com/anchore/grype) |
| `checkov` | infrastructure-as-code | candidate | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |
| `tfsec` | infrastructure-as-code | superseded → `trivy` | [aquasecurity/tfsec](https://github.com/aquasecurity/tfsec) |
| `gitleaks` | secret | candidate | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |

`tfsec` is now part of Trivy and is catalogued as superseded, so it is never
selected; the catalogue points to its successor instead.

## Risk-driven selection

Selection is driven by a risk profile and, optionally, an evidence domain, and it
never returns a superseded tool:

```python
from rigor_foundry.adapter_catalogue import builtin_catalogue

catalogue = builtin_catalogue()
[e.tool_id for e in catalogue.select("supply-chain")]          # grype, osv-scanner, trivy
[e.tool_id for e in catalogue.select("infrastructure-as-code")]  # checkov (tfsec superseded)
catalogue.for_domain("container")                                # trivy, grype
```

The catalogue is versioned and content-addressed. It is reachable via submodule
import (`rigor_foundry.adapter_catalogue`). Third-party findings only become
RigorFoundry evidence through a digest-bound adapter profile and independent
review — the catalogue selects tools, it does not trust their conclusions.
