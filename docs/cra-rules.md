# CRA readiness rules and StandardPack

RigorFoundry rule pack `rigor-foundry/1.17.0` adds six CRA readiness
signals. They are review candidates, not findings, legal conclusions, or a
claim that a product complies with Regulation (EU) 2024/2847. All six rules
enter maturity probation with no calibration credit.

The mapping uses the [official EUR-Lex text of Regulation (EU)
2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj). Article 14 applies
from 11 September 2026; most other provisions apply from 11 December 2027.
Only the manufacturer decides product and operator applicability.

## Explicit activation

Legacy policy schema 1.3 remains unchanged and does not read `.rigor/cra`.
Policy schema 1.4 activates the lane only through an explicit `cra` block:

```json
{
  "schema_version": "1.4",
  "ignored_inventory": [
    {
      "evidence_id": "cra-state",
      "path": ".rigor/cra",
      "capture": "directory-sha256"
    }
  ],
  "cra": {
    "schema_version": "1.0",
    "applicability": "required",
    "rationale": "Manufacturer-declared CRA audit scope for this product.",
    "product_key": "widget",
    "disclosure_policy_path": "SECURITY.md",
    "state_evidence_id": "cra-state",
    "cra_policy_digest": "<canonical digest of the preceding CRA fields>"
  }
}
```

The snippet shows only the changed fields; a real policy still contains every
ordinary repository-policy field. Generate the CRA block through the Python
`CraPolicy.build` API or another schema-aware tool so the digest is derived,
not typed by hand. `not-applicable` requires a rationale and null product,
policy-path, and state-evidence fields. Absence of `cra`, or explicit
`not-applicable`, is fully inert.

Required scope binds `state_evidence_id` to exactly one ignored-inventory
`directory-sha256` declaration for `.rigor/cra`. A scan hashes one bounded,
no-follow manifest before replaying the append-only record chains under the CRA
lock, then hashes it again. Any content, entry, or directory drift aborts the
scan instead of producing a mixed-state report. Exact registration, event,
inventory, or advisory digests also remain in candidate evidence. Missing,
unsafe, or over-limit state is unresolved evidence; it is never a pass.

## Probation rules

| Rule | Bounded signal | Verification boundary |
| --- | --- | --- |
| `CR001-missing-disclosure-policy` | The explicitly declared CVD policy path is not one tracked UTF-8 file. | Confirm applicability and independently review the tracked policy. |
| `CR002-missing-security-contact` | The tracked CVD policy has no bounded public email-address signal. | Verify that a public contact is monitored and operational; syntax is not delivery proof. |
| `CR003-stale-component-inventory` | The latest imported inventory's commit, tree, object format, or tracked-content digest differs from the scan inventory. | Review repository/SBOM drift and import only an externally generated SBOM when appropriate. |
| `CR004-untracked-reporting-timeline` | A started Article 14 operational stage has no bound draft, receipt, or explicit already-provided skip; unavailable CRA state produces the same unresolved rule family. | Recompute the timeline and inspect operator evidence. RigorFoundry never submits. |
| `CR005-support-period-too-short` | Support is below 60 months and no internally consistent shorter expected-use declaration supports it. | Review Article 13(8), expected use, and retained evidence. Below 60 months is not automatically a legal failure. |
| `CR006-fixed-vuln-without-advisory` | A vulnerability is `fix-available` or `disclosed` without operator-declared publication or justified-delay evidence. | Review the security update and advisory record. RigorFoundry never publishes. |

Every candidate carries a tracked policy or disclosure-policy anchor. Dynamic
evidence is content-addressed inside the candidate and therefore changes the
report and campaign run digest when the verified CRA state changes. Campaigns
retain the same ignored-state directory digest and run the ordinary
independent-review workflow.

## Advisory evidence lifecycle

The lifecycle is append-only and prepare-only:

```bash
rigor advisory-draft VULN-2026-001 \
  --root . \
  --security-update-ref release/v1.2.3 \
  --advisory-path SECURITY/ADV-2026-001.md \
  --drafted-at 2026-09-12T10:00:00Z

rigor advisory-publish VULN-2026-001 \
  --root . \
  --published-at 2026-09-13T10:00:00Z \
  --evidence operator-publication-evidence.txt
```

The draft binds the advisory file's exact SHA-256. Publication and delay
revisions require a separate bounded repository-local operator-evidence file
and bind its normalised relative path plus exact SHA-256. Replay rehashes the
advisory and every historical publication or delay evidence file, and fails
closed if any bytes no longer match the chain. If publication is delayed,
`advisory-delay --reason TEXT --review-at TS --evidence FILE` records the
manufacturer's declaration and review time. It does not adjudicate whether the
reason is legally sufficient. A later `advisory-publish` revision may close
that delay. No command sends or publishes content.

## Signed CRA StandardPack

`cra-pack` emits a real `StandardPack` signed with a caller-supplied Ed25519
PEM key. Private key material is bounded-read, used in memory, and never copied
into the repository or pack. On POSIX, the command rejects any signing-key file
with group or other permissions:

```bash
rigor cra-pack \
  --out cra-standard-pack.json \
  --signing-key /secure/path/cra-pack-key.pem \
  --key-id organisation-cra-pack-2026
```

The output maps Annex I Part I(2)(a), Annex I Part II(1–8), and Article 14 to
nine evidence contracts. The mapping manifest has its own digest and names the
official CELEX identifier; it does not claim to hash or reproduce the external
legal text. Consumers must independently provision the matching public key in
their verification trust store.

The built-in `eu-cra-2024-2847` compliance-map template records `supporting`
and `partial` relations and explicit unsupported domain gaps. In particular,
secure, timely, free update distribution remains operator evidence. Pack
controls use the ordinary `EffectiveProfileLock` and `ControlAssessment`
pipeline; without fresh evidence and independent review they remain
`needs-evidence` or `blocked`, never pass.

## Enforcement prohibition

CR001–CR006 have no rule-specific adjudicated corpus on landing. A ratchet or
zero gate may activate a CR rule only after the normal maturity report proves
the configured repository, reviewer, positive-review, false-positive, and
reviewer-effort thresholds for that exact rule-pack digest. A clean scan alone
cannot provide that evidence.
