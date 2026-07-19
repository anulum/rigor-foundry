// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence tree tests in the VS Code host

import assert from "node:assert/strict";
import {AuditCandidate, AuditReport} from "../../src/contracts.js";
import {EvidenceTreeProvider} from "../../src/treeView.js";

const candidate: AuditCandidate = {
  candidate_id: "b".repeat(64),
  category: "application-security",
  rule_id: "AS001",
  anchor: {
    schema_version: "1.0",
    kind: "tracked-blob",
    path: "src/app.py",
    line_start: 1,
    line_end: 1,
    blob_oid: "e".repeat(40),
    content_sha256: "f".repeat(64),
  },
  symbol: "unsafe",
  evidence: "eval(user_input)",
  confidence: "high",
  rationale: "dynamic evaluation requires review",
  verification: "inspect the call boundary",
};

const report: AuditReport = {
  schema_version: "1.3",
  scanner_version: "0.3.0",
  rule_pack_version: "rigor-foundry/1.11.0",
  rule_pack_digest: "c".repeat(64),
  report_digest: "a".repeat(64),
  repository_root: "/workspace",
  head: "d".repeat(40),
  branch: "main",
  candidates: [candidate],
};

/** Exercise category grouping and fail-closed unreviewed labelling in the real host. */
export function testTreeView(): void {
  const provider = new EvidenceTreeProvider();
  provider.update({
    report,
    reviews: new Map(),
    reportPath: "/workspace/report.json",
    reviewPath: undefined,
    canonicallyValidated: false,
  });
  const categories = provider.getChildren();
  assert.equal(categories.length, 1);
  const category = categories[0];
  assert.ok(category?.kind === "category");
  const candidates = provider.getChildren(category);
  assert.equal(candidates.length, 1);
  const node = candidates[0];
  assert.ok(node?.kind === "candidate");
  const item = provider.getTreeItem(node);
  assert.equal(item.contextValue, "rigorFoundry.candidate");
  assert.match(String(item.description), /needs-evidence/u);
  assert.equal(typeof item.tooltip, "string", "candidate evidence must remain plain text");
}
