// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence contract tests

import assert from "node:assert/strict";
import test from "node:test";
import {parseAuditReport, parseReviewDocument} from "../../src/contracts.js";

const digest = "a".repeat(64);
const candidateId = "b".repeat(64);

function report(): unknown {
  return {
    schema_version: "1.3",
    scanner_version: "0.3.0",
    rule_pack_version: "rigor-foundry/1.11.0",
    rule_pack_digest: "c".repeat(64),
    report_digest: digest,
    repository_root: "/work/repository",
    head: "d".repeat(40),
    branch: "main",
    candidates: [{
      candidate_id: candidateId,
      category: "application-security",
      rule_id: "AS001",
      anchor: {
        schema_version: "1.0",
        kind: "tracked-blob",
        path: "src/app.py",
        line_start: 3,
        line_end: 4,
        blob_oid: "e".repeat(40),
        content_sha256: "f".repeat(64),
      },
      symbol: "unsafe",
      evidence: "eval(user_input)",
      confidence: "high",
      rationale: "dynamic evaluation requires review",
      verification: "inspect the call boundary",
    }],
  };
}

function reviews(): unknown {
  return {
    schema_version: "1.0",
    reviews: [{
      report_digest: digest,
      candidate_id: candidateId,
      decision: "needs-evidence",
      reviewer: "",
      reviewed_at: "",
      rationale: "",
      evidence: [],
      severity: null,
      owner: "",
      dependencies: [],
      acceptance_gates: [],
      title: "",
      boundary_justification: "",
      expires_at: "",
      reopen_triggers: [],
    }],
  };
}

test("parses one structurally bound report and review", () => {
  const parsedReport = parseAuditReport(report());
  const parsedReviews = parseReviewDocument(reviews(), parsedReport);
  assert.equal(parsedReport.candidates[0]?.candidate_id, candidateId);
  assert.equal(parsedReviews.reviews[0]?.decision, "needs-evidence");
});

test("rejects traversal anchors", () => {
  const value = report() as {candidates: Array<{anchor: {path: string}}>};
  value.candidates[0]!.anchor.path = "../outside.py";
  assert.throws(() => parseAuditReport(value), /dot segments/u);
});

test("rejects reviews bound to another report", () => {
  const parsedReport = parseAuditReport(report());
  const value = reviews() as {reviews: Array<{report_digest: string}>};
  value.reviews[0]!.report_digest = "0".repeat(64);
  assert.throws(() => parseReviewDocument(value, parsedReport), /does not bind/u);
});

test("parses the fixed repository-tree locus and retains its content identities", () => {
  const value = report() as {candidates: Array<Record<string, unknown>>};
  value.candidates[0] = {
    candidate_id: candidateId,
    category: "governance",
    rule_id: "GV001",
    anchor: {
      schema_version: "1.0",
      kind: "repository-tree",
      path: ".",
      line_start: 1,
      line_end: 1,
      tree_oid: "e".repeat(40),
      tracked_content_sha256: "f".repeat(64),
    },
    symbol: "repository",
    evidence: "repository-wide evidence",
    confidence: "medium",
    rationale: "repository state requires review",
    verification: "inspect the exact tree",
  };
  const parsed = parseAuditReport(value);
  const anchor = parsed.candidates[0]?.anchor;
  assert.equal(anchor?.kind, "repository-tree");
  if (anchor?.kind === "repository-tree") {
    assert.equal(anchor.tree_oid, "e".repeat(40));
    assert.equal(anchor.tracked_content_sha256, "f".repeat(64));
  }
  const invalid = structuredClone(value) as {candidates: Array<{anchor: {line_end: number}}>};
  invalid.candidates[0]!.anchor.line_end = 2;
  assert.throws(() => parseAuditReport(invalid), /fixed 1:1/u);
});
