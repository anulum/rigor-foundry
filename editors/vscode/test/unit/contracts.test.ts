// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — CLI-produced evidence contracts and explicit invalid-input controls

/**
 * Exercise structural evidence parsers using actual CLI-produced reports and draft ledgers.
 * Transform those documents into explicit invalid inputs and keep display-shape checks separate from review approval.
 * @module
 */

import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import test from "node:test";
import {
  assertRepositoryPath,
  parseAuditReport,
  parseReviewDocument,
} from "../../src/contracts.js";
import { createEvidenceRepository } from "../support/repository.js";

/**
 * Check public structural parsers against real evidence and explicit transformations of it.
 *
 * Modified documents below are parser inputs, never canonical scanner output or review approval.
 * The unmodified reports, identities, and draft ledgers come from real CLI invocations.
 * @returns Completion after original contracts and malformed-input controls have executed.
 */
async function run(): Promise<void> {
  const repository = await createEvidenceRepository();
  const { report, reviews, treeReport } = repository;
  const first = report.candidates[0];
  const review = reviews.reviews[0];
  const tracked = report.candidates.find((candidate) => candidate.anchor.kind === "tracked-blob");
  const tree = treeReport.candidates.find(
    (candidate) => candidate.anchor.kind === "repository-tree",
  );
  assert.ok(first);
  assert.ok(review);
  assert.ok(tracked?.anchor.kind === "tracked-blob");
  assert.ok(tree?.anchor.kind === "repository-tree");
  const treeAnchor = tree.anchor;
  try {
    await test("parses one structurally bound report and review", () => {
      const parsedReport = parseAuditReport(report);
      const parsedReviews = parseReviewDocument(reviews, parsedReport);
      assert.equal(parsedReport.candidates[0]?.candidate_id, first.candidate_id);
      assert.equal(parsedReviews.reviews[0]?.decision, "needs-evidence");
      assert.equal(parsedReviews.reviews.length, report.candidates.length);
    });

    await test("rejects traversal anchors", () => {
      const value = {
        ...report,
        candidates: [
          {
            ...tracked,
            anchor: { ...tracked.anchor, path: "../outside.py" },
          },
        ],
      };
      assert.throws(() => parseAuditReport(value), /dot segments/u);
    });

    await test("rejects reviews bound to another report", () => {
      const value = { ...reviews, reviews: [{ ...review, report_digest: "0".repeat(64) }] };
      assert.throws(() => parseReviewDocument(value, report), /does not bind/u);
    });

    await test("parses the fixed repository-tree locus and retains its content identities", () => {
      const parsed = parseAuditReport(treeReport);
      const anchor = parsed.candidates.find(
        (candidate) => candidate.candidate_id === tree.candidate_id,
      )?.anchor;
      assert.ok(anchor?.kind === "repository-tree");
      assert.equal(anchor.tree_oid, treeAnchor.tree_oid);
      assert.equal(anchor.tracked_content_sha256, treeAnchor.tracked_content_sha256);
      const invalid = {
        ...treeReport,
        candidates: [
          {
            ...tree,
            anchor: { ...tree.anchor, line_end: 2 },
          },
        ],
      };
      assert.throws(() => parseAuditReport(invalid), /fixed 1:1/u);
    });

    for (const value of [null, [], "report", 1, false]) {
      await test("refuses a non-object report envelope: " + String(value), () => {
        assert.throws(() => parseAuditReport(value), /must be an object/u);
      });
    }

    for (const [name, value, expected] of [
      [
        "unsupported schema",
        { ...report, schema_version: "2.0" },
        /schema_version is unsupported/u,
      ],
      ["missing candidate array", { ...report, candidates: null }, /candidates must be an array/u],
      [
        "duplicate identities",
        { ...report, candidates: [first, first] },
        /identities must be unique/u,
      ],
      ["empty scanner version", { ...report, scanner_version: "" }, /non-empty string/u],
      ["non-string scanner version", { ...report, scanner_version: 1 }, /non-empty string/u],
      ["invalid report digest", { ...report, report_digest: "not-a-digest" }, /SHA-256 digest/u],
    ] as const) {
      await test("refuses report " + name, () => {
        assert.throws(() => parseAuditReport(value), expected);
      });
    }

    for (const [name, candidate, expected] of [
      ["non-object", null, /must be an object/u],
      ["invalid confidence", { ...tracked, confidence: "certain" }, /confidence is unsupported/u],
      ["invalid identity", { ...tracked, candidate_id: 1 }, /non-empty string/u],
      [
        "unsupported anchor schema",
        { ...tracked, anchor: { ...tracked.anchor, schema_version: "2.0" } },
        /schema_version is unsupported/u,
      ],
      [
        "unsupported anchor kind",
        { ...tracked, anchor: { ...tracked.anchor, kind: "directory" } },
        /kind is unsupported/u,
      ],
      [
        "zero source coordinate",
        { ...tracked, anchor: { ...tracked.anchor, line_start: 0 } },
        /positive integer/u,
      ],
      [
        "fractional source coordinate",
        { ...tracked, anchor: { ...tracked.anchor, line_start: 1.5 } },
        /positive integer/u,
      ],
      [
        "unsafe source coordinate",
        { ...tracked, anchor: { ...tracked.anchor, line_start: Number.MAX_SAFE_INTEGER + 1 } },
        /positive integer/u,
      ],
      [
        "inverted span",
        { ...tracked, anchor: { ...tracked.anchor, line_start: 2, line_end: 1 } },
        /inverted line span/u,
      ],
      [
        "invalid Git identity",
        { ...tracked, anchor: { ...tracked.anchor, blob_oid: "invalid" } },
        /Git object identifier/u,
      ],
      [
        "invalid content identity",
        { ...tracked, anchor: { ...tracked.anchor, content_sha256: "INVALID" } },
        /SHA-256 digest/u,
      ],
    ] as const) {
      await test("refuses candidate " + name, () => {
        assert.throws(() => parseAuditReport({ ...report, candidates: [candidate] }), expected);
      });
    }

    await test("accepts empty optional display text without claiming canonical validity", () => {
      const parsed = parseAuditReport({
        ...report,
        branch: "",
        candidates: [{ ...tracked, symbol: "", confidence: "low" }],
      });
      const candidate = parsed.candidates[0];
      assert.ok(candidate);
      assert.equal(parsed.branch, "");
      assert.equal(candidate.symbol, "");
      assert.equal(candidate.confidence, "low");
    });

    await test("accepts the repository root only for an explicitly permitted tree locus", () => {
      assert.equal(assertRepositoryPath(".", true), ".");
      assert.equal(assertRepositoryPath(tracked.anchor.path), tracked.anchor.path);
      for (const value of ["", ".", "..", "../source.py", "src//file.py", "src/./file.py"]) {
        assert.throws(() => assertRepositoryPath(value), /dot segments/u);
      }
      for (const value of ["/absolute.py", "src\\file.py", "src/\0file.py"]) {
        assert.throws(() => assertRepositoryPath(value), /portable repository-relative/u);
      }
    });

    for (const [name, value, expected] of [
      [
        "unsupported envelope",
        { ...reviews, schema_version: "2.0" },
        /schema_version is unsupported/u,
      ],
      ["non-array records", { ...reviews, reviews: null }, /reviews must be an array/u],
      ["non-object record", { ...reviews, reviews: [null] }, /must be an object/u],
      [
        "unknown decision",
        { ...reviews, reviews: [{ ...review, decision: "approved" }] },
        /decision is unsupported/u,
      ],
      [
        "invalid severity type",
        { ...reviews, reviews: [{ ...review, severity: 2 }] },
        /severity is unsupported/u,
      ],
      [
        "invalid severity value",
        { ...reviews, reviews: [{ ...review, severity: "P5" }] },
        /severity is unsupported/u,
      ],
      [
        "severity on draft",
        { ...reviews, reviews: [{ ...review, severity: "P1" }] },
        /allowed only for valid/u,
      ],
      [
        "non-array evidence",
        { ...reviews, reviews: [{ ...review, evidence: null }] },
        /must be an array/u,
      ],
      [
        "non-string evidence",
        { ...reviews, reviews: [{ ...review, evidence: [null] }] },
        /must be a string/u,
      ],
      [
        "unknown candidate",
        { ...reviews, reviews: [{ ...review, candidate_id: "0".repeat(64) }] },
        /unknown candidate/u,
      ],
      ["duplicate candidate", { ...reviews, reviews: [review, review] }, /duplicate review/u],
    ] as const) {
      await test("refuses ledger " + name, () => {
        assert.throws(() => parseReviewDocument(value, report), expected);
      });
    }

    await test("checks display decision and string-array shapes without asserting review approval", () => {
      for (const decision of ["valid", "invalid", "accepted-boundary", "needs-evidence"]) {
        const parsed = parseReviewDocument(
          {
            ...reviews,
            reviews: [
              {
                ...review,
                decision,
                severity: decision === "valid" ? "P1" : null,
                evidence: ["", repository.artifactRoot],
              },
            ],
          },
          report,
        );
        const record = parsed.reviews[0];
        assert.ok(record);
        assert.equal(record.decision, decision);
        assert.deepEqual(record.evidence, ["", repository.artifactRoot]);
      }
    });
  } finally {
    await rm(repository.root, { recursive: true, force: true });
  }
}

run().catch((error: unknown): void => {
  process.stderr.write("Evidence contract test setup failed: " + String(error) + "\n");
  process.exitCode = 1;
});
