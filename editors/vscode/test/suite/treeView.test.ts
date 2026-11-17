// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence tree tests in the VS Code host

/**
 * Check category grouping and plain-text candidate labels with actual VS Code tree objects.
 * Keep scanner confidence and review decisions visible as separate evidence attributes.
 * @module
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import { parseAuditReport, parseReviewDocument } from "../../src/contracts.js";
import type { RigorFoundryApi } from "../../src/extension.js";
import type { EvidenceSnapshot } from "../../src/store.js";
import { EvidenceStore } from "../../src/store.js";
import { EvidenceTreeProvider } from "../../src/treeView.js";
import type { CandidateNode } from "../../src/treeView.js";
import { readEvidenceOutput, waitForEvidenceOutput } from "../support/nativeUi.js";
import { writeObservedEvidencePair } from "./cli.test.js";

/**
 * Exercise real report grouping and review labels with actual VS Code tree objects.
 * @param snapshot - Evidence loaded from the actual adopter scan and optional canonical ledger.
 * @returns Candidate rows whose identities can be passed to the actual registered commands.
 */
export function testTreeView(snapshot: EvidenceSnapshot): CandidateNode[] {
  const report = snapshot.report;
  assert.ok(report);
  const provider = new EvidenceTreeProvider();
  assert.deepEqual(provider.getChildren(), []);
  let notifications = 0;
  const subscription = provider.onDidChangeTreeData(() => {
    notifications += 1;
  });
  provider.update(snapshot);
  assert.equal(notifications, 1);
  subscription.dispose();
  const categories = provider.getChildren();
  const expectedCategories = [...new Set(report.candidates.map((item) => item.category))].sort(
    (left, right) => left.localeCompare(right),
  );
  assert.equal(categories.length, expectedCategories.length);
  const rows: CandidateNode[] = [];
  for (const [index, category] of categories.entries()) {
    assert.ok(category.kind === "category");
    assert.equal(category.category, expectedCategories[index]);
    const categoryItem = provider.getTreeItem(category);
    assert.equal(categoryItem.description, String(category.candidates.length));
    const candidates = provider.getChildren(category);
    assert.equal(candidates.length, category.candidates.length);
    for (const node of candidates) {
      assert.ok(node.kind === "candidate");
      rows.push(node);
      assert.deepEqual(provider.getChildren(node), []);
      const item = provider.getTreeItem(node);
      assert.equal(item.contextValue, "rigorFoundry.candidate");
      const review = snapshot.reviews.get(node.candidate.candidate_id);
      assert.equal(
        item.description,
        `${review?.decision ?? "needs-evidence"} · ${node.candidate.confidence}`,
      );
      assert.equal(typeof item.tooltip, "string", "candidate evidence must remain plain text");
      assert.ok(typeof item.tooltip === "string");
      assert.ok(item.tooltip.includes(`Candidate: ${node.candidate.candidate_id}`));
      assert.ok(item.tooltip.includes(`Report: ${report.report_digest}`));
      assert.ok(
        item.tooltip.includes(
          `Canonical CLI validation: ${snapshot.canonicallyValidated ? "yes" : "no"}`,
        ),
      );
      assert.ok(item.command);
      assert.equal(item.command.command, "rigorFoundry.openEvidence");
      assert.deepEqual(item.command.arguments, [node]);
    }
  }
  assert.equal(rows.length, report.candidates.length);
  provider.update(new EvidenceStore().snapshot());
  assert.deepEqual(provider.getChildren(), []);
  for (const row of rows) {
    const staleItem = provider.getTreeItem(row);
    assert.ok(typeof staleItem.tooltip === "string");
    assert.ok(staleItem.tooltip.includes("Report: not loaded"));
    assert.ok(staleItem.tooltip.includes("Canonical CLI validation: no"));
  }
  return rows;
}

/**
 * Render explicit edits of real evidence while canonical validation refuses their altered identities.
 * These copies are unvalidated display inputs, never scanner output or accepted review decisions.
 * @param api - Actual activated extension and its public evidence-loading API.
 * @param root - Open adopter repository containing the original CLI-produced evidence.
 * @param reportPath - Original complete report containing a repository-tree candidate.
 * @param reviewPath - Original CLI-produced draft ledger bound to that report.
 * @returns Completion after real tree objects and registered CLI refusals have been checked.
 */
export async function testUnvalidatedTreeEvidence(
  api: RigorFoundryApi,
  root: string,
  reportPath: string,
  reviewPath: string,
): Promise<void> {
  const input = JSON.parse(await readFile(reportPath, "utf8")) as Record<string, unknown>;
  const report = parseAuditReport(input);
  const tree = report.candidates.find((candidate) => candidate.anchor.kind === "repository-tree");
  assert.ok(tree);
  const candidates = input["candidates"] as Record<string, unknown>[];
  const selected = candidates.find((candidate) => candidate["candidate_id"] === tree.candidate_id);
  assert.ok(selected);
  const anchor = selected["anchor"] as Record<string, unknown>;
  anchor["path"] = ".";
  const ledger = parseReviewDocument(JSON.parse(await readFile(reviewPath, "utf8")), report);
  const edits = await mkdtemp(path.join(root, ".rigor", "unvalidated-tree-"));
  const editedReport = path.join(edits, "report.json");
  const editedReviews = path.join(edits, "reviews.json");
  const observations = [];
  try {
    await writeObservedEvidencePair(
      edits,
      Buffer.from(JSON.stringify(input)),
      Buffer.from(JSON.stringify(ledger)),
    );
    await api.loadReport(root, editedReport);
    await api.loadReviews(root, editedReviews);
    const provider = new EvidenceTreeProvider();
    provider.update(api.getSnapshot());
    const draft = testTreeView(api.getSnapshot()).find(
      (row) => row.candidate.candidate_id === tree.candidate_id,
    );
    assert.ok(draft);
    const draftItem = provider.getTreeItem(draft);
    assert.equal(draftItem.label, `${tree.rule_id}: repository`);
    assert.ok(typeof draftItem.tooltip === "string");
    assert.ok(draftItem.tooltip.includes("Decision source: review by unassigned"));
    for (const decision of ["valid", "invalid"] as const) {
      const edited = {
        ...ledger,
        reviews: ledger.reviews.map((review) => ({
          ...review,
          decision,
          reviewer: decision === "valid" ? "Display draft" : "",
          severity: decision === "valid" ? "P2" : null,
        })),
      };
      const beforeChange = await readEvidenceOutput(root);
      await writeFile(editedReviews, JSON.stringify(edited));
      await waitForEvidenceOutput(
        root,
        beforeChange,
        "Review ledger changed on disk; canonical validation status was cleared.",
      );
      await api.loadReviews(root, editedReviews);
      const before = api.getSnapshot();
      assert.equal(before.canonicallyValidated, false);
      provider.update(before);
      const row = testTreeView(before).find(
        (candidate) => candidate.candidate.candidate_id === tree.candidate_id,
      );
      assert.ok(row);
      const item = provider.getTreeItem(row);
      assert.equal(item.description, `${decision} · ${tree.confidence}`);
      assert.ok(item.iconPath instanceof vscode.ThemeIcon);
      assert.equal(item.iconPath.id, decision === "valid" ? "error" : "pass");
      const output = await readEvidenceOutput(root);
      await vscode.commands.executeCommand("rigorFoundry.validateReviews");
      const refusal = await waitForEvidenceOutput(
        root,
        output,
        "RigorFoundry CLI failed with exit code 2",
      );
      assert.deepEqual(api.getSnapshot(), before);
      assert.equal(api.getSnapshot().canonicallyValidated, false);
      observations.push({
        decision,
        icon: item.iconPath.id,
        refusal,
        canonicallyValidated: false,
      });
    }
    await writeFile(
      path.join(root, ".rigor", "unvalidated-tree-observations.json"),
      JSON.stringify({ inputScope: "Explicit invalid copies of real CLI evidence", observations }),
      { flag: "wx" },
    );
  } finally {
    await api.loadReport(root, reportPath);
    await rm(edits, { recursive: true, force: true });
  }
}
