// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence tree view

/**
 * Render audit candidates grouped by category through the real VS Code tree API.
 * Present plain-text evidence, review attribution, and the loaded pair validation state.
 * @module
 */

import * as vscode from "vscode";
import type { AuditCandidate, ReviewRecord } from "./contracts.js";
import type { EvidenceSnapshot } from "./store.js";

/** Nodes presented by the category-grouped evidence tree. */
export type EvidenceNode = CategoryNode | CandidateNode;

/** One audit category and its ordered candidate children. */
export interface CategoryNode {
  /** Discriminant used to expand a category rather than open source evidence. */
  readonly kind: "category";
  /** Scanner category shared by this group's candidates. */
  readonly category: string;
  /** Candidates in report order, without changing scanner confidence or reviewer decisions. */
  readonly candidates: readonly AuditCandidate[];
}

/** One candidate and its optional review source. */
export interface CandidateNode {
  /** Discriminant selecting an individual evidence row. */
  readonly kind: "candidate";
  /** Structurally checked scanner candidate shown by this row. */
  readonly candidate: AuditCandidate;
  /** Cross-bound review record, absent when the candidate has no loaded review. */
  readonly review: ReviewRecord | undefined;
}

/** Render evidence provenance and fail-closed review labels without mutation commands. */
export class EvidenceTreeProvider implements vscode.TreeDataProvider<EvidenceNode> {
  /** Notification source for replacing the displayed evidence snapshot. */
  private readonly changed = new vscode.EventEmitter<EvidenceNode | undefined>();
  /** Last snapshot supplied by the evidence store; initially no report is loaded. */
  private snapshot: EvidenceSnapshot = {
    report: undefined,
    workspaceRoot: undefined,
    reviews: new Map(),
    reportPath: undefined,
    reviewPath: undefined,
    canonicallyValidated: false,
  };

  /** VS Code event invalidating all rows after a snapshot update. */
  public readonly onDidChangeTreeData = this.changed.event;

  /**
   * Replace the displayed snapshot and notify VS Code listeners.
   * @param snapshot - Accepted store projection to render without altering its decisions.
   */
  public update(snapshot: EvidenceSnapshot): void {
    this.snapshot = snapshot;
    this.changed.fire(undefined);
  }

  /**
   * Convert a category or candidate node into its VS Code tree item.
   * @param element - Group or evidence row previously returned by this provider.
   * @returns A tree item with plain-text provenance and an explicit evidence-opening command.
   */
  public getTreeItem(element: EvidenceNode): vscode.TreeItem {
    if (element.kind === "category") {
      const item = new vscode.TreeItem(element.category, vscode.TreeItemCollapsibleState.Expanded);
      item.description = String(element.candidates.length);
      item.iconPath = new vscode.ThemeIcon("folder");
      return item;
    }
    const candidate = element.candidate;
    const decision = element.review?.decision ?? "needs-evidence";
    const item = new vscode.TreeItem(
      `${candidate.rule_id}: ${candidate.anchor.path === "." ? "repository" : candidate.anchor.path}`,
      vscode.TreeItemCollapsibleState.None,
    );
    item.contextValue = "rigorFoundry.candidate";
    item.description = `${decision} · ${candidate.confidence}`;
    item.iconPath = new vscode.ThemeIcon(
      decision === "valid" ? "error" : decision === "invalid" ? "pass" : "question",
    );
    item.command = {
      command: "rigorFoundry.openEvidence",
      title: "Open candidate evidence",
      arguments: [element],
    };
    const validated = this.snapshot.canonicallyValidated ? "yes" : "no";
    item.tooltip = [
      `Candidate: ${candidate.candidate_id}`,
      `Report: ${this.snapshot.report?.report_digest ?? "not loaded"}`,
      `Decision source: ${element.review === undefined ? "no review record" : `review by ${element.review.reviewer || "unassigned"}`}`,
      `Canonical CLI validation: ${validated}`,
      "",
      candidate.evidence,
    ].join("\n");
    return item;
  }

  /**
   * Return sorted categories or the candidates owned by one category.
   * @param element - Parent group, leaf row, or undefined for the root of the tree.
   * @returns Ordered child rows; empty for a leaf or an unloaded report.
   */
  public getChildren(element?: EvidenceNode): EvidenceNode[] {
    const report = this.snapshot.report;
    if (report === undefined) {
      return [];
    }
    if (element === undefined) {
      const groups = new Map<string, AuditCandidate[]>();
      for (const candidate of report.candidates) {
        const group = groups.get(candidate.category) ?? [];
        group.push(candidate);
        groups.set(candidate.category, group);
      }
      return [...groups.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, candidates]) => ({ kind: "category", category, candidates }));
    }
    if (element.kind === "candidate") {
      return [];
    }
    return element.candidates.map((candidate) => ({
      kind: "candidate",
      candidate,
      review: this.snapshot.reviews.get(candidate.candidate_id),
    }));
  }
}
