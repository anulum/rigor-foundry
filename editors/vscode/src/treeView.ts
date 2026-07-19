// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence tree view

import * as vscode from "vscode";
import {AuditCandidate, ReviewRecord} from "./contracts.js";
import {EvidenceSnapshot} from "./store.js";

/** Nodes presented by the category-grouped evidence tree. */
export type EvidenceNode = CategoryNode | CandidateNode;

/** One audit category and its ordered candidate children. */
export interface CategoryNode {
  readonly kind: "category";
  readonly category: string;
  readonly candidates: readonly AuditCandidate[];
}

/** One candidate and its optional review source. */
export interface CandidateNode {
  readonly kind: "candidate";
  readonly candidate: AuditCandidate;
  readonly review: ReviewRecord | undefined;
}

/** Render evidence provenance and fail-closed review labels without mutation commands. */
export class EvidenceTreeProvider implements vscode.TreeDataProvider<EvidenceNode> {
  private readonly changed = new vscode.EventEmitter<EvidenceNode | undefined>();
  private snapshot: EvidenceSnapshot = {
    report: undefined,
    reviews: new Map(),
    reportPath: undefined,
    reviewPath: undefined,
    canonicallyValidated: false,
  };

  public readonly onDidChangeTreeData = this.changed.event;

  /** Replace the displayed snapshot and notify VS Code listeners. */
  public update(snapshot: EvidenceSnapshot): void {
    this.snapshot = snapshot;
    this.changed.fire(undefined);
  }

  /** Convert a category or candidate node into its VS Code tree item. */
  public getTreeItem(element: EvidenceNode): vscode.TreeItem {
    if (element.kind === "category") {
      const item = new vscode.TreeItem(
        element.category,
        vscode.TreeItemCollapsibleState.Expanded,
      );
      item.description = `${element.candidates.length}`;
      item.iconPath = new vscode.ThemeIcon("folder");
      return item;
    }
    const candidate = element.candidate;
    const decision = element.review?.decision ?? "needs-evidence";
    const item = new vscode.TreeItem(
      `${candidate.rule_id}: ${candidate.anchor.path || "repository"}`,
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

  /** Return sorted categories or the candidates owned by one category. */
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
        .map(([category, candidates]) => ({kind: "category", category, candidates}));
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
