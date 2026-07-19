// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence-view state

import {AuditReport, parseAuditReport, parseReviewDocument, ReviewDocument, ReviewRecord} from "./contracts.js";
import {readBoundedJson, readBoundedJsonWithDigest} from "./fileAccess.js";
import {realpath} from "node:fs/promises";

/** Immutable view state exposed to the tree and integration-test API. */
export interface EvidenceSnapshot {
  readonly report: AuditReport | undefined;
  readonly reviews: ReadonlyMap<string, ReviewRecord>;
  readonly reportPath: string | undefined;
  readonly reviewPath: string | undefined;
  readonly canonicallyValidated: boolean;
}

/** Own the loaded report/review pair and its session-local CLI validation status. */
export class EvidenceStore {
  private report: AuditReport | undefined;
  private reviewDocument: ReviewDocument | undefined;
  private reportPath: string | undefined;
  private reviewPath: string | undefined;
  private reviewContentDigest: string | undefined;
  private validatedBinding: string | undefined;

  /** Return a new immutable projection of the currently loaded evidence. */
  public snapshot(): EvidenceSnapshot {
    const reviews = new Map(
      (this.reviewDocument?.reviews ?? []).map((review) => [review.candidate_id, review]),
    );
    return {
      report: this.report,
      reviews,
      reportPath: this.reportPath,
      reviewPath: this.reviewPath,
      canonicallyValidated:
        this.report !== undefined &&
        this.reviewContentDigest !== undefined &&
        this.validatedBinding === `${this.report.report_digest}\0${this.reviewContentDigest}`,
    };
  }

  /** Load a structurally checked report whose recorded repository is the active workspace. */
  public async loadReport(root: string, file: string, maximumBytes: number): Promise<AuditReport> {
    const report = parseAuditReport(await readBoundedJson(root, file, maximumBytes));
    const [canonicalRoot, canonicalReportedRoot] = await Promise.all([
      realpath(root),
      realpath(report.repository_root),
    ]);
    if (canonicalRoot !== canonicalReportedRoot) {
      throw new Error("audit report repository_root does not match the active workspace");
    }
    this.report = report;
    this.reportPath = file;
    this.reviewDocument = undefined;
    this.reviewPath = undefined;
    this.reviewContentDigest = undefined;
    this.validatedBinding = undefined;
    return report;
  }

  /** Load review records cross-bound to the current report and clear prior validation state. */
  public async loadReviews(root: string, file: string, maximumBytes: number): Promise<ReviewDocument> {
    if (this.report === undefined) {
      throw new Error("load an audit report before loading its review ledger");
    }
    const evidence = await readBoundedJsonWithDigest(root, file, maximumBytes);
    const document = parseReviewDocument(evidence.value, this.report);
    this.reviewDocument = document;
    this.reviewPath = file;
    this.reviewContentDigest = evidence.contentSha256;
    this.validatedBinding = undefined;
    return document;
  }

  /** Mark the loaded in-memory report/review snapshot after the canonical CLI succeeds. */
  public markCanonicallyValidated(): void {
    if (this.report === undefined || this.reviewContentDigest === undefined) {
      throw new Error("a report and review ledger must be loaded before validation");
    }
    this.validatedBinding = `${this.report.report_digest}\0${this.reviewContentDigest}`;
  }

  /** Invalidate CLI validation after an observed report or review filesystem change. */
  public clearCanonicalValidation(): void {
    this.validatedBinding = undefined;
  }
}
