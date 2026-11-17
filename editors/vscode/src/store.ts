// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence-view state

/**
 * Own the loaded report and cross-bound review ledger as one evidence-view state.
 * Validate private copies of their exact bytes without replacing a newer selection.
 * @module
 */

import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runCli } from "./cli.js";
import type { CommandResult } from "./cli.js";
import { EvidenceRefusal, parseAuditReport, parseReviewDocument } from "./contracts.js";
import type { AuditReport, ReviewDocument, ReviewRecord } from "./contracts.js";
import { readBoundedJsonWithDigest } from "./fileAccess.js";

/** Immutable view state exposed to the tree and integration-test API. */
export interface EvidenceSnapshot {
  /** Last structurally accepted report, absent before the first successful load. */
  readonly report: AuditReport | undefined;
  /** Canonical repository directory accepted with the report, independent of editor focus. */
  readonly workspaceRoot: string | undefined;
  /** Fresh candidate-to-review lookup derived from the loaded ledger. */
  readonly reviews: ReadonlyMap<string, ReviewRecord>;
  /** Source path of the loaded report, without asserting that disk content is unchanged. */
  readonly reportPath: string | undefined;
  /** Source path of the ledger bound to the current report. */
  readonly reviewPath: string | undefined;
  /** Whether this exact loaded report/review byte pair has passed the CLI together. */
  readonly canonicallyValidated: boolean;
}

/** Accepted report and the exact source identity to which its owner was bound. */
export interface LoadedReport {
  /** Structurally accepted report; canonical semantics remain the CLI's responsibility. */
  readonly value: AuditReport;
  /** Canonical repository owning the report. */
  readonly root: string;
  /** Original contained report path. */
  readonly path: string;
  /** SHA-256 of the exact originally loaded bytes, including formatting. */
  readonly contentSha256: string;
}

/** Accepted review records and their exact source identity. */
export interface LoadedReviews {
  /** Structurally cross-bound review ledger. */
  readonly value: ReviewDocument;
  /** Original contained review path. */
  readonly path: string;
  /** SHA-256 of the exact originally loaded bytes, including formatting. */
  readonly contentSha256: string;
}

/** Own the loaded report/review pair and its session-local CLI validation status. */
export class EvidenceStore {
  /** Current accepted report, canonical owner and source byte identity. */
  private report: LoadedReport | undefined;
  /** Current cross-bound review ledger, cleared when a report loads. */
  private reviews: LoadedReviews | undefined;
  /** Opaque identity changed by successful loads and observed filesystem invalidation. */
  private selection = Symbol();
  /** Selection identities associated with issued snapshots without extending the public view. */
  private readonly snapshotSelections = new WeakMap<EvidenceSnapshot, symbol>();
  /** Exact selection whose private byte pair last passed the canonical CLI. */
  private validatedSelection: symbol | undefined;

  /**
   * Return a new read-only projection of the currently loaded evidence.
   * @returns Current report, fresh review lookup, source paths, and pair validation status.
   */
  public snapshot(): EvidenceSnapshot {
    const snapshot: EvidenceSnapshot = {
      report: this.report?.value,
      workspaceRoot: this.report?.root,
      reviews: new Map(
        (this.reviews?.value.reviews ?? []).map((review) => [review.candidate_id, review]),
      ),
      reportPath: this.report?.path,
      reviewPath: this.reviews?.path,
      canonicallyValidated: this.validatedSelection === this.selection,
    };
    this.snapshotSelections.set(snapshot, this.selection);
    return snapshot;
  }

  /**
   * Load a structurally checked report whose recorded repository is the active workspace.
   * @param root - Existing workspace directory against which the reported root is compared.
   * @param file - Existing bounded report file within that workspace.
   * @param maximumBytes - Evidence byte ceiling passed to the bounded file reader.
   * @returns Accepted report after clearing the previous ledger and validation binding.
   * @throws {EvidenceRefusal} For invalid evidence or a different canonical repository.
   */
  public async loadReport(root: string, file: string, maximumBytes: number): Promise<AuditReport> {
    const evidence = await readBoundedJsonWithDigest(root, file, maximumBytes);
    const report = parseAuditReport(evidence.value);
    const [canonicalRoot, canonicalReportedRoot] = await Promise.all([
      realpath(root),
      realpath(report.repository_root),
    ]);
    if (canonicalRoot !== canonicalReportedRoot) {
      throw new EvidenceRefusal(
        "audit report repository_root does not match the active workspace",
      );
    }
    this.report = {
      value: report,
      root: canonicalRoot,
      path: file,
      contentSha256: evidence.contentSha256,
    };
    this.reviews = undefined;
    this.clearCanonicalValidation();
    return report;
  }

  /**
   * Load review records cross-bound to the report selected when this read began.
   * @param root - Existing workspace containing the ledger file.
   * @param file - Existing bounded ledger whose records must bind the loaded report.
   * @param maximumBytes - Evidence byte ceiling passed to the bounded file reader.
   * @returns Accepted ledger while retaining its exact source byte identity.
   * @throws {EvidenceRefusal} For absent, changed, differently owned, or invalid evidence.
   */
  public async loadReviews(
    root: string,
    file: string,
    maximumBytes: number,
  ): Promise<ReviewDocument> {
    const report = this.report;
    const selection = this.selection;
    if (report === undefined) {
      throw new EvidenceRefusal("load an audit report before loading its review ledger");
    }
    if ((await realpath(root)) !== report.root) {
      throw new EvidenceRefusal("review ledger workspace does not match the loaded report");
    }
    const evidence = await readBoundedJsonWithDigest(root, file, maximumBytes);
    const document = parseReviewDocument(evidence.value, report.value);
    if (this.selection !== selection) {
      throw new EvidenceRefusal("evidence selection changed while loading the review ledger");
    }
    this.reviews = { value: document, path: file, contentSha256: evidence.contentSha256 };
    this.clearCanonicalValidation();
    return document;
  }

  /**
   * Validate the exact loaded bytes through the real CLI without reloading selected evidence.
   * @param snapshot - Snapshot issued by this store when the command selected its owner.
   * @param executable - Explicit configured canonical CLI, executed without a shell.
   * @param maximumBytes - Bound applied to original input reads before and after CLI execution.
   * @param timeoutMilliseconds - Hard process deadline passed to the bounded runner.
   * @returns Actual successful CLI output after input and selection revalidation.
   * @throws {EvidenceRefusal} For incomplete or stale selection, changed bytes, or CLI refusal.
   */
  public async validateReviews(
    snapshot: EvidenceSnapshot,
    executable: string,
    maximumBytes: number,
    timeoutMilliseconds: number,
  ): Promise<CommandResult> {
    const selection = this.snapshotSelections.get(snapshot);
    const assertSelected = (): void => {
      if (selection !== this.selection) {
        throw new EvidenceRefusal("evidence selection changed during canonical validation");
      }
    };
    assertSelected();
    const report = this.report;
    const reviews = this.reviews;
    if (report === undefined || reviews === undefined) {
      throw new EvidenceRefusal("load both the report and review ledger before validation");
    }
    this.validatedSelection = undefined;
    const readPair = async (): Promise<readonly [Buffer, Buffer]> => {
      const reportInput = await readBoundedJsonWithDigest(report.root, report.path, maximumBytes);
      const reviewInput = await readBoundedJsonWithDigest(report.root, reviews.path, maximumBytes);
      if (
        reportInput.contentSha256 !== report.contentSha256 ||
        reviewInput.contentSha256 !== reviews.contentSha256
      ) {
        throw new EvidenceRefusal(
          "evidence files changed; reload the report and review ledger before validation",
        );
      }
      return [reportInput.contentBytes, reviewInput.contentBytes];
    };
    const [reportBytes, reviewBytes] = await readPair();
    assertSelected();
    let result: CommandResult;
    if (process.platform === "win32") {
      const { validateWindowsPair } = await import("./windowsEvidence.js");
      result = await validateWindowsPair(
        executable,
        report.root,
        reportBytes,
        reviewBytes,
        timeoutMilliseconds,
      );
    } else {
      const directory = await mkdtemp(path.join(tmpdir(), "rigor-validation-"));
      const reportInput = path.join(directory, "report.json");
      const reviewInput = path.join(directory, "reviews.json");
      try {
        await writeFile(reportInput, reportBytes, { flag: "wx", mode: 0o400 });
        await writeFile(reviewInput, reviewBytes, { flag: "wx", mode: 0o400 });
        result = await runCli(
          executable,
          ["validate-review", "--report", reportInput, "--review", reviewInput],
          { cwd: report.root, timeoutMilliseconds },
        );
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
    await readPair();
    assertSelected();
    this.validatedSelection = selection;
    return result;
  }

  /** Invalidate validation and any pending completion after observed evidence changes. */
  public clearCanonicalValidation(): void {
    this.validatedSelection = undefined;
    this.selection = Symbol();
  }
}
