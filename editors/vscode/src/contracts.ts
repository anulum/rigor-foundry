// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence contract parser

/** Canonical RigorFoundry review decisions displayed by the extension. */
export type ReviewDecision =
  | "valid"
  | "invalid"
  | "accepted-boundary"
  | "needs-evidence";

interface CandidateAnchorBase {
  readonly schema_version: "1.0";
  readonly kind: "tracked-blob" | "repository-tree";
  readonly path: string;
  readonly line_start: number;
  readonly line_end: number;
}

/** Exact Git blob and content identities for a tracked source span. */
export interface TrackedBlobAnchor extends CandidateAnchorBase {
  readonly kind: "tracked-blob";
  readonly blob_oid: string;
  readonly content_sha256: string;
}

/** Exact Git tree and tracked-content identities for repository-wide evidence. */
export interface RepositoryTreeAnchor extends CandidateAnchorBase {
  readonly kind: "repository-tree";
  readonly tree_oid: string;
  readonly tracked_content_sha256: string;
}

/** Stable source or repository locus attached to one candidate. */
export type CandidateAnchor = TrackedBlobAnchor | RepositoryTreeAnchor;

/** Structurally checked candidate fields needed by the evidence view. */
export interface AuditCandidate {
  readonly candidate_id: string;
  readonly category: string;
  readonly rule_id: string;
  readonly anchor: CandidateAnchor;
  readonly symbol: string;
  readonly evidence: string;
  readonly confidence: "low" | "medium" | "high";
  readonly rationale: string;
  readonly verification: string;
}

/** Structurally checked subset of audit-report schema 1.3. */
export interface AuditReport {
  readonly schema_version: "1.3";
  readonly scanner_version: string;
  readonly rule_pack_version: string;
  readonly rule_pack_digest: string;
  readonly report_digest: string;
  readonly repository_root: string;
  readonly head: string;
  readonly branch: string;
  readonly candidates: readonly AuditCandidate[];
}

/** Review-ledger record cross-bound to a loaded report candidate. */
export interface ReviewRecord {
  readonly report_digest: string;
  readonly candidate_id: string;
  readonly decision: ReviewDecision;
  readonly reviewer: string;
  readonly reviewed_at: string;
  readonly rationale: string;
  readonly evidence: readonly string[];
  readonly severity: "P0" | "P1" | "P2" | "P3" | "P4" | null;
  readonly owner: string;
  readonly dependencies: readonly string[];
  readonly acceptance_gates: readonly string[];
  readonly title: string;
  readonly boundary_justification: string;
  readonly expires_at: string;
  readonly reopen_triggers: readonly string[];
}

/** Review document using the canonical schema 1.0 envelope. */
export interface ReviewDocument {
  readonly schema_version: "1.0";
  readonly reviews: readonly ReviewRecord[];
}

const DIGEST = /^[0-9a-f]{64}$/u;
const DECISIONS = new Set<ReviewDecision>([
  "valid",
  "invalid",
  "accepted-boundary",
  "needs-evidence",
]);
const CONFIDENCES = new Set(["low", "medium", "high"]);
const SEVERITIES = new Set(["P0", "P1", "P2", "P3", "P4"]);

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    throw new Error(`${label} must be ${allowEmpty ? "a string" : "a non-empty string"}`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  const parsed = text(value, label);
  if (!DIGEST.test(parsed)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return parsed;
}

function objectId(value: unknown, label: string): string {
  const parsed = text(value, label);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(parsed)) {
    throw new Error(`${label} must be a lowercase Git object identifier`);
  }
  return parsed;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value as number;
}

function strings(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((item, index) => text(item, `${label}[${index}]`, true));
}

/** Return a portable repository path or reject escape and ambiguity segments. */
export function assertRepositoryPath(value: string, allowRoot = false): string {
  if (allowRoot && value === ".") {
    return value;
  }
  if (value.includes("\\") || value.startsWith("/") || value.includes("\0")) {
    throw new Error("evidence path must be a portable repository-relative path");
  }
  const parts = value.split("/");
  if (value.length === 0 || parts.some((part) => part.length === 0 || part === ".." || part === ".")) {
    throw new Error("evidence path must not contain dot segments");
  }
  return value;
}

function parseAnchor(value: unknown, label: string): CandidateAnchor {
  const data = record(value, label);
  if (data.schema_version !== "1.0") {
    throw new Error(`${label}.schema_version is unsupported`);
  }
  if (data.kind !== "tracked-blob" && data.kind !== "repository-tree") {
    throw new Error(`${label}.kind is unsupported`);
  }
  const lineStart = positiveInteger(data.line_start, `${label}.line_start`);
  const lineEnd = positiveInteger(data.line_end, `${label}.line_end`);
  if (lineEnd < lineStart) {
    throw new Error(`${label} has an inverted line span`);
  }
  const path = assertRepositoryPath(text(data.path, `${label}.path`, true), data.kind === "repository-tree");
  if (data.kind === "tracked-blob") {
    return {
      schema_version: "1.0",
      kind: "tracked-blob",
      path,
      line_start: lineStart,
      line_end: lineEnd,
      blob_oid: objectId(data.blob_oid, `${label}.blob_oid`),
      content_sha256: digest(data.content_sha256, `${label}.content_sha256`),
    };
  }
  if (lineStart !== 1 || lineEnd !== 1) {
    throw new Error(`${label} repository-tree span must be the fixed 1:1 locus`);
  }
  return {
    schema_version: "1.0",
    kind: "repository-tree",
    path,
    line_start: lineStart,
    line_end: lineEnd,
    tree_oid: objectId(data.tree_oid, `${label}.tree_oid`),
    tracked_content_sha256: digest(
      data.tracked_content_sha256,
      `${label}.tracked_content_sha256`,
    ),
  };
}

function parseCandidate(value: unknown, index: number): AuditCandidate {
  const label = `report.candidates[${index}]`;
  const data = record(value, label);
  const confidence = text(data.confidence, `${label}.confidence`);
  if (!CONFIDENCES.has(confidence)) {
    throw new Error(`${label}.confidence is unsupported`);
  }
  return {
    candidate_id: digest(data.candidate_id, `${label}.candidate_id`),
    category: text(data.category, `${label}.category`),
    rule_id: text(data.rule_id, `${label}.rule_id`),
    anchor: parseAnchor(data.anchor, `${label}.anchor`),
    symbol: text(data.symbol, `${label}.symbol`, true),
    evidence: text(data.evidence, `${label}.evidence`),
    confidence: confidence as AuditCandidate["confidence"],
    rationale: text(data.rationale, `${label}.rationale`),
    verification: text(data.verification, `${label}.verification`),
  };
}

/** Parse the report fields required for bounded display without claiming canonical validity. */
export function parseAuditReport(value: unknown): AuditReport {
  const data = record(value, "report");
  if (data.schema_version !== "1.3") {
    throw new Error("report.schema_version is unsupported; use a compatible extension");
  }
  if (!Array.isArray(data.candidates)) {
    throw new Error("report.candidates must be an array");
  }
  const candidates = data.candidates.map(parseCandidate);
  const identities = new Set(candidates.map((candidate) => candidate.candidate_id));
  if (identities.size !== candidates.length) {
    throw new Error("report candidate identities must be unique");
  }
  return {
    schema_version: "1.3",
    scanner_version: text(data.scanner_version, "report.scanner_version"),
    rule_pack_version: text(data.rule_pack_version, "report.rule_pack_version"),
    rule_pack_digest: digest(data.rule_pack_digest, "report.rule_pack_digest"),
    report_digest: digest(data.report_digest, "report.report_digest"),
    repository_root: text(data.repository_root, "report.repository_root"),
    head: text(data.head, "report.head"),
    branch: text(data.branch, "report.branch", true),
    candidates,
  };
}

function parseReview(value: unknown, index: number): ReviewRecord {
  const label = `reviews.reviews[${index}]`;
  const data = record(value, label);
  const decision = text(data.decision, `${label}.decision`);
  if (!DECISIONS.has(decision as ReviewDecision)) {
    throw new Error(`${label}.decision is unsupported`);
  }
  const severity = data.severity;
  if (severity !== null && (typeof severity !== "string" || !SEVERITIES.has(severity))) {
    throw new Error(`${label}.severity is unsupported`);
  }
  if (decision !== "valid" && severity !== null) {
    throw new Error(`${label}.severity is allowed only for valid decisions`);
  }
  return {
    report_digest: digest(data.report_digest, `${label}.report_digest`),
    candidate_id: digest(data.candidate_id, `${label}.candidate_id`),
    decision: decision as ReviewDecision,
    reviewer: text(data.reviewer, `${label}.reviewer`, true),
    reviewed_at: text(data.reviewed_at, `${label}.reviewed_at`, true),
    rationale: text(data.rationale, `${label}.rationale`, true),
    evidence: strings(data.evidence, `${label}.evidence`),
    severity: severity as ReviewRecord["severity"],
    owner: text(data.owner, `${label}.owner`, true),
    dependencies: strings(data.dependencies, `${label}.dependencies`),
    acceptance_gates: strings(data.acceptance_gates, `${label}.acceptance_gates`),
    title: text(data.title, `${label}.title`, true),
    boundary_justification: text(data.boundary_justification, `${label}.boundary_justification`, true),
    expires_at: text(data.expires_at, `${label}.expires_at`, true),
    reopen_triggers: strings(data.reopen_triggers, `${label}.reopen_triggers`),
  };
}

/** Parse reviews and cross-bind every record to the loaded report and candidates. */
export function parseReviewDocument(value: unknown, report: AuditReport): ReviewDocument {
  const data = record(value, "reviews");
  if (data.schema_version !== "1.0") {
    throw new Error("reviews.schema_version is unsupported");
  }
  if (!Array.isArray(data.reviews)) {
    throw new Error("reviews.reviews must be an array");
  }
  const reviews = data.reviews.map(parseReview);
  const candidateIds = new Set(report.candidates.map((candidate) => candidate.candidate_id));
  const reviewedIds = new Set<string>();
  for (const review of reviews) {
    if (review.report_digest !== report.report_digest) {
      throw new Error(`review ${review.candidate_id} does not bind the loaded report digest`);
    }
    if (!candidateIds.has(review.candidate_id)) {
      throw new Error(`review references unknown candidate ${review.candidate_id}`);
    }
    if (reviewedIds.has(review.candidate_id)) {
      throw new Error(`duplicate review for candidate ${review.candidate_id}`);
    }
    reviewedIds.add(review.candidate_id);
  }
  return {schema_version: "1.0", reviews};
}
