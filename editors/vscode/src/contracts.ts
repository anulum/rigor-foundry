// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence contract parser

/**
 * Parse the report and review fields needed by the evidence display.
 * Check supported shapes, identities, paths, and cross-binding while leaving canonical validity to the CLI.
 * @module
 */

/** An authored refusal whose message can be displayed without native process or file details. */
export class EvidenceRefusal extends Error {
  /**
   * Preserve a display-safe explanation and an optional undisplayed diagnostic cause.
   * @param message - Explanation authored by the extension, without raw external diagnostics.
   * @param options - Original failure retained for programmatic diagnosis.
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EvidenceRefusal";
  }
}

/** Canonical RigorFoundry review decisions displayed by the extension. */
export type ReviewDecision = "valid" | "invalid" | "accepted-boundary" | "needs-evidence";

/** Common schema, path, and inclusive source coordinates of a candidate anchor. */
interface CandidateAnchorBase {
  /** Anchor envelope version accepted by this extension. */
  readonly schema_version: "1.0";
  /** Discriminant selecting a source blob or the repository tree. */
  readonly kind: "tracked-blob" | "repository-tree";
  /** Portable repository-relative path; a tree anchor may use the root dot. */
  readonly path: string;
  /** First one-based source line; repository-tree anchors use one. */
  readonly line_start: number;
  /** Last inclusive source line; repository-tree anchors use one. */
  readonly line_end: number;
}

/** Exact Git blob and content identities for a tracked source span. */
export interface TrackedBlobAnchor extends CandidateAnchorBase {
  /** Selects the tracked-file interpretation of this anchor. */
  readonly kind: "tracked-blob";
  /** Lowercase SHA-1 or SHA-256 Git object identifier of the tracked blob. */
  readonly blob_oid: string;
  /** SHA-256 identity of the exact source bytes described by the report. */
  readonly content_sha256: string;
}

/** Exact Git tree and tracked-content identities for repository-wide evidence. */
export interface RepositoryTreeAnchor extends CandidateAnchorBase {
  /** Selects the repository-wide interpretation of this anchor. */
  readonly kind: "repository-tree";
  /** Lowercase SHA-1 or SHA-256 Git identifier of the repository tree. */
  readonly tree_oid: string;
  /** SHA-256 identity of the tracked-content inventory described by the report. */
  readonly tracked_content_sha256: string;
}

/** Stable source or repository locus attached to one candidate. */
export type CandidateAnchor = TrackedBlobAnchor | RepositoryTreeAnchor;

/** Structurally checked candidate fields needed by the evidence view. */
export interface AuditCandidate {
  /** Stable lowercase SHA-256 candidate identity supplied by the scanner. */
  readonly candidate_id: string;
  /** Grouping label used by the evidence tree. */
  readonly category: string;
  /** Scanner rule identifier shown alongside the source locus. */
  readonly rule_id: string;
  /** Checked source span or repository-tree locus and recorded content identities. */
  readonly anchor: CandidateAnchor;
  /** Recorded source symbol; empty when no symbol applies. */
  readonly symbol: string;
  /** Recorded observation shown as plain evidence text. */
  readonly evidence: string;
  /** Scanner confidence label, independent of any reviewer decision. */
  readonly confidence: "low" | "medium" | "high";
  /** Scanner explanation for reporting this candidate. */
  readonly rationale: string;
  /** Suggested verification text; displaying it does not execute it. */
  readonly verification: string;
}

/** Structurally checked subset of audit-report schema 1.3. */
export interface AuditReport {
  /** Report envelope version supported for structural display. */
  readonly schema_version: "1.3";
  /** Scanner version recorded by the report producer. */
  readonly scanner_version: string;
  /** Version of the rule pack recorded by the scanner. */
  readonly rule_pack_version: string;
  /** Recorded rule-pack SHA-256 identity; canonical validation belongs to the CLI. */
  readonly rule_pack_digest: string;
  /** Recorded report SHA-256 identity used to cross-bind review records. */
  readonly report_digest: string;
  /** Recorded absolute repository root, checked against the selected workspace on load. */
  readonly repository_root: string;
  /** Recorded Git head text, displayed without asserting current checkout parity. */
  readonly head: string;
  /** Recorded branch name; empty for a detached head. */
  readonly branch: string;
  /** Ordered, structurally checked candidates with unique identities. */
  readonly candidates: readonly AuditCandidate[];
}

/** Review-ledger record cross-bound to a loaded report candidate. */
export interface ReviewRecord {
  /** Report identity to which this review record binds. */
  readonly report_digest: string;
  /** Identity of the known report candidate being reviewed. */
  readonly candidate_id: string;
  /** Reviewer decision displayed independently of scanner confidence. */
  readonly decision: ReviewDecision;
  /** Reviewer attribution text; may be empty in a draft ledger. */
  readonly reviewer: string;
  /** Recorded review timestamp text; canonical temporal checks belong to the CLI. */
  readonly reviewed_at: string;
  /** Reviewer explanation, retained verbatim for display. */
  readonly rationale: string;
  /** Ordered reviewer evidence references, without executing or fetching them. */
  readonly evidence: readonly string[];
  /** Priority label available only for valid decisions; null otherwise. */
  readonly severity: "P0" | "P1" | "P2" | "P3" | "P4" | null;
  /** Recorded remediation owner, which may be unassigned in a draft. */
  readonly owner: string;
  /** Recorded dependency identifiers, without scheduling work. */
  readonly dependencies: readonly string[];
  /** Recorded acceptance conditions, without claiming their execution. */
  readonly acceptance_gates: readonly string[];
  /** Review title, which may be empty in a draft. */
  readonly title: string;
  /** Recorded explanation for an accepted boundary. */
  readonly boundary_justification: string;
  /** Recorded boundary expiry text; displaying it does not validate freshness. */
  readonly expires_at: string;
  /** Recorded conditions requiring a new review. */
  readonly reopen_triggers: readonly string[];
}

/** Review document using the canonical schema 1.0 envelope. */
export interface ReviewDocument {
  /** Review-ledger envelope version accepted by the extension. */
  readonly schema_version: "1.0";
  /** Ordered records cross-bound to the currently loaded report. */
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

/**
 * Narrow a JSON value to a field dictionary without accepting null or arrays.
 * @param value - Untrusted parsed JSON value.
 * @param label - Authored schema location used in refusal messages.
 * @returns The object dictionary; its individual values remain unknown.
 */
function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new EvidenceRefusal(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Require text and distinguish fields whose schema permits an empty string.
 * @param value - Untrusted field value.
 * @param label - Authored schema location used in refusal messages.
 * @param allowEmpty - Whether the field permits zero characters.
 * @returns The checked string without trimming or normalizing its content.
 */
function text(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    throw new EvidenceRefusal(
      `${label} must be ${allowEmpty ? "a string" : "a non-empty string"}`,
    );
  }
  return value;
}

/**
 * Check the lexical representation of a SHA-256 identity without recomputing it.
 * @param value - Untrusted field expected to contain 64 lowercase hexadecimal characters.
 * @param label - Authored schema location used in refusal messages.
 * @returns The digest string, whose canonical content binding remains a CLI responsibility.
 */
function digest(value: unknown, label: string): string {
  const parsed = text(value, label);
  if (!DIGEST.test(parsed)) {
    throw new EvidenceRefusal(`${label} must be a lowercase SHA-256 digest`);
  }
  return parsed;
}

/**
 * Accept the lowercase Git object identifier forms supported by the report schema.
 * @param value - Untrusted SHA-1 or SHA-256 Git object identifier.
 * @param label - Authored schema location used in refusal messages.
 * @returns The lexical identifier without asserting that the object exists.
 */
function objectId(value: unknown, label: string): string {
  const parsed = text(value, label);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(parsed)) {
    throw new EvidenceRefusal(`${label} must be a lowercase Git object identifier`);
  }
  return parsed;
}

/**
 * Require a positive integral source coordinate.
 * @param value - Untrusted one-based line coordinate.
 * @param label - Authored schema location used in refusal messages.
 * @returns The checked number; file-specific line bounds are checked when evidence opens.
 */
function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new EvidenceRefusal(`${label} must be a positive integer`);
  }
  return value as number;
}

/**
 * Check an ordered array of text fields while preserving empty entries.
 * @param value - Untrusted array of review metadata values.
 * @param label - Authored schema location used to identify a rejected element.
 * @returns A new array containing checked strings in their original order.
 */
function strings(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value)) {
    throw new EvidenceRefusal(`${label} must be an array`);
  }
  return value.map((item, index) => text(item, `${label}[${String(index)}]`, true));
}

/**
 * Return a portable repository path or reject escape and ambiguity segments.
 * @param value - Forward-slash repository-relative path recorded in an anchor.
 * @param allowRoot - Whether the repository-tree root dot is an accepted locus.
 * @returns The checked path, without resolving it against the current filesystem.
 * @throws {EvidenceRefusal} When the path is absolute, empty, ambiguous, or escaping.
 */
export function assertRepositoryPath(value: string, allowRoot = false): string {
  if (allowRoot && value === ".") {
    return value;
  }
  if (value.includes("\\") || value.startsWith("/") || value.includes("\0")) {
    throw new EvidenceRefusal("evidence path must be a portable repository-relative path");
  }
  const parts = value.split("/");
  if (
    value.length === 0 ||
    parts.some((part) => part.length === 0 || part === ".." || part === ".")
  ) {
    throw new EvidenceRefusal("evidence path must not contain dot segments");
  }
  return value;
}

/**
 * Check the discriminated anchor envelope and its kind-specific identity fields.
 * @param value - Untrusted anchor object from one report candidate.
 * @param label - Authored schema location used in refusal messages.
 * @returns A new tracked-blob or fixed-locus repository-tree anchor.
 */
function parseAnchor(value: unknown, label: string): CandidateAnchor {
  const data = record(value, label);
  if (data["schema_version"] !== "1.0") {
    throw new EvidenceRefusal(`${label}.schema_version is unsupported`);
  }
  if (data["kind"] !== "tracked-blob" && data["kind"] !== "repository-tree") {
    throw new EvidenceRefusal(`${label}.kind is unsupported`);
  }
  const lineStart = positiveInteger(data["line_start"], `${label}.line_start`);
  const lineEnd = positiveInteger(data["line_end"], `${label}.line_end`);
  if (lineEnd < lineStart) {
    throw new EvidenceRefusal(`${label} has an inverted line span`);
  }
  const path = assertRepositoryPath(
    text(data["path"], `${label}.path`, true),
    data["kind"] === "repository-tree",
  );
  if (data["kind"] === "tracked-blob") {
    return {
      schema_version: "1.0",
      kind: "tracked-blob",
      path,
      line_start: lineStart,
      line_end: lineEnd,
      blob_oid: objectId(data["blob_oid"], `${label}.blob_oid`),
      content_sha256: digest(data["content_sha256"], `${label}.content_sha256`),
    };
  }
  if (lineStart !== 1 || lineEnd !== 1) {
    throw new EvidenceRefusal(`${label} repository-tree span must be the fixed 1:1 locus`);
  }
  return {
    schema_version: "1.0",
    kind: "repository-tree",
    path,
    line_start: lineStart,
    line_end: lineEnd,
    tree_oid: objectId(data["tree_oid"], `${label}.tree_oid`),
    tracked_content_sha256: digest(
      data["tracked_content_sha256"],
      `${label}.tracked_content_sha256`,
    ),
  };
}

/**
 * Check the candidate subset needed to render and locate its recorded evidence.
 * @param value - Untrusted candidate object from the report array.
 * @param index - Zero-based position used to identify malformed fields.
 * @returns A checked display candidate without asserting canonical scanner validity.
 */
function parseCandidate(value: unknown, index: number): AuditCandidate {
  const label = `report.candidates[${String(index)}]`;
  const data = record(value, label);
  const confidence = text(data["confidence"], `${label}.confidence`);
  if (!CONFIDENCES.has(confidence)) {
    throw new EvidenceRefusal(`${label}.confidence is unsupported`);
  }
  return {
    candidate_id: digest(data["candidate_id"], `${label}.candidate_id`),
    category: text(data["category"], `${label}.category`),
    rule_id: text(data["rule_id"], `${label}.rule_id`),
    anchor: parseAnchor(data["anchor"], `${label}.anchor`),
    symbol: text(data["symbol"], `${label}.symbol`, true),
    evidence: text(data["evidence"], `${label}.evidence`),
    confidence: confidence as AuditCandidate["confidence"],
    rationale: text(data["rationale"], `${label}.rationale`),
    verification: text(data["verification"], `${label}.verification`),
  };
}

/**
 * Parse the report fields required for bounded display without claiming canonical validity.
 * @param value - Untrusted parsed report document.
 * @returns A display report with supported schema and unique candidate identities.
 * @throws {EvidenceRefusal} When a required field, anchor, or identity is malformed.
 */
export function parseAuditReport(value: unknown): AuditReport {
  const data = record(value, "report");
  if (data["schema_version"] !== "1.3") {
    throw new EvidenceRefusal("report.schema_version is unsupported; use a compatible extension");
  }
  if (!Array.isArray(data["candidates"])) {
    throw new EvidenceRefusal("report.candidates must be an array");
  }
  const candidates = data["candidates"].map(parseCandidate);
  const identities = new Set(candidates.map((candidate) => candidate.candidate_id));
  if (identities.size !== candidates.length) {
    throw new EvidenceRefusal("report candidate identities must be unique");
  }
  return {
    schema_version: "1.3",
    scanner_version: text(data["scanner_version"], "report.scanner_version"),
    rule_pack_version: text(data["rule_pack_version"], "report.rule_pack_version"),
    rule_pack_digest: digest(data["rule_pack_digest"], "report.rule_pack_digest"),
    report_digest: digest(data["report_digest"], "report.report_digest"),
    repository_root: text(data["repository_root"], "report.repository_root"),
    head: text(data["head"], "report.head"),
    branch: text(data["branch"], "report.branch", true),
    candidates,
  };
}

/**
 * Check a review's display fields and the decision-dependent severity restriction.
 * @param value - Untrusted review record from the ledger array.
 * @param index - Zero-based position used to identify malformed fields.
 * @returns A checked record pending report and candidate cross-binding.
 */
function parseReview(value: unknown, index: number): ReviewRecord {
  const label = `reviews.reviews[${String(index)}]`;
  const data = record(value, label);
  const decision = text(data["decision"], `${label}.decision`);
  if (!DECISIONS.has(decision as ReviewDecision)) {
    throw new EvidenceRefusal(`${label}.decision is unsupported`);
  }
  const severity = data["severity"];
  if (severity !== null && (typeof severity !== "string" || !SEVERITIES.has(severity))) {
    throw new EvidenceRefusal(`${label}.severity is unsupported`);
  }
  if (decision !== "valid" && severity !== null) {
    throw new EvidenceRefusal(`${label}.severity is allowed only for valid decisions`);
  }
  return {
    report_digest: digest(data["report_digest"], `${label}.report_digest`),
    candidate_id: digest(data["candidate_id"], `${label}.candidate_id`),
    decision: decision as ReviewDecision,
    reviewer: text(data["reviewer"], `${label}.reviewer`, true),
    reviewed_at: text(data["reviewed_at"], `${label}.reviewed_at`, true),
    rationale: text(data["rationale"], `${label}.rationale`, true),
    evidence: strings(data["evidence"], `${label}.evidence`),
    severity: severity as ReviewRecord["severity"],
    owner: text(data["owner"], `${label}.owner`, true),
    dependencies: strings(data["dependencies"], `${label}.dependencies`),
    acceptance_gates: strings(data["acceptance_gates"], `${label}.acceptance_gates`),
    title: text(data["title"], `${label}.title`, true),
    boundary_justification: text(
      data["boundary_justification"],
      `${label}.boundary_justification`,
      true,
    ),
    expires_at: text(data["expires_at"], `${label}.expires_at`, true),
    reopen_triggers: strings(data["reopen_triggers"], `${label}.reopen_triggers`),
  };
}

/**
 * Parse reviews and cross-bind every record to the loaded report and candidates.
 * @param value - Untrusted parsed review ledger.
 * @param report - Structurally checked report currently selected by the user.
 * @returns The checked ledger with unique records bound to known report candidates.
 * @throws {EvidenceRefusal} For unsupported schemas, malformed records, or binding conflicts.
 */
export function parseReviewDocument(value: unknown, report: AuditReport): ReviewDocument {
  const data = record(value, "reviews");
  if (data["schema_version"] !== "1.0") {
    throw new EvidenceRefusal("reviews.schema_version is unsupported");
  }
  if (!Array.isArray(data["reviews"])) {
    throw new EvidenceRefusal("reviews.reviews must be an array");
  }
  const reviews = data["reviews"].map(parseReview);
  const candidateIds = new Set(report.candidates.map((candidate) => candidate.candidate_id));
  const reviewedIds = new Set<string>();
  for (const review of reviews) {
    if (review.report_digest !== report.report_digest) {
      throw new EvidenceRefusal(
        `review ${review.candidate_id} does not bind the loaded report digest`,
      );
    }
    if (!candidateIds.has(review.candidate_id)) {
      throw new EvidenceRefusal(`review references unknown candidate ${review.candidate_id}`);
    }
    if (reviewedIds.has(review.candidate_id)) {
      throw new EvidenceRefusal(`duplicate review for candidate ${review.candidate_id}`);
    }
    reviewedIds.add(review.candidate_id);
  }
  return { schema_version: "1.0", reviews };
}
