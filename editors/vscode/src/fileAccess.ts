// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — bounded workspace evidence access

/**
 * Resolve contained workspace paths and read bounded UTF-8 JSON evidence.
 * Check file kind, descriptor and path stability, and exact byte identity before returning parsed values.
 * @module
 */

import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { EvidenceRefusal } from "./contracts.js";

/**
 * Compare resolved filesystem paths using the current platform's path semantics.
 * @param root - Absolute directory against which containment is checked.
 * @param candidate - Absolute path that may identify the root itself.
 * @returns Whether the relative path stays within the root without changing volumes.
 */
function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
  );
}

/**
 * Resolve a configured relative path without allowing lexical workspace escape.
 * @param workspaceRoot - Workspace directory against which configuration is resolved.
 * @param configuredPath - Nonempty relative path supplied by extension configuration.
 * @returns The absolute lexical path; existing targets still require canonical verification.
 * @throws {EvidenceRefusal} For absolute, empty, NUL-containing, or escaping paths.
 */
export function resolveWorkspacePath(workspaceRoot: string, configuredPath: string): string {
  if (
    configuredPath.length === 0 ||
    path.isAbsolute(configuredPath) ||
    configuredPath.includes("\0")
  ) {
    throw new EvidenceRefusal(
      "configured evidence paths must be non-empty and workspace-relative",
    );
  }
  const resolved = path.resolve(workspaceRoot, configuredPath);
  if (!isInside(path.resolve(workspaceRoot), resolved)) {
    throw new EvidenceRefusal("configured evidence path escapes the workspace");
  }
  return resolved;
}

/**
 * Resolve an existing path and prove that its canonical target remains in the workspace.
 * @param workspaceRoot - Existing workspace directory, including any canonical alias.
 * @param candidatePath - Existing file or directory whose resolved target will be inspected.
 * @returns The canonical target path inside the canonical workspace root.
 * @throws {EvidenceRefusal} When canonical resolution escapes the workspace.
 */
export async function verifyExistingWorkspacePath(
  workspaceRoot: string,
  candidatePath: string,
): Promise<string> {
  const canonicalRoot = await realpath(workspaceRoot);
  const canonicalCandidate = await realpath(candidatePath);
  if (!isInside(canonicalRoot, canonicalCandidate)) {
    throw new EvidenceRefusal("evidence path resolves outside the workspace");
  }
  return canonicalCandidate;
}

/**
 * Prove that an existing workspace path is a non-symlink regular file.
 * @param workspaceRoot - Existing workspace directory used for canonical containment.
 * @param candidatePath - File path whose final component must not be a symbolic link.
 * @returns The regular file's canonical path inside the workspace.
 * @throws {EvidenceRefusal} For a symbolic link, nonregular target, or escaping path.
 */
export async function verifyExistingRegularWorkspacePath(
  workspaceRoot: string,
  candidatePath: string,
): Promise<string> {
  const candidateStat = await lstat(candidatePath);
  if (candidateStat.isSymbolicLink() || !candidateStat.isFile()) {
    throw new EvidenceRefusal("evidence path must identify a non-symlink regular file");
  }
  return await verifyExistingWorkspacePath(workspaceRoot, candidatePath);
}

/**
 * Read one stable, bounded regular file descriptor and parse its UTF-8 JSON value.
 * @param workspaceRoot - Existing workspace containing the evidence file.
 * @param candidatePath - Existing non-symlink JSON file to read.
 * @param maximumBytes - Integral byte ceiling from one through 64 mebibytes.
 * @returns The unknown JSON value, which still requires schema-specific checks.
 * @throws {EvidenceRefusal} When bounds, containment, stability, encoding, or JSON fail.
 */
export async function readBoundedJson(
  workspaceRoot: string,
  candidatePath: string,
  maximumBytes: number,
): Promise<unknown> {
  return (await readBoundedJsonWithDigest(workspaceRoot, candidatePath, maximumBytes)).value;
}

/** Bounded JSON value paired with the SHA-256 identity of its exact UTF-8 bytes. */
export interface BoundedJsonWithDigest {
  /** Parsed JSON value, without a claim of schema or canonical evidence validity. */
  readonly value: unknown;
  /** Lowercase SHA-256 of the exact stable file bytes parsed into the value. */
  readonly contentSha256: string;
  /** Exact bounded input bytes, retained for passing the same input to the canonical CLI. */
  readonly contentBytes: Buffer;
}

/**
 * Read bounded JSON and retain the exact byte identity used for validation state.
 * @param workspaceRoot - Existing workspace containing the evidence file.
 * @param candidatePath - Existing non-symlink JSON file to read through a stable descriptor.
 * @param maximumBytes - Integral byte ceiling from one through 64 mebibytes.
 * @returns Parsed JSON and its exact byte digest after identity and extra-byte checks.
 * @throws {EvidenceRefusal} When bounds, containment, stability, encoding, or JSON fail.
 */
export async function readBoundedJsonWithDigest(
  workspaceRoot: string,
  candidatePath: string,
  maximumBytes: number,
): Promise<BoundedJsonWithDigest> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 67_108_864) {
    throw new EvidenceRefusal("maximum evidence bytes must be an integer from 1 through 67108864");
  }
  if (process.platform === "win32") {
    const existing = await lstat(candidatePath);
    if (existing.isSymbolicLink())
      throw new EvidenceRefusal("evidence path must not be a symbolic link");
    const canonicalRoot = await realpath(workspaceRoot);
    const canonicalFile = await verifyExistingWorkspacePath(canonicalRoot, candidatePath);
    if (!existing.isFile())
      throw new EvidenceRefusal("evidence path must identify a regular file");
    if (existing.size > maximumBytes)
      throw new EvidenceRefusal(
        `evidence file exceeds the configured ${String(maximumBytes)}-byte limit`,
      );
    const { readWindowsEvidence } = await import("./windowsEvidence.js");
    let bytes: Buffer;
    try {
      bytes = await readWindowsEvidence(canonicalRoot, canonicalFile, maximumBytes);
    } catch (error: unknown) {
      throw new EvidenceRefusal(
        "native evidence file could not be read as a stable contained regular file",
        { cause: error },
      );
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new EvidenceRefusal("evidence file is not valid UTF-8");
    }
    try {
      return {
        value: JSON.parse(content) as unknown,
        contentSha256: createHash("sha256").update(bytes).digest("hex"),
        contentBytes: bytes,
      };
    } catch (error: unknown) {
      throw new EvidenceRefusal("evidence file is not valid JSON", { cause: error });
    }
  }
  const pathBefore = await lstat(candidatePath);
  if (pathBefore.isSymbolicLink()) {
    throw new EvidenceRefusal("evidence path must not be a symbolic link");
  }
  const canonicalPath = await verifyExistingWorkspacePath(workspaceRoot, candidatePath);
  const handle = await open(canonicalPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile()) {
      throw new EvidenceRefusal("evidence path must identify a regular file");
    }
    if (before.size > maximumBytes) {
      throw new EvidenceRefusal(
        `evidence file exceeds the configured ${String(maximumBytes)}-byte limit`,
      );
    }
    const boundedContent = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < boundedContent.length) {
      const result = await handle.read(
        boundedContent,
        offset,
        boundedContent.length - offset,
        null,
      );
      if (result.bytesRead === 0) {
        break;
      }
      offset += result.bytesRead;
    }
    const extra = Buffer.alloc(1);
    const extraRead = await handle.read(extra, 0, 1, null);
    const after = await handle.stat();
    const pathAfter = await lstat(candidatePath);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      pathBefore.dev !== pathAfter.dev ||
      pathBefore.ino !== pathAfter.ino ||
      pathAfter.isSymbolicLink() ||
      offset !== before.size ||
      extraRead.bytesRead !== 0
    ) {
      throw new EvidenceRefusal("evidence file changed while it was being read");
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(boundedContent);
    } catch {
      throw new EvidenceRefusal("evidence file is not valid UTF-8");
    }
    try {
      return {
        value: JSON.parse(content) as unknown,
        contentSha256: createHash("sha256").update(boundedContent).digest("hex"),
        contentBytes: boundedContent,
      };
    } catch (error: unknown) {
      throw new EvidenceRefusal("evidence file is not valid JSON", { cause: error });
    }
  } finally {
    await handle.close();
  }
}
