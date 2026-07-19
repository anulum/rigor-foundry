// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — bounded workspace evidence access

import {constants} from "node:fs";
import {lstat, open, realpath} from "node:fs/promises";
import {createHash} from "node:crypto";
import path from "node:path";

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

/** Resolve a configured relative path without allowing lexical workspace escape. */
export function resolveWorkspacePath(workspaceRoot: string, configuredPath: string): string {
  if (configuredPath.length === 0 || path.isAbsolute(configuredPath) || configuredPath.includes("\0")) {
    throw new Error("configured evidence paths must be non-empty and workspace-relative");
  }
  const resolved = path.resolve(workspaceRoot, configuredPath);
  if (!isInside(path.resolve(workspaceRoot), resolved)) {
    throw new Error("configured evidence path escapes the workspace");
  }
  return resolved;
}

/** Resolve an existing path and prove that its canonical target remains in the workspace. */
export async function verifyExistingWorkspacePath(
  workspaceRoot: string,
  candidatePath: string,
): Promise<string> {
  const canonicalRoot = await realpath(workspaceRoot);
  const canonicalCandidate = await realpath(candidatePath);
  if (!isInside(canonicalRoot, canonicalCandidate)) {
    throw new Error("evidence path resolves outside the workspace");
  }
  return canonicalCandidate;
}

/** Prove that an existing workspace path is a non-symlink regular file. */
export async function verifyExistingRegularWorkspacePath(
  workspaceRoot: string,
  candidatePath: string,
): Promise<string> {
  const candidateStat = await lstat(candidatePath);
  if (candidateStat.isSymbolicLink() || !candidateStat.isFile()) {
    throw new Error("evidence path must identify a non-symlink regular file");
  }
  return await verifyExistingWorkspacePath(workspaceRoot, candidatePath);
}

/** Read one stable, bounded regular file descriptor and parse its UTF-8 JSON value. */
export async function readBoundedJson(
  workspaceRoot: string,
  candidatePath: string,
  maximumBytes: number,
): Promise<unknown> {
  return (await readBoundedJsonWithDigest(workspaceRoot, candidatePath, maximumBytes)).value;
}

/** Bounded JSON value paired with the SHA-256 identity of its exact UTF-8 bytes. */
export interface BoundedJsonWithDigest {
  readonly value: unknown;
  readonly contentSha256: string;
}

/** Read bounded JSON and retain the exact byte identity used for validation state. */
export async function readBoundedJsonWithDigest(
  workspaceRoot: string,
  candidatePath: string,
  maximumBytes: number,
): Promise<BoundedJsonWithDigest> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 67_108_864) {
    throw new Error("maximum evidence bytes must be an integer from 1 through 67108864");
  }
  const pathBefore = await lstat(candidatePath);
  if (pathBefore.isSymbolicLink()) {
    throw new Error("evidence path must not be a symbolic link");
  }
  const canonicalPath = await verifyExistingWorkspacePath(workspaceRoot, candidatePath);
  const handle = await open(canonicalPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile()) {
      throw new Error("evidence path must identify a regular file");
    }
    if (before.size > maximumBytes) {
      throw new Error(`evidence file exceeds the configured ${maximumBytes}-byte limit`);
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
      throw new Error("evidence file changed while it was being read");
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", {fatal: true}).decode(boundedContent);
    } catch {
      throw new Error("evidence file is not valid UTF-8");
    }
    try {
      return {
        value: JSON.parse(content) as unknown,
        contentSha256: createHash("sha256").update(boundedContent).digest("hex"),
      };
    } catch (error: unknown) {
      const detail = error instanceof Error ? error.message : "unknown JSON error";
      throw new Error(`evidence file is not valid JSON: ${detail}`);
    }
  } finally {
    await handle.close();
  }
}
