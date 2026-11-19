// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — owned native evidence worker

/**
 * Perform bounded disk I/O in a separately contained native worker process.
 * Hold private validation inputs until the controller acquires independent read guards.
 * @module
 */

import { readSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { inspect } from "node:util";
import { WindowsDirectory, bytesDigest, sameIdentity } from "./windowsResources.js";
import type { WindowsFile, NativeFileIdentity } from "./windowsResources.js";
import { runWindowsCommand, WindowsCommandFailure } from "./windowsProcess.js";
import type { WindowsCommandResult } from "./windowsProcess.js";
import {
  frame,
  integerField,
  identityRecord,
  maximumHeaderBytes,
  parseIdentity,
  record,
  textField,
} from "./windowsProtocol.js";
import type { WorkerFrame } from "./windowsProtocol.js";

/**
 * Read an exact finite stdin block; blocking is confined to this owned worker.
 * @param size - Required byte length within a previously checked finite bound.
 * @returns Exact requested bytes, or a refusal on EOF.
 */
function inputBytes(size: number): Buffer {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const read = readSync(0, bytes, offset, size - offset, null);
    if (read === 0) throw new Error("native worker input ended before its complete frame");
    offset += read;
  }
  return bytes;
}

/**
 * Read one bounded framed request without waiting for stdin EOF.
 * @returns Complete checked frame container.
 */
function inputFrame(): WorkerFrame {
  const length = inputBytes(4);
  const size = length.readUInt32LE(0);
  if (size < 2 || size > maximumHeaderBytes) throw new Error("native worker header is invalid");
  const encoded = inputBytes(size);
  const header = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded)));
  const payload = inputBytes(integerField(header["payloadBytes"], 134217728));
  return { header, payload };
}

/**
 * Flush one exact output frame before proceeding to a dependent worker phase.
 * @param bytes - Authored finite frame.
 * @returns Completion after Node has written the complete output buffer.
 */
async function outputFrame(bytes: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(bytes, (error: Error | null | undefined): void => {
      if (error !== null && error !== undefined) reject(error);
      else resolve();
    });
  });
}

/**
 * Compare only a directory's immutable object identity across child mutations.
 * @param actual - Metadata acquired through a real retained directory handle.
 * @param expected - Controller or earlier worker receipt.
 */
function sameObject(actual: NativeFileIdentity, expected: NativeFileIdentity): void {
  if (actual.volume !== expected.volume || actual.fileId !== expected.fileId)
    throw new Error("native worker directory object differs from its owner receipt");
}

/**
 * Read one workspace-contained source file through retained no-reparse parents.
 * @param header - Validated frame header container.
 * @returns Exact bounded source bytes.
 */
function readSource(header: Record<string, unknown>): Buffer {
  const root = textField(header["root"]);
  const candidate = textField(header["path"]);
  const relative = path.win32.relative(root, candidate);
  if (!relative || path.win32.isAbsolute(relative) || relative.split(/[\\/]/).includes(".."))
    throw new Error("native evidence path escapes its workspace");
  let directory = WindowsDirectory.open(root);
  let file: WindowsFile | undefined;
  try {
    const components = relative.split(/[\\/]/);
    const leaf = components.pop();
    if (leaf === undefined) throw new Error("native evidence path has no file component");
    for (const component of components) {
      const child = directory.child(component);
      directory.close();
      directory = child;
    }
    file = directory.file(leaf);
    return file.read(integerField(header["maximumBytes"]));
  } finally {
    try {
      file?.close();
    } finally {
      directory.close();
    }
  }
}

/**
 * Release every acquired handle, preserving independent failures in release order.
 * @param resources - Native resources ordered from child to parent.
 * @param failures - Prior operation failures followed by any release failures.
 */
function closeWorkerResources(
  resources: readonly (WindowsFile | WindowsDirectory | undefined)[],
  failures: unknown[],
): void {
  for (const resource of resources) {
    try {
      resource?.close();
    } catch (error: unknown) {
      failures.push(error);
    }
  }
}

/**
 * Prepare exact private files, transfer independent guards, then run the canonical CLI.
 * @param request - Finite byte pair and execution fields received from the controller.
 * @returns Completion after the actual inner CLI tree settles and guards release.
 */
async function validatePair(request: WorkerFrame): Promise<void> {
  const header = request.header;
  const reportLength = integerField(header["reportBytes"]);
  const reviewLength = integerField(header["reviewBytes"]);
  if (request.payload.length !== reportLength + reviewLength)
    throw new Error("native validation pair length differs from its header");
  const parent = WindowsDirectory.open(textField(header["temporaryParent"]));
  let directory: WindowsDirectory | undefined;
  const guards: WindowsFile[] = [];
  const failures: unknown[] = [];
  try {
    sameObject(parent.identity(), parseIdentity(header["parentIdentity"]));
    const name = `rigor-validation-${randomUUID()}`;
    directory = parent.child(name, true);
    const inputs = [
      ["report.json", request.payload.subarray(0, reportLength)],
      ["reviews.json", request.payload.subarray(reportLength)],
    ] as const;
    const receipts: Record<string, unknown>[] = [];
    for (const [leaf, bytes] of inputs) {
      const writer = directory.file(leaf, true);
      try {
        writer.write(bytes);
        writer.permissions("FR");
      } finally {
        writer.close();
      }
      const guard = directory.file(leaf);
      guards.push(guard);
      const actual = guard.read(bytes.length);
      if (!actual.equals(bytes))
        throw new Error("private validation input differs after read-guard acquisition");
      receipts.push({
        name: leaf,
        identity: identityRecord(guard.identity()),
        sha256: bytesDigest(actual),
      });
    }
    await outputFrame(
      frame({
        kind: "prepared",
        name,
        parent: identityRecord(parent.identity()),
        directory: identityRecord(directory.identity()),
        files: receipts,
      }),
    );
    const ack = inputFrame();
    if (ack.header["kind"] !== "ack" || ack.payload.length !== 0)
      throw new Error("native validation guard handoff was not acknowledged");
    const environment = Object.fromEntries(
      Object.entries(process.env).filter(([key]) => key.toUpperCase() !== "ELECTRON_RUN_AS_NODE"),
    );
    if (header["electronRunAsNode"] !== null)
      environment["ELECTRON_RUN_AS_NODE"] = textField(header["electronRunAsNode"]);
    let result: WindowsCommandResult;
    let executionFailure: { message: string; diagnostic: string; settled: boolean } | null = null;
    try {
      result = await runWindowsCommand(
        textField(header["executable"]),
        [
          "validate-review",
          "--report",
          directory.nativePath + "\\report.json",
          "--review",
          directory.nativePath + "\\reviews.json",
        ],
        {
          cwd: textField(header["cwd"]),
          timeoutMilliseconds: integerField(header["timeoutMilliseconds"], 2147483647),
          maximumOutputBytes: 1048576,
          environment,
        },
      );
    } catch (error: unknown) {
      result =
        error instanceof WindowsCommandFailure
          ? error.output
          : { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
      executionFailure = {
        settled: !(error instanceof WindowsCommandFailure) || error.settled,
        message:
          error instanceof WindowsCommandFailure
            ? error.message
            : "RigorFoundry CLI could not be started",
        diagnostic: (error instanceof Error ? error.message : "native CLI failure").slice(0, 8192),
      };
    }
    await outputFrame(
      frame(
        { kind: "result", code: result.code, stdoutBytes: result.stdout.length, executionFailure },
        Buffer.concat([result.stdout, result.stderr]),
      ),
    );
  } catch (error: unknown) {
    failures.push(error);
  } finally {
    closeWorkerResources([...guards.reverse(), directory, parent], failures);
  }
  if (failures.length > 0)
    throw new AggregateError(failures, "native worker operation or guard release failed");
}

/**
 * Remove only an exact owned private pair after the controller observed validation settlement.
 * @param header - Previously acquired object identities and expected exact content hashes.
 */
function cleanupPair(header: Record<string, unknown>): void {
  const parent = WindowsDirectory.open(textField(header["temporaryParent"]));
  const failures: unknown[] = [];
  try {
    sameObject(parent.identity(), parseIdentity(header["parentIdentity"]));
    const name = textField(header["name"]);
    if (!/^rigor-validation-[0-9a-f-]{36}$/.test(name))
      throw new Error("owned private directory name is invalid");
    const expectedDirectory = parseIdentity(header["directory"]);
    const directory = parent.child(name);
    const handles: WindowsFile[] = [];
    try {
      sameObject(directory.identity(), expectedDirectory);
      const files = header["files"];
      if (!Array.isArray(files) || files.length !== 2)
        throw new Error("owned validation pair receipt is incomplete");
      for (const [index, leaf] of ["report.json", "reviews.json"].entries()) {
        const receipt = record(files[index]);
        if (receipt["name"] !== leaf) throw new Error("owned validation file name differs");
        const file = directory.file(leaf, false, true);
        handles.push(file);
        if (
          !sameIdentity(file.identity(), parseIdentity(receipt["identity"])) ||
          bytesDigest(file.read(67108864)) !== receipt["sha256"]
        )
          throw new Error("owned validation input changed before cleanup");
      }
      for (const file of handles) file.discard();
    } catch (error: unknown) {
      failures.push(error);
    } finally {
      closeWorkerResources([...handles.reverse(), directory], failures);
    }
    if (failures.length === 0) parent.discardChild(name, expectedDirectory);
  } catch (error: unknown) {
    failures.push(error);
  } finally {
    closeWorkerResources([parent], failures);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, "native worker cleanup or guard release failed");
}

/**
 * Dispatch exactly one finite controller request on this owned worker's private stdin.
 * @returns Completion only after the requested real operation and output flush.
 */
async function main(): Promise<void> {
  // The write callback rejects the active operation; Node then emits the same stream error.
  process.stdout.once("error", (): void => {
    process.exitCode = 1;
  });
  const request = inputFrame();
  switch (request.header["kind"]) {
    case "read":
      if (request.payload.length !== 0)
        throw new Error("native read request must not carry payload");
      await outputFrame(frame({ kind: "read" }, readSource(request.header)));
      break;
    case "validate":
      await validatePair(request);
      break;
    case "cleanup":
      if (request.payload.length !== 0)
        throw new Error("native cleanup request must not carry payload");
      cleanupPair(request.header);
      await outputFrame(frame({ kind: "cleaned" }));
      break;
    default:
      throw new Error("native worker operation is unsupported");
  }
}

void main().catch((error: unknown): void => {
  const diagnostic =
    error instanceof Error
      ? inspect(error, { depth: 2, customInspect: false })
      : "native worker failed";
  const bounded = Buffer.from(diagnostic, "utf8").subarray(0, 8191);
  process.stderr.write(bounded);
  process.stderr.write("\n");
  process.exitCode = 1;
});
