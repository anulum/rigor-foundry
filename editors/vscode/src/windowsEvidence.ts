// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native editor evidence ownership

/**
 * Retain independent controller guards while contained workers perform finite disk operations.
 * Validate exact private byte pairs through the configured CLI and observe whole-job settlement.
 * @module
 */

import path from "node:path";
import { tmpdir } from "node:os";
import { realpath } from "node:fs/promises";
import { CommandExecutionFailure } from "./cli.js";
import type { CommandOptions, CommandResult } from "./cli.js";
import { runWindowsCommand, WindowsCommandFailure } from "./windowsProcess.js";
import type { WindowsWorkerConversation } from "./windowsProcess.js";
import { WindowsDirectory, bytesDigest, sameIdentity } from "./windowsResources.js";
import type { WindowsFile } from "./windowsResources.js";
import {
  frame,
  integerField,
  identityRecord,
  parseFrame,
  parseIdentity,
  record,
  textField,
} from "./windowsProtocol.js";
import type { WorkerFrame } from "./windowsProtocol.js";

/** Native resources retained when process settlement or exact owned cleanup is unconfirmed. */
interface RetainedPair {
  /** Held temporary parent chain. */
  readonly parent: WindowsDirectory;
  /** Private directory independently retained before acknowledging the worker. */
  directory: WindowsDirectory | undefined;
  /** Actual independently acquired file guards. */
  readonly files: WindowsFile[];
}

/** Keep live guards reachable after refusing unconfirmed settlement or cleanup. */
const retainedPairs = new Set<RetainedPair>();

/**
 * Capture the caller's original Electron helper switch without case ambiguity.
 * @returns Exact original value or null for absence.
 */
function originalElectronSwitch(): string | null {
  const entries = Object.entries(process.env).filter(
    ([key]) => key.toUpperCase() === "ELECTRON_RUN_AS_NODE",
  );
  if (entries.length > 1) throw new Error("Electron helper environment is ambiguous");
  return entries[0]?.[1] ?? null;
}

/**
 * Launch the owned worker under the current actual Node or Electron image.
 * @param input - Exact finite framed request.
 * @param cwd - Existing absolute working directory.
 * @param timeoutMilliseconds - Operation deadline before separate bounded native cleanup.
 * @param maximumOutputBytes - Aggregate actual worker-output ceiling.
 * @param conversation - Optional controller guard-handoff callback.
 * @returns Actual worker bytes after observed process-tree settlement.
 */
async function worker(
  input: Buffer,
  cwd: string,
  timeoutMilliseconds: number,
  maximumOutputBytes: number,
  conversation?: WindowsWorkerConversation,
): Promise<Buffer> {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.toUpperCase() !== "ELECTRON_RUN_AS_NODE"),
  );
  environment["ELECTRON_RUN_AS_NODE"] = "1";
  const result = await runWindowsCommand(
    process.execPath,
    [path.join(__dirname, "windowsWorker.js")],
    {
      cwd,
      timeoutMilliseconds,
      maximumOutputBytes,
      environment,
      input,
      ...(conversation === undefined ? {} : { conversation }),
    },
  );
  if (result.code !== 0)
    throw new Error("native evidence worker refused its operation", { cause: result });
  if (result.stderr.length !== 0)
    throw new Error("native evidence worker returned unexpected diagnostics", { cause: result });
  return result.stdout;
}

/**
 * Require exactly one complete output frame with the expected operation kind.
 * @param bytes - Actual bounded worker output.
 * @param kind - Expected authored response kind.
 * @returns Complete checked frame.
 */
function response(bytes: Buffer, kind: string): WorkerFrame {
  const parsed = parseFrame(bytes);
  if (parsed?.consumed !== bytes.length || parsed.value.header["kind"] !== kind)
    throw new Error("native worker response is incomplete or has unexpected trailing bytes");
  return parsed.value;
}

/**
 * Read exact bounded workspace bytes outside the editor's event loop.
 * @param root - Canonical owning workspace directory.
 * @param file - Existing workspace-contained file.
 * @param maximumBytes - Positive evidence ceiling checked by the public caller.
 * @returns Exact stable source bytes from real retained no-reparse native handles.
 */
export async function readWindowsEvidence(
  root: string,
  file: string,
  maximumBytes: number,
): Promise<Buffer> {
  const bytes = await worker(
    frame({ kind: "read", root, path: file, maximumBytes }),
    root,
    30000,
    maximumBytes + 16388,
  );
  const result = response(bytes, "read");
  if (result.payload.length > maximumBytes)
    throw new Error("native evidence worker exceeded the requested byte ceiling");
  return result.payload;
}

/**
 * Run one configured native CLI directly with whole-job settlement and bounded streams.
 * @param executable - Literal configured executable or command name.
 * @param args - Literal arguments without shell expansion.
 * @param options - Public command budgets and environment.
 * @returns Exact UTF-8 decoding of the actual completed process streams.
 */
export async function runNativeCli(
  executable: string,
  args: readonly string[],
  options: CommandOptions,
): Promise<CommandResult> {
  try {
    const result = await runWindowsCommand(executable, args, {
      cwd: options.cwd,
      timeoutMilliseconds: options.timeoutMilliseconds,
      maximumOutputBytes: options.maximumOutputBytes ?? 1048576,
      environment: options.environment ?? process.env,
    });
    const output = {
      stdout: result.stdout.toString("utf8"),
      stderr: result.stderr.toString("utf8"),
    };
    if (result.code !== 0)
      throw new CommandExecutionFailure(
        `RigorFoundry CLI failed with exit code ${String(result.code)}`,
        output,
        { cause: new Error(output.stderr.trim()) },
      );
    return output;
  } catch (error: unknown) {
    if (error instanceof CommandExecutionFailure) throw error;
    const output =
      error instanceof WindowsCommandFailure
        ? {
            stdout: error.output.stdout.toString("utf8"),
            stderr: error.output.stderr.toString("utf8"),
          }
        : { stdout: "", stderr: "" };
    throw new CommandExecutionFailure(
      error instanceof WindowsCommandFailure
        ? error.message
        : "RigorFoundry CLI could not be started",
      output,
      { cause: error },
    );
  }
}

/**
 * Validate a private exact byte pair while controller guards outlive every owned CLI descendant.
 * @param executable - Configured canonical CLI; no inferred Python interpreter is substituted.
 * @param root - Owning workspace passed as the actual CLI working directory.
 * @param report - Exact originally selected report bytes.
 * @param reviews - Exact originally selected review-ledger bytes.
 * @param timeoutMilliseconds - Finite CLI operation deadline.
 * @returns Actual canonical CLI output after settlement and exact owned cleanup.
 */
export async function validateWindowsPair(
  executable: string,
  root: string,
  report: Buffer,
  reviews: Buffer,
  timeoutMilliseconds: number,
): Promise<CommandResult> {
  const temporaryParent = await realpath(tmpdir());
  const owner: RetainedPair = {
    parent: WindowsDirectory.open(temporaryParent),
    directory: undefined,
    files: [],
  };
  const parentIdentity = owner.parent.identity();
  let prepared: WorkerFrame | undefined;
  let prefix = Buffer.alloc(0);
  let consumed = 0;
  let output: Buffer | undefined;
  let failure: unknown;
  let failed = false;
  let settled = true;
  let nativeResult: WorkerFrame | undefined;
  try {
    output = await worker(
      frame(
        {
          kind: "validate",
          temporaryParent,
          parentIdentity: identityRecord(parentIdentity),
          executable,
          cwd: root,
          reportBytes: report.length,
          reviewBytes: reviews.length,
          timeoutMilliseconds,
          electronRunAsNode: originalElectronSwitch(),
        },
        Buffer.concat([report, reviews]),
      ),
      root,
      timeoutMilliseconds + 30000,
      1081352,
      {
        onOutput: (chunk, reply): void => {
          if (prepared !== undefined) return;
          prefix = Buffer.concat([prefix, chunk]);
          if (prefix.length > 32776)
            throw new Error("native prepared-input receipt exceeded its bound");
          const parsed = parseFrame(prefix);
          if (parsed === undefined) return;
          const receipt = parsed.value;
          if (receipt.header["kind"] !== "prepared" || receipt.payload.length !== 0)
            throw new Error("native worker did not prepare an exact private pair");
          const parent = parseIdentity(receipt.header["parent"]);
          if (parent.volume !== parentIdentity.volume || parent.fileId !== parentIdentity.fileId)
            throw new Error("native prepared parent differs from the controller guard");
          const name = textField(receipt.header["name"]);
          if (!/^rigor-validation-[0-9a-f-]{36}$/.test(name))
            throw new Error("native private directory receipt name is invalid");
          owner.directory = owner.parent.child(name);
          const directory = parseIdentity(receipt.header["directory"]);
          const actual = owner.directory.identity();
          if (directory.volume !== actual.volume || directory.fileId !== actual.fileId)
            throw new Error("native private directory differs from its worker guard");
          const files = receipt.header["files"];
          if (!Array.isArray(files) || files.length !== 2)
            throw new Error("native private pair receipt is incomplete");
          for (const [index, name] of ["report.json", "reviews.json"].entries()) {
            const fileReceipt = record(files[index]);
            const expectedBytes = index === 0 ? report : reviews;
            const expected = parseIdentity(fileReceipt["identity"]);
            if (
              fileReceipt["name"] !== name ||
              fileReceipt["sha256"] !== bytesDigest(expectedBytes) ||
              expected.size !== BigInt(expectedBytes.length) ||
              expected.links !== 1
            )
              throw new Error(
                "native private input receipt differs from the selected exact bytes",
              );
            const file = owner.directory.file(name, false, false, true);
            owner.files.push(file);
            if (!sameIdentity(file.identity(), expected))
              throw new Error("controller private input guard differs from the worker guard");
          }
          prepared = receipt;
          consumed = parsed.consumed;
          reply(frame({ kind: "ack" }));
        },
      },
    );
  } catch (error: unknown) {
    failure = error;
    failed = true;
    settled = !(error instanceof WindowsCommandFailure) || error.settled;
  }
  if (!failed) {
    try {
      if (output === undefined || prepared === undefined)
        throw new Error("native validation returned no complete prepared pair");
      nativeResult = response(output.subarray(consumed), "result");
      if (nativeResult.header["executionFailure"] !== null) {
        const innerFailure = record(nativeResult.header["executionFailure"]);
        if (typeof innerFailure["settled"] !== "boolean")
          throw new Error("native CLI settlement receipt is absent");
        if (!innerFailure["settled"]) {
          settled = false;
          throw new Error("inner native CLI settlement was not confirmed");
        }
      }
    } catch (error: unknown) {
      failed = true;
      failure = error;
    }
  }
  if (!settled) {
    retainedPairs.add(owner);
    throw new Error(
      "native validation settlement is unconfirmed; independent input guards retained",
      { cause: failure },
    );
  }
  try {
    for (const file of owner.files) file.permissions("FA");
    for (const file of owner.files) file.close();
    owner.directory?.close();
    owner.directory = undefined;
    if (prepared !== undefined) {
      const cleanup = await worker(
        frame({
          ...prepared.header,
          kind: "cleanup",
          temporaryParent,
          parentIdentity: identityRecord(parentIdentity),
        }),
        root,
        30000,
        32776,
      );
      response(cleanup, "cleaned");
    } else if (failed)
      throw new Error(
        "private input preparation failed before complete ownership receipt; partial objects retained",
        { cause: failure },
      );
    owner.parent.close();
  } catch (error: unknown) {
    retainedPairs.add(owner);
    throw new AggregateError(
      [...(failed ? [failure] : []), error],
      "native validation cleanup was not confirmed; owned resources retained",
      { cause: error },
    );
  }
  if (failed) throw failure;
  if (nativeResult === undefined) throw new Error("native validation returned no complete result");
  const result = nativeResult;
  const stdoutBytes = integerField(result.header["stdoutBytes"], 1048576);
  if (stdoutBytes > result.payload.length)
    throw new Error("native CLI stream receipt length is invalid");
  const decoded = {
    stdout: result.payload.subarray(0, stdoutBytes).toString("utf8"),
    stderr: result.payload.subarray(stdoutBytes).toString("utf8"),
  };
  const code = integerField(result.header["code"], 0xffffffff);
  if (result.header["executionFailure"] !== null) {
    const executionFailure = record(result.header["executionFailure"]);
    throw new CommandExecutionFailure(textField(executionFailure["message"]), decoded, {
      cause: new Error(textField(executionFailure["diagnostic"])),
    });
  }
  if (code !== 0)
    throw new CommandExecutionFailure(
      `RigorFoundry CLI failed with exit code ${String(code)}`,
      decoded,
      { cause: new Error(decoded.stderr.trim()) },
    );
  return decoded;
}
