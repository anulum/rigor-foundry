// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — owned Windows process trees

/**
 * Start explicit images suspended and retain their native job through observed settlement.
 * Poll only available pipe bytes; write finite worker input outside the editor event loop.
 * @module
 */

import { stat } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import * as abi from "./windowsAbi.js";
import {
  WindowsDirectory,
  WindowsResourceError,
  nativePath,
  requireHandle,
  requireInteger,
  requireRecord,
  sameIdentity,
} from "./windowsResources.js";

/** Raw bounded streams after the real leader and its owned descendants have settled. */
export interface WindowsCommandResult {
  /** Actual completed leader status. */
  readonly code: number;
  /** Exact bounded standard output. */
  readonly stdout: Buffer;
  /** Exact bounded diagnostic output. */
  readonly stderr: Buffer;
}

/** Explicit process budgets and optional finite binary worker input. */
export interface WindowsCommandOptions {
  /** Existing absolute child working directory. */
  readonly cwd: string;
  /** Positive operation deadline, separate from bounded failure cleanup. */
  readonly timeoutMilliseconds: number;
  /** Aggregate raw standard-output and diagnostic byte ceiling. */
  readonly maximumOutputBytes: number;
  /** Complete environment; undefined values remove variables. */
  readonly environment: NodeJS.ProcessEnv;
  /** Optional finite worker protocol, written once to the child's private stdin. */
  readonly input?: Buffer;
  /** Optional two-phase worker handoff; stdin stays open until its one bounded reply. */
  readonly conversation?: WindowsWorkerConversation;
}

/** One bounded reply after the controller has retained prepared private-input guards. */
export interface WindowsWorkerConversation {
  /** Inspect exact incremental stdout; queue the sole ACK only after validating PREPARED. */
  readonly onOutput: (chunk: Buffer, reply: (bytes: Buffer) => void) => void;
}

/** Refusal retaining bounded streams and whether the actual process group settled. */
export class WindowsCommandFailure extends Error {
  /** Actual bounded output observed before refusal. */
  public readonly output: WindowsCommandResult;
  /** Whether all owned child processes were observed terminated. */
  public readonly settled: boolean;
  /**
   * Preserve operation and cleanup diagnostics without inventing success.
   * @param message - Authored failure explanation.
   * @param output - Actual bounded process streams and leader status if known.
   * @param settled - Confirmed owned process-group settlement.
   * @param cause - Actual failure chain.
   */
  public constructor(
    message: string,
    output: WindowsCommandResult,
    settled: boolean,
    cause: unknown,
  ) {
    super(message, { cause });
    this.output = output;
    this.settled = settled;
  }
}

/**
 * Quote one literal Windows CRT argument, including quotes and trailing backslashes.
 * @param argument - Exact non-NUL argument.
 * @returns One fully quoted command-line argument without shell processing.
 */
function quoteArgument(argument: string): string {
  let output = '"';
  let slashes = 0;
  for (const character of argument) {
    if (character === "\\") {
      slashes += 1;
      continue;
    }
    output += "\\".repeat(character === '"' ? slashes * 2 + 1 : slashes) + character;
    slashes = 0;
  }
  return output + "\\".repeat(slashes * 2) + '"';
}

/**
 * Select an actual native executable using the caller's explicit environment.
 * @param executable - Absolute/relative executable path or PATH command name.
 * @param options - Exact caller environment and working directory.
 * @returns Explicit drive-absolute image path; resource guards still validate it.
 */
async function executablePath(
  executable: string,
  options: WindowsCommandOptions,
): Promise<string> {
  if (/^[A-Za-z]:[^\\/]/.test(executable))
    throw new Error("drive-relative executable paths are ambiguous");
  const direct = path.win32.isAbsolute(executable) || /[\\/]/.test(executable);
  const candidates = direct
    ? [path.win32.resolve(options.cwd, executable)]
    : (Object.entries(options.environment)
        .find(([key]) => key.toUpperCase() === "PATH")?.[1]
        ?.split(";")
        .filter((root) => path.win32.isAbsolute(root))
        .map((root) => path.win32.join(root, executable)) ?? []);
  let missing: Error | undefined;
  for (const candidate of candidates) {
    const image = path.win32.extname(candidate) === "" ? candidate + ".exe" : candidate;
    if (path.win32.extname(image).toLowerCase() !== ".exe")
      throw new Error("native Windows CLI requires a PE executable");
    try {
      if ((await stat(image)).isFile()) return image;
    } catch (error: unknown) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        !["ENOENT", "ENOTDIR"].includes(String(error.code))
      )
        throw error;
      missing = error;
    }
  }
  if (missing !== undefined) throw missing;
  throw new Error("configured native Windows executable was not found");
}

/**
 * Validate and encode the caller's exact case-insensitive Windows environment.
 * @param environment - Explicit complete caller environment.
 * @returns NUL-terminated UTF-16 environment block.
 */
function environmentBlock(environment: NodeJS.ProcessEnv): Buffer {
  const entries = Object.entries(environment).filter(
    (entry): entry is [string, string] => entry[1] !== undefined,
  );
  if (
    entries.some(([key, value]) => !key || key.includes("=") || (key + value).includes("\0")) ||
    new Set(entries.map(([key]) => key.toUpperCase())).size !== entries.length
  ) {
    throw new Error("native Windows environment names and values must be unambiguous");
  }
  entries.sort(([left], [right]) =>
    left.toUpperCase() < right.toUpperCase()
      ? -1
      : left.toUpperCase() > right.toUpperCase()
        ? 1
        : 0,
  );
  const block = Buffer.from(
    entries.map(([key, value]) => `${key}=${value}`).join("\0") + "\0\0",
    "utf16le",
  );
  if (block.length > 2097152)
    throw new Error("native Windows environment exceeds its finite bound");
  return block;
}

/** Retain rare pending native writes until their actual callbacks permit safe handle release. */
const pendingResourceReleases = new Set<Promise<void>>();

/**
 * Preserve unknown native callback failures as an Error with its actual cause.
 * @param value - Original native callback or operation failure.
 * @returns Intelligible error retaining the original diagnostic value.
 */
function nativeFailure(value: unknown): Error {
  return value instanceof Error
    ? value
    : new Error("native Windows operation failed", { cause: value });
}

/**
 * Run one real native image and contain all descendants before returning its output.
 * @param executable - Configured native executable or PATH command name.
 * @param args - Literal Windows CRT arguments, never a shell program.
 * @param options - Explicit working directory, environment, byte and time budgets.
 * @returns Actual status and exact bounded bytes after observed owned-job settlement.
 * @throws {WindowsCommandFailure} On operation or cleanup failure; unconfirmed jobs never succeed.
 */
export async function runWindowsCommand(
  executable: string,
  args: readonly string[],
  options: WindowsCommandOptions,
): Promise<WindowsCommandResult> {
  if (
    !executable ||
    [executable, options.cwd, ...args].some((value) => value.includes("\0")) ||
    !path.win32.isAbsolute(options.cwd) ||
    !Number.isSafeInteger(options.timeoutMilliseconds) ||
    options.timeoutMilliseconds < 1 ||
    options.timeoutMilliseconds > 2147483647 ||
    !Number.isSafeInteger(options.maximumOutputBytes) ||
    options.maximumOutputBytes < 1 ||
    options.maximumOutputBytes > 134283264 ||
    (options.input?.length ?? 0) > 134234112
  ) {
    throw new Error("native Windows command arguments and budgets must be explicit and finite");
  }
  const environment = environmentBlock(options.environment);
  const deadline = performance.now() + options.timeoutMilliseconds;
  const imagePath = await executablePath(executable, options);
  const parent = WindowsDirectory.open(path.win32.dirname(imagePath));
  let image: ReturnType<WindowsDirectory["file"]> | undefined;
  const handles: bigint[] = [];
  const streams: [Buffer[], Buffer[]] = [[], []];
  let total = 0;
  let code = 1;
  let job: bigint | undefined;
  let assigned = false;
  let processHandle: bigint | undefined;
  let thread: bigint | undefined;
  let attributes: Buffer | undefined;
  let attributesReady = false;
  let operationFailure: unknown;
  let failed = false;
  let settled = true;
  let inputWrite: Promise<void> | undefined;
  let inputFinished = true;
  /**
   * Read callback-owned write completion without assuming synchronous callback execution.
   * @returns Whether the actual native write callback has finished.
   */
  const inputIsComplete = (): boolean => inputFinished;
  let inputFailure: Error | undefined;
  const cleanupErrors: unknown[] = [];

  /**
   * Adopt only a real valid native handle.
   * @param value - Native acquisition result.
   * @returns Exact owned native handle.
   */
  const own = (value: unknown): bigint => {
    const handle = requireHandle(value);
    handles.push(handle);
    return handle;
  };
  /**
   * Release one owned reference only after confirmed native close success.
   * @param handle - Exact currently owned resource.
   */
  const release = (handle: bigint): void => {
    const index = handles.indexOf(handle);
    if (index < 0) throw new Error("native handle ownership was lost");
    if (abi.closeHandle(handle) === 0) throw new WindowsResourceError("handle close");
    handles.splice(index, 1);
  };
  /**
   * Allocate a pipe whose endpoints are initially noninheritable.
   * @returns Owned reader and writer handles.
   */
  const pipe = (): readonly [bigint, bigint] => {
    const reader: unknown[] = [null];
    const writer: unknown[] = [null];
    const security = Buffer.alloc(abi.koffi.sizeof(abi.nativeTypes.securityAttributes));
    abi.koffi.encode(security, abi.nativeTypes.securityAttributes, {
      length: security.length,
      descriptor: null,
      inherit: 0,
    });
    if (abi.createPipe(reader, writer, security, 65536) === 0)
      throw new WindowsResourceError("pipe creation");
    return [own(reader[0]), own(writer[0])];
  };
  /**
   * Attempt independent cleanup without losing earlier failure diagnostics.
   * @param action - Independent resource cleanup operation.
   */
  const cleanup = (action: () => void): void => {
    try {
      action();
    } catch (error: unknown) {
      cleanupErrors.push(error);
    }
  };
  /** Release remaining handles and image/parent guards after all native operations finish. */
  const releaseRemaining = (): void => {
    if (attributesReady && attributes !== undefined)
      cleanup(() => {
        if (attributes !== undefined) abi.deleteAttributes(attributes);
      });
    for (const handle of [...handles].reverse())
      cleanup(() => {
        release(handle);
      });
    cleanup(() => {
      image?.close();
    });
    cleanup(() => {
      parent.close();
    });
  };

  try {
    image = parent.file(path.win32.basename(imagePath));
    const originalImage = image.identity();
    if (originalImage.links !== 1)
      throw new Error("native executable must be a single-link regular file");
    const expectedImage = nativePath(image.handle, 2);
    const [stdinRead, stdinWrite] = pipe();
    const [stdoutRead, stdoutWrite] = pipe();
    const [stderrRead, stderrWrite] = pipe();
    job = own(abi.createJob(null, null));
    const limits = Buffer.alloc(abi.koffi.sizeof(abi.extendedLimitsType));
    abi.koffi.encode(limits, abi.extendedLimitsType, {
      basic: {
        processTime: 0,
        jobTime: 0,
        flags: 0x2200,
        minimumWorkingSet: 0,
        maximumWorkingSet: 0,
        activeProcesses: 0,
        affinity: 0,
        priority: 0,
        scheduling: 0,
      },
      ioCounters: [0, 0, 0, 0, 0, 0],
      processMemory: 0,
      jobMemory: 2147483648,
      peakProcessMemory: 0,
      peakJobMemory: 0,
    });
    if (abi.setJobInformation(job, 9, limits, limits.length) === 0)
      throw new WindowsResourceError("job limits");
    const size: unknown[] = [0];
    if (abi.initializeAttributes(null, 1, 0, size) !== 0 || abi.getLastError() !== 122)
      throw new Error("native process attribute size query failed");
    const attributeSize = requireInteger(size[0], 65536);
    if (attributeSize === 0) throw new Error("native process attribute size is empty");
    attributes = Buffer.alloc(attributeSize);
    if (abi.initializeAttributes(attributes, 1, 0, size) === 0)
      throw new WindowsResourceError("process attributes");
    attributesReady = true;
    const inherited = Buffer.alloc(24);
    for (const [index, handle] of [stdinRead, stdoutWrite, stderrWrite].entries()) {
      inherited.writeBigUInt64LE(handle, index * 8);
      if (abi.setHandleInformation(handle, 1, 1) === 0)
        throw new WindowsResourceError("child handle inheritance");
    }
    if (
      abi.updateAttributes(attributes, 0, 0x20002, inherited, inherited.length, null, null) === 0
    )
      throw new WindowsResourceError("explicit handle list");
    const startup = Buffer.alloc(abi.koffi.sizeof(abi.startupInfoExType));
    abi.koffi.encode(startup, abi.startupInfoExType, {
      startup: {
        cb: startup.length,
        reserved: null,
        desktop: null,
        title: null,
        x: 0,
        y: 0,
        xSize: 0,
        ySize: 0,
        xChars: 0,
        yChars: 0,
        fill: 0,
        flags: 0x100,
        show: 0,
        reservedBytes: 0,
        reservedData: null,
        stdin: stdinRead,
        stdout: stdoutWrite,
        stderr: stderrWrite,
      },
      attributes: abi.koffi.address(attributes),
    });
    const command = Buffer.from(
      [imagePath, ...args].map(quoteArgument).join(" ") + "\0",
      "utf16le",
    );
    if (command.length > 65534)
      throw new Error("native command line exceeds the Windows character bound");
    const info: abi.NativeProcessInfo = { process: null, thread: null, pid: 0, tid: 0 };
    if (
      abi.createProcess(
        imagePath,
        command,
        null,
        null,
        1,
        0x4 | 0x400 | 0x80000 | 0x8000000,
        environment,
        options.cwd,
        startup,
        info,
      ) === 0
    )
      throw new WindowsResourceError("suspended process creation");
    processHandle = own(info.process);
    thread = own(info.thread);
    settled = false;
    for (const handle of [stdinRead, stdoutWrite, stderrWrite])
      if (abi.setHandleInformation(handle, 1, 0) === 0)
        throw new WindowsResourceError("parent inheritance reset");
    if (abi.assignJob(job, processHandle) === 0)
      throw new WindowsResourceError("suspended process job assignment");
    assigned = true;
    const actualImage = Buffer.alloc(65536);
    const imageLength = [32768];
    if (abi.queryProcessImage(processHandle, 1, actualImage, imageLength) === 0)
      throw new WindowsResourceError("created native image query");
    const length = requireInteger(imageLength[0], 32767);
    if (length === 0 || actualImage.subarray(0, length * 2).toString("utf16le") !== expectedImage)
      throw new Error("created native image differs from the retained executable");
    if (abi.resumeThread(thread) !== 1)
      throw new Error("native primary thread did not have exactly one suspension");
    release(thread);
    thread = undefined;
    for (const handle of [stdinRead, stdoutWrite, stderrWrite]) release(handle);
    const input = options.input;
    const conversation = options.conversation;
    let replyQueued = false;
    if (conversation !== undefined && (input === undefined || input.length === 0)) {
      throw new Error("native worker conversation requires a finite initial request");
    }
    /**
     * Write one retained buffer outside the editor event loop.
     * @param bytes - Exact finite request or ACK bytes.
     * @param finish - Close stdin after this complete write.
     * @returns Completion only after the actual native callback.
     */
    const writeInput = (bytes: Buffer, finish: boolean): Promise<void> => {
      inputFinished = false;
      return new Promise<void>((resolve, reject) => {
        const count = [0];
        abi.writeFile.async(
          stdinWrite,
          bytes,
          bytes.length,
          count,
          null,
          (error: unknown, success: number): void => {
            try {
              if (error !== null && error !== undefined) throw nativeFailure(error);
              if (success === 0 || count[0] !== bytes.length)
                throw new Error("native worker input was not written completely");
              if (finish) release(stdinWrite);
              inputFinished = true;
              resolve();
            } catch (failure: unknown) {
              inputFinished = true;
              inputFailure = nativeFailure(failure);
              reject(inputFailure);
            }
          },
        );
      });
    };
    /**
     * Queue the single controller ACK after the initial write has actually completed.
     * @param bytes - Bounded ACK frame after prepared-input guard acquisition.
     */
    const reply = (bytes: Buffer): void => {
      if (conversation === undefined || replyQueued || bytes.length < 1 || bytes.length > 16384)
        throw new Error("native worker reply is absent, repeated or exceeds its bound");
      replyQueued = true;
      inputWrite = (inputWrite ?? Promise.resolve()).then(() => writeInput(bytes, true));
      void inputWrite.catch((error: unknown): void => {
        inputFinished = true;
        inputFailure = nativeFailure(error);
      });
    };
    if (input !== undefined && input.length > 0) {
      inputWrite = writeInput(input, conversation === undefined);
      // Retain the rejection for the operation loop and finalizer without an unhandled promise.
      void inputWrite.catch((error: unknown): void => {
        inputFinished = true;
        inputFailure = nativeFailure(error);
      });
    } else release(stdinWrite);
    const pipes = new Map<bigint, 0 | 1>([
      [stdoutRead, 0],
      [stderrRead, 1],
    ]);
    let leaderDone = false;
    while (pipes.size > 0 || !leaderDone || !inputIsComplete()) {
      if (performance.now() >= deadline)
        throw new Error(
          `RigorFoundry CLI timed out after ${String(options.timeoutMilliseconds)} ms`,
        );
      if (inputFailure !== undefined) throw inputFailure;
      const state = abi.waitForObject(processHandle, 0);
      if (state === 0 && !leaderDone) {
        leaderDone = true;
        const actualCode = [0];
        if (abi.getExitCode(processHandle, actualCode) === 0)
          throw new WindowsResourceError("process exit status");
        code = requireInteger(actualCode[0]);
        if (abi.terminateJob(job, 1) === 0)
          throw new WindowsResourceError("remaining descendant termination");
      } else if (state !== 0 && state !== 258) throw new WindowsResourceError("process wait");
      let progress = false;
      for (const [reader, index] of pipes) {
        const available = [0];
        if (abi.peekPipe(reader, null, 0, null, available, null) === 0) {
          if (abi.getLastError() === 109) {
            pipes.delete(reader);
            continue;
          }
          throw new WindowsResourceError("output availability");
        }
        const ready = requireInteger(available[0]);
        if (ready === 0) continue;
        const block = Buffer.alloc(Math.min(65536, ready, options.maximumOutputBytes - total + 1));
        const count = [0];
        if (abi.readFile(reader, block, block.length, count, null) === 0)
          throw new WindowsResourceError("available output read");
        const read = requireInteger(count[0], block.length);
        if (read === 0) throw new Error("native pipe reported bytes without read progress");
        if (total + read > options.maximumOutputBytes)
          throw new Error(
            `RigorFoundry CLI output exceeded ${String(options.maximumOutputBytes)} bytes`,
          );
        const chunk = block.subarray(0, read);
        streams[index].push(chunk);
        if (index === 0) conversation?.onOutput(chunk, reply);
        total += read;
        progress = true;
      }
      if (!progress || pipes.size > 0)
        await delay(Math.min(progress ? 0 : 5, Math.max(0, deadline - performance.now())));
    }
    if (inputFailure !== undefined) throw inputFailure;
    if (!sameIdentity(originalImage, image.identity()))
      throw new Error("native executable identity changed during execution");
    parent.identity();
  } catch (error: unknown) {
    failed = true;
    operationFailure = error;
  } finally {
    try {
      let jobTerminationRequested = job === undefined;
      if (job !== undefined)
        cleanup(() => {
          if (job !== undefined && abi.terminateJob(job, 1) === 0)
            throw new WindowsResourceError("owned job termination");
          jobTerminationRequested = true;
        });
      if (processHandle !== undefined) {
        const leader = processHandle;
        if ((!assigned || !jobTerminationRequested) && abi.waitForObject(leader, 0) !== 0)
          cleanup(() => {
            if (abi.terminateProcess(leader, 1) === 0)
              throw new WindowsResourceError("unassigned leader termination");
          });
        const limit = performance.now() + 2000;
        while (abi.waitForObject(leader, 0) === 258 && performance.now() < limit) await delay(5);
        settled = abi.waitForObject(leader, 0) === 0;
        if (!settled) cleanupErrors.push(new Error("native leader termination is unconfirmed"));
      }
      for (const handle of [thread, processHandle])
        if (handle !== undefined)
          cleanup(() => {
            release(handle);
          });
      if (job !== undefined) {
        const ownedJob = job;
        const limit = performance.now() + 2000;
        let empty = false;
        while (performance.now() < limit) {
          const accounting = Buffer.alloc(abi.koffi.sizeof(abi.nativeTypes.jobAccounting));
          if (abi.queryJobInformation(ownedJob, 1, accounting, accounting.length, null) === 0) {
            cleanupErrors.push(new WindowsResourceError("job settlement query"));
            break;
          }
          const data = requireRecord(abi.koffi.decode(accounting, abi.nativeTypes.jobAccounting));
          if (requireInteger(data["activeProcesses"]) === 0) {
            empty = true;
            break;
          }
          if (performance.now() >= limit) break;
          await delay(5);
        }
        settled = settled && empty;
        if (!empty) cleanupErrors.push(new Error("owned native job settlement is unconfirmed"));
      }
      if (inputWrite !== undefined && !inputIsComplete()) {
        const completion = inputWrite.then(
          () => true,
          () => true,
        );
        await Promise.race([completion, delay(2000)]);
      }
    } catch (error: unknown) {
      cleanupErrors.push(error);
      settled = false;
    } finally {
      if (inputIsComplete()) releaseRemaining();
      else if (inputWrite !== undefined) {
        cleanupErrors.push(
          new Error("native input write completion is unconfirmed; resources retained"),
        );
        const deferred = inputWrite
          .catch((): undefined => undefined)
          .then((): void => {
            releaseRemaining();
            pendingResourceReleases.delete(deferred);
          });
        pendingResourceReleases.add(deferred);
      }
    }
  }
  const output = { code, stdout: Buffer.concat(streams[0]), stderr: Buffer.concat(streams[1]) };
  if (failed || cleanupErrors.length > 0) {
    const reason =
      operationFailure instanceof Error
        ? operationFailure.message
        : "native Windows command cleanup failed";
    throw new WindowsCommandFailure(
      reason,
      output,
      settled,
      new AggregateError(
        [...(failed ? [operationFailure] : []), ...cleanupErrors],
        "native operation and cleanup failures",
      ),
    );
  }
  return output;
}
