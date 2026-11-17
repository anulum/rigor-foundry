// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — shell-free CLI execution

/**
 * Execute local programs without a shell under explicit output and time bounds.
 * Settle after process streams close and retain native failure details outside display-safe messages.
 * @module
 */

import { spawn } from "node:child_process";
import { EvidenceRefusal } from "./contracts.js";

/** Captured bounded output from one closed CLI invocation. */
export interface CommandResult {
  /** Exact UTF-8 decoding of the closed process's bounded standard output. */
  readonly stdout: string;
  /** Exact UTF-8 decoding of the closed process's bounded diagnostic output. */
  readonly stderr: string;
}

/** Process refusal paired with the bounded output captured before the child streams closed. */
export class CommandExecutionFailure extends EvidenceRefusal {
  /** Captured output prefix, limited by the invocation's combined byte ceiling. */
  public readonly output: CommandResult;

  /**
   * Preserve a safe explanation, bounded output, and the original diagnostic cause.
   * @param message - Authored explanation suitable for the command notification boundary.
   * @param output - Actual captured child streams, without exceeding the configured ceiling.
   * @param options - Original diagnostic cause retained for programmatic inspection.
   */
  public constructor(message: string, output: CommandResult, options?: ErrorOptions) {
    super(message, options);
    this.name = "CommandExecutionFailure";
    this.output = output;
  }
}

/** Explicit bounds and working directory for a shell-free CLI invocation. */
export interface CommandOptions {
  /** Existing working directory passed directly to the child process. */
  readonly cwd: string;
  /** Positive, safely representable Node timer delay in milliseconds. */
  readonly timeoutMilliseconds: number;
  /** Combined stdout/stderr byte ceiling; defaults to one mebibyte. */
  readonly maximumOutputBytes?: number;
  /** Complete child environment; omission inherits the calling process's environment. */
  readonly environment?: NodeJS.ProcessEnv;
}

/**
 * Run the CLI directly and wait for its streams to close before settling.
 * @param executable - Program name or path, without shell expansion.
 * @param args - Literal process arguments, including any caller-supplied paths.
 * @param options - Working directory, execution deadline, and combined byte ceiling.
 * @returns Captured output after a zero exit status and closed process streams.
 * @throws {EvidenceRefusal} For invalid bounds, process failure, timeout, or excess output.
 */
export async function runCli(
  executable: string,
  args: readonly string[],
  options: CommandOptions,
): Promise<CommandResult> {
  if (executable.length === 0 || executable.includes("\0")) {
    throw new EvidenceRefusal("RigorFoundry executable must be a non-empty string");
  }
  const maximumOutputBytes = options.maximumOutputBytes ?? 1_048_576;
  if (
    !Number.isSafeInteger(maximumOutputBytes) ||
    maximumOutputBytes < 1 ||
    maximumOutputBytes > 67_108_864
  ) {
    throw new EvidenceRefusal(
      "maximum CLI output bytes must be an integer from 1 through 67108864",
    );
  }
  if (
    !Number.isSafeInteger(options.timeoutMilliseconds) ||
    options.timeoutMilliseconds < 1 ||
    options.timeoutMilliseconds > 2_147_483_647
  ) {
    throw new EvidenceRefusal(
      "CLI timeout must be an integer from 1 through 2147483647 milliseconds",
    );
  }
  if (process.platform === "win32") {
    const { runNativeCli } = await import("./windowsEvidence.js");
    return await runNativeCli(executable, args, options);
  }
  return await new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(executable, [...args], {
      cwd: options.cwd,
      env: options.environment,
      shell: false,
      windowsHide: true,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let failure: EvidenceRefusal | undefined;

    const terminate = (): void => {
      if (child.pid === undefined) {
        return;
      }
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };

    const fail = (error: EvidenceRefusal): void => {
      if (failure !== undefined) {
        return;
      }
      failure = error;
      clearTimeout(timer);
      terminate();
    };

    const collect = (chunks: Buffer[], chunk: Buffer): void => {
      if (failure !== undefined) {
        return;
      }
      outputBytes += chunk.length;
      if (outputBytes > maximumOutputBytes) {
        fail(
          new EvidenceRefusal(
            `RigorFoundry CLI output exceeded ${String(maximumOutputBytes)} bytes`,
          ),
        );
        return;
      }
      chunks.push(chunk);
    };

    child.stdout.on("data", (chunk: Buffer) => {
      collect(stdout, chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      collect(stderr, chunk);
    });
    child.once("error", (error: Error) => {
      fail(new EvidenceRefusal("RigorFoundry CLI could not be started", { cause: error }));
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const result = {
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      if (failure !== undefined) {
        reject(new CommandExecutionFailure(failure.message, result, { cause: failure.cause }));
        return;
      }
      if (code !== 0) {
        const suffix = signal === null ? `exit code ${String(code)}` : `signal ${signal}`;
        reject(
          new CommandExecutionFailure(`RigorFoundry CLI failed with ${suffix}`, result, {
            cause: new Error(result.stderr.trim()),
          }),
        );
        return;
      }
      resolve(result);
    });

    const timer = setTimeout(() => {
      fail(
        new EvidenceRefusal(
          `RigorFoundry CLI timed out after ${String(options.timeoutMilliseconds)} ms`,
        ),
      );
    }, options.timeoutMilliseconds);
    timer.unref();
  });
}
