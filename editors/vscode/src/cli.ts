// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — shell-free CLI execution

import {spawn} from "node:child_process";

/** Captured output from one successful CLI invocation. */
export interface CommandResult {
  readonly stdout: string;
  readonly stderr: string;
}

/** Explicit bounds and working directory for a shell-free CLI invocation. */
export interface CommandOptions {
  readonly cwd: string;
  readonly timeoutMilliseconds: number;
  readonly maximumOutputBytes?: number;
}

/** Run the configured CLI without a shell, enforcing timeout and combined output bounds. */
export async function runCli(
  executable: string,
  args: readonly string[],
  options: CommandOptions,
): Promise<CommandResult> {
  if (executable.length === 0 || executable.includes("\0")) {
    throw new Error("RigorFoundry executable must be a non-empty string");
  }
  const maximumOutputBytes = options.maximumOutputBytes ?? 1_048_576;
  return await new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(executable, [...args], {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;

    const terminate = (): void => {
      if (child.pid === undefined) {
        return;
      }
      try {
        if (process.platform === "win32") {
          child.kill("SIGKILL");
        } else {
          process.kill(-child.pid, "SIGKILL");
        }
      } catch {
        child.kill("SIGKILL");
      }
    };

    const fail = (error: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      terminate();
      reject(error);
    };

    const collect = (chunks: Buffer[], chunk: Buffer): void => {
      outputBytes += chunk.length;
      if (outputBytes > maximumOutputBytes) {
        fail(new Error(`RigorFoundry CLI output exceeded ${maximumOutputBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    };

    child.stdout.on("data", (chunk: Buffer) => collect(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => collect(stderr, chunk));
    child.on("error", (error) => fail(error));
    child.on("close", (code, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      const result = {
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      if (code !== 0) {
        const suffix = signal === null ? `exit code ${String(code)}` : `signal ${signal}`;
        reject(new Error(`RigorFoundry CLI failed with ${suffix}: ${result.stderr.trim()}`));
        return;
      }
      resolve(result);
    });

    const timer = setTimeout(
      () => fail(new Error(`RigorFoundry CLI timed out after ${options.timeoutMilliseconds} ms`)),
      options.timeoutMilliseconds,
    );
    timer.unref();
  });
}
