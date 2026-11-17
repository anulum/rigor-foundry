// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — shell-free process tests

/**
 * Exercise the public process runner with real child processes.
 * Check literal arguments, combined output limits, process creation failures, and timeout reaping.
 * @module
 */

import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import { EvidenceRefusal } from "../../src/contracts.js";

/**
 * Register and await real child-process cases while preserving the native test runner's verdicts.
 * @returns Completion after all process, output-bound, and deadline cases have settled.
 */
async function run(): Promise<void> {
  await test("passes metacharacters as literal arguments without a shell", async () => {
    const result = await runCli(
      process.execPath,
      ["-e", "process.stdout.write(process.argv[1])", "$(touch should-not-run)"],
      { cwd: process.cwd(), timeoutMilliseconds: 5000 },
    );
    assert.equal(result.stdout, "$(touch should-not-run)");
  });

  await test("rejects non-zero commands with bounded diagnostics", async () => {
    await assert.rejects(
      runCli(process.execPath, ["-e", "process.stderr.write('failure'); process.exit(7)"], {
        cwd: process.cwd(),
        timeoutMilliseconds: 5000,
      }),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.ok(error instanceof EvidenceRefusal);
        assert.ok(error.cause instanceof Error);
        assert.match(`${error.message}: ${error.cause.message}`, /exit code 7: failure/u);
        assert.doesNotMatch(error.message, /failure/u);
        assert.deepEqual(error.output, { stdout: "", stderr: "failure" });
        return true;
      },
    );
  });

  await test("captures both bounded output streams after a successful process closes", async () => {
    const result = await runCli(
      process.execPath,
      ["-e", "process.stdout.write('report');process.stderr.write('diagnostic')"],
      { cwd: process.cwd(), timeoutMilliseconds: 5000, maximumOutputBytes: 16 },
    );
    assert.deepEqual(result, { stdout: "report", stderr: "diagnostic" });
  });

  await test("passes a complete child environment without changing the parent", async () => {
    const parent = process.env["RIGOR_CHILD_FIXTURE"];
    const result = await runCli(process.execPath, ["-p", "process.env.RIGOR_CHILD_FIXTURE"], {
      cwd: process.cwd(),
      timeoutMilliseconds: 5000,
      environment: { ...process.env, RIGOR_CHILD_FIXTURE: "owned-child-context" },
    });
    assert.equal(result.stdout, "owned-child-context\n");
    assert.equal(process.env["RIGOR_CHILD_FIXTURE"], parent);
  });

  await test("rejects invalid executable names before process creation", async () => {
    for (const executable of ["", "bad\0executable"]) {
      await assert.rejects(
        runCli(executable, [], { cwd: process.cwd(), timeoutMilliseconds: 5000 }),
        /executable must be a non-empty string/u,
      );
    }
  });

  await test("rejects unsafe output and timer bounds rather than accepting Node coercion", async () => {
    for (const maximumOutputBytes of [
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      67_108_865,
    ]) {
      await assert.rejects(
        runCli(process.execPath, ["--version"], {
          cwd: process.cwd(),
          timeoutMilliseconds: 5000,
          maximumOutputBytes,
        }),
        /maximum CLI output bytes/u,
      );
    }
    for (const timeoutMilliseconds of [
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      2_147_483_648,
    ]) {
      await assert.rejects(
        runCli(process.execPath, ["--version"], { cwd: process.cwd(), timeoutMilliseconds }),
        /CLI timeout must be an integer/u,
      );
    }
  });

  await test("preserves a spawn failure as an undisplayed diagnostic cause", async () => {
    const missing = path.join(process.cwd(), "missing-rigor-executable");
    await assert.rejects(
      runCli(missing, [], { cwd: process.cwd(), timeoutMilliseconds: 5000 }),
      (error: unknown): boolean => {
        assert.ok(error instanceof EvidenceRefusal);
        assert.equal(error.message, "RigorFoundry CLI could not be started");
        assert.ok(error.cause instanceof Error);
        assert.match(error.cause.message, /ENOENT/u);
        assert.ok(!error.message.includes(missing));
        return true;
      },
    );
  });

  await test("enforces one combined stdout and stderr ceiling", async () => {
    await assert.rejects(
      runCli(
        process.execPath,
        ["-e", "process.stdout.write('12345');process.stderr.write('67890')"],
        {
          cwd: process.cwd(),
          timeoutMilliseconds: 5000,
          maximumOutputBytes: 9,
        },
      ),
      /CLI output exceeded 9 bytes/u,
    );
  });

  for (const order of ["stdout-first", "stderr-first"]) {
    await test("bounds queued output and reaps the writer: " + order, async (context) => {
      const root = await mkdtemp(path.join(tmpdir(), "rigor-cli-queued-"));
      context.after(async () => {
        await rm(root, { recursive: true, force: true });
      });
      const identity = path.join(root, "pid.txt");
      const program = [
        "require('node:fs').writeFileSync(process.argv[1],String(process.pid));",
        order === "stdout-first"
          ? "process.stdout.write('o'.repeat(8192));process.stderr.write('e'.repeat(8192));"
          : "process.stderr.write('e'.repeat(8192));process.stdout.write('o'.repeat(8192));",
        "setInterval(()=>{},1000);",
      ].join("\n");
      await assert.rejects(
        runCli(process.execPath, ["-e", program, identity], {
          cwd: root,
          timeoutMilliseconds: 5000,
          maximumOutputBytes: 1024,
        }),
        (error: unknown): boolean => {
          assert.ok(error instanceof CommandExecutionFailure);
          assert.equal(error.message, "RigorFoundry CLI output exceeded 1024 bytes");
          assert.ok(
            Buffer.byteLength(error.output.stdout) + Buffer.byteLength(error.output.stderr) <=
              1024,
          );
          return true;
        },
      );
      const pid = Number(await readFile(identity, "utf8"));
      assert.ok(Number.isSafeInteger(pid) && pid > 0);
      assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
    });
  }

  await test("refuses oversized output from a naturally exiting process", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-cli-exit-output-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const identity = path.join(root, "pid.txt");
    const environment = { ...process.env };
    delete environment["NODE_V8_COVERAGE"];
    await assert.rejects(
      runCli(
        process.execPath,
        [
          "-e",
          [
            "const fs=require('node:fs');",
            "fs.writeFileSync(process.argv[1],String(process.pid));",
            "fs.writeSync(1,'x'.repeat(8192));",
          ].join("\n"),
          identity,
        ],
        {
          cwd: root,
          timeoutMilliseconds: 5000,
          maximumOutputBytes: 1024,
          environment,
        },
      ),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.equal(error.message, "RigorFoundry CLI output exceeded 1024 bytes");
        assert.ok(
          Buffer.byteLength(error.output.stdout) + Buffer.byteLength(error.output.stderr) <= 1024,
        );
        return true;
      },
    );
    const pid = Number(await readFile(identity, "utf8"));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  });

  await test("waits for the timed-out process to be reaped before rejecting", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-cli-timeout-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const identity = path.join(root, "pid.txt");
    await assert.rejects(
      runCli(
        process.execPath,
        [
          "-e",
          "require('node:fs').writeFileSync(process.argv[1],String(process.pid));setInterval(()=>{},1000)",
          identity,
        ],
        { cwd: root, timeoutMilliseconds: 3000 },
      ),
      /CLI timed out after 3000 ms/u,
    );
    const pid = Number(await readFile(identity, "utf8"));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  });
}

void run();
