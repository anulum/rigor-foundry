// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — Linux process-group lifecycle contracts

/**
 * Exercise actual signal failure and late inherited-pipe output on Linux.
 * Generic child programs load no first-party code; the public parent stays instrumented.
 * @module
 */

import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

/**
 * Exercise complete public process lifecycles using real Linux process groups and pipes.
 * @returns Completion after both failures settle and their actual process evidence is checked.
 */
async function run(): Promise<void> {
  assert.equal(process.platform, "linux");
  await test("preserves private diagnostics when a command terminates by signal", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-cli-signal-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const identity = path.join(root, "pid.txt");
    const program = [
      "const fs=require('node:fs');",
      "fs.writeFileSync(process.argv[1],String(process.pid));",
      "fs.writeSync(2,'private signal diagnostic');",
      "process.kill(process.pid,'SIGTERM');",
    ].join("\n");
    await assert.rejects(
      runCli(process.execPath, ["-e", program, identity], {
        cwd: root,
        timeoutMilliseconds: 5000,
      }),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.equal(error.message, "RigorFoundry CLI failed with signal SIGTERM");
        assert.deepEqual(error.output, { stdout: "", stderr: "private signal diagnostic" });
        assert.ok(error.cause instanceof Error);
        assert.equal(error.cause.message, "private signal diagnostic");
        assert.doesNotMatch(error.message, /private signal diagnostic/u);
        return true;
      },
    );
    const pid = Number(await readFile(identity, "utf8"));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  });

  await test("refuses late pipe output after the original process group has exited", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-cli-leader-exit-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const identity = path.join(root, "leader.txt");
    const group = path.join(root, "group-disappeared");
    const completed = path.join(root, "writer-complete");
    const writerProgram = [
      "const fs=require('node:fs');",
      "const leader=Number(process.argv[1]);const deadline=Date.now()+3000;",
      "const timer=setInterval(()=>{",
      "let absent=false;",
      "try{process.kill(leader,0);}catch(error){if(error.code==='ESRCH')absent=true;else throw error;}",
      "if(!absent){if(Date.now()>deadline){clearInterval(timer);process.exitCode=8;}return;}",
      "clearInterval(timer);",
      "let groupAbsent=false;",
      "try{process.kill(-leader,0);}catch(error){if(error.code==='ESRCH')groupAbsent=true;else throw error;}",
      "if(!groupAbsent)throw new Error('original process group still exists');",
      "fs.writeFileSync(process.argv[2],'ok');",
      "fs.writeSync(1,'x'.repeat(8192));",
      "setTimeout(()=>{fs.writeSync(2,'y'.repeat(8192));fs.writeFileSync(process.argv[3],'ok');},100);",
      "},10);",
    ].join("\n");
    const leaderProgram = [
      "const fs=require('node:fs');const {spawn}=require('node:child_process');",
      "const child=spawn(process.execPath,['-e',process.argv[2],String(process.pid),process.argv[3],process.argv[4]],{detached:true,stdio:['ignore',1,2],env:process.env});",
      "fs.writeFileSync(process.argv[1],String(process.pid));child.unref();",
    ].join("\n");
    const environment = { ...process.env };
    delete environment["NODE_V8_COVERAGE"];
    await assert.rejects(
      runCli(process.execPath, ["-e", leaderProgram, identity, writerProgram, group, completed], {
        cwd: root,
        timeoutMilliseconds: 5000,
        maximumOutputBytes: 1024,
        environment,
      }),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.equal(error.message, "RigorFoundry CLI output exceeded 1024 bytes");
        assert.deepEqual(error.output, { stdout: "", stderr: "" });
        return true;
      },
    );
    assert.equal(await readFile(group, "utf8"), "ok");
    assert.equal(await readFile(completed, "utf8"), "ok");
    const pid = Number(await readFile(identity, "utf8"));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  });
}
run().catch((error: unknown): void => {
  process.stderr.write(`Linux process test registration failed: ${String(error)}\n`);
  process.exitCode = 1;
});
