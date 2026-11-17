// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native process input completion and settlement

/**
 * Exercise finite binary stdin and actual early pipe closure through the public native runner.
 * Verify complete bytes or original write refusal, then actual process reaping and recovery.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

void test(
  "delivers finite binary stdin completely before reporting successful native settlement",
  { skip: process.platform !== "win32" },
  async (context) => {
    const { runWindowsCommand } = await import("../../src/windowsProcess.js");
    const root = await mkdtemp(path.join(tmpdir(), "rigor-native-input-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const output = path.join(root, "received.bin");
    const identity = path.join(root, "child.pid");
    const input = Buffer.alloc(1_048_577);
    for (let index = 0; index < input.length; index += 1) input[index] = index % 256;
    const digest = createHash("sha256").update(input).digest("hex");
    const program = [
      "const fs=require('node:fs');const crypto=require('node:crypto');const chunks=[];",
      "process.stdin.on('data',chunk=>chunks.push(chunk));",
      "process.stdin.on('end',()=>{const bytes=Buffer.concat(chunks);",
      "fs.writeFileSync(process.argv[1],bytes);fs.writeFileSync(process.argv[2],String(process.pid));",
      "process.stdout.write(crypto.createHash('sha256').update(bytes).digest('hex'));",
      "process.stderr.write(String(bytes.length));});",
    ].join("\n");
    const actual = await runWindowsCommand(process.execPath, ["-e", program, output, identity], {
      cwd: root,
      environment: { ...process.env },
      timeoutMilliseconds: 10_000,
      maximumOutputBytes: 8192,
      input,
    });
    assert.equal(actual.code, 0);
    assert.equal(actual.stdout.toString("utf8"), digest);
    assert.equal(actual.stderr.toString("utf8"), String(input.length));
    assert.deepEqual(await readFile(output), input);
    const pid = Number(await readFile(identity, "utf8"));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  },
);

void test(
  "preserves real early stdin closure failure and reaps the owned process before recovery",
  { skip: process.platform !== "win32" },
  async (context) => {
    const { runWindowsCommand, WindowsCommandFailure } =
      await import("../../src/windowsProcess.js");
    const root = await mkdtemp(path.join(tmpdir(), "rigor-native-closed-input-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const identity = path.join(root, "child.pid");
    const program = [
      "const fs=require('node:fs');",
      "fs.writeFileSync(process.argv[1],String(process.pid));",
      "fs.closeSync(0);process.exit(0);",
    ].join("\n");
    await assert.rejects(
      runWindowsCommand(process.execPath, ["-e", program, identity], {
        cwd: root,
        environment: { ...process.env },
        timeoutMilliseconds: 10_000,
        maximumOutputBytes: 8192,
        input: Buffer.alloc(1_048_577, 97),
      }),
      (error: unknown): boolean => {
        assert.ok(error instanceof WindowsCommandFailure);
        assert.equal(error.message, "native worker input was not written completely");
        assert.equal(error.settled, true);
        assert.ok(error.cause instanceof AggregateError);
        assert.equal(error.cause.errors.length, 1);
        const original: unknown = error.cause.errors[0];
        assert.ok(original instanceof Error);
        assert.equal(original.message, error.message);
        assert.ok(error.output.stdout.length + error.output.stderr.length <= 8192);
        return true;
      },
    );
    const pid = Number(await readFile(identity, "utf8"));
    assert.ok(Number.isSafeInteger(pid) && pid > 0);
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
    const recovered = await runWindowsCommand(process.execPath, ["-p", "'recovered'"], {
      cwd: root,
      environment: { ...process.env },
      timeoutMilliseconds: 10_000,
      maximumOutputBytes: 8192,
    });
    assert.equal(recovered.code, 0);
    assert.equal(recovered.stdout.toString("utf8"), "recovered\n");
    assert.equal(recovered.stderr.length, 0);
  },
);
