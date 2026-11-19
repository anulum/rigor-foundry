// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native evidence worker output settlement

/**
 * Exercise real worker stdout closure while preserving the failure and native read recovery.
 * @module
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { frame } from "../../src/windowsProtocol.js";

void test(
  "reports an actual disconnected result pipe through the worker failure handler",
  { skip: process.platform !== "win32", timeout: 30_000 },
  async () => {
    const { readWindowsEvidence } = await import("../../src/windowsEvidence.js");
    const editor = await realpath(path.resolve(__dirname, "../../.."));
    const source = path.join(editor, "package.json");
    const bytes = await readFile(source);
    const request = frame({
      kind: "read",
      root: editor,
      path: source,
      maximumBytes: bytes.length,
    });
    const child = spawn(process.execPath, [path.join(editor, "out/src/windowsWorker.js")], {
      cwd: editor,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 15_000,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
    });
    const completed = once(child, "close");
    const chunks: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer): void => {
      chunks.push(chunk);
    });
    const outputClosed = once(child.stdout, "close");
    child.stdout.destroy();
    await outputClosed;
    await new Promise<void>((resolve, reject) => {
      child.stdin.on("error", reject);
      child.stdin.end(request, resolve);
    });
    assert.deepEqual(await completed, [1, null]);
    assert.equal(child.exitCode, 1);
    const diagnostic = Buffer.concat(chunks);
    assert.ok(diagnostic.length <= 8192);
    assert.match(diagnostic.toString("utf8"), /EPIPE: broken pipe, write/u);
    assert.doesNotMatch(diagnostic.toString("utf8"), /Unhandled 'error' event/u);
    assert.deepEqual(await readWindowsEvidence(editor, source, bytes.length), bytes);
  },
);
