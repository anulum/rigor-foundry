// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — generated editor output cleanup contract

/**
 * Run the unchanged cleanup entry point over actual copied source and generated output.
 * Preserve source, dependency bytes and an unrelated working directory on both invocations.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { runCli } from "../../src/cli.js";

void test("cleanup is rooted at its own script and preserves source and dependencies", async (context) => {
  const extensionRoot = path.resolve(__dirname, "../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-clean-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const editor = path.join(allocation, "editor");
  const output = path.join(editor, "out");
  const copiedScript = path.join(editor, "scripts", "clean.mjs");
  const keptSource = path.join(editor, "src", "contracts.ts");
  const keptDependency = path.join(editor, "node_modules", "koffi", "src", "koffi", "index.cjs");
  const unrelatedOutput = path.join(allocation, "out", "contracts.js");
  const originalScript = path.join(extensionRoot, "scripts", "clean.mjs");
  const sourceBytes = await readFile(path.join(extensionRoot, "src", "contracts.ts"));
  const dependencyBytes = await readFile(
    path.join(extensionRoot, "native", "koffi", "src", "koffi", "index.cjs"),
  );
  const generatedBytes = await readFile(path.join(extensionRoot, "out", "src", "contracts.js"));
  const scriptBytes = await readFile(originalScript);
  for (const file of [copiedScript, keptSource, keptDependency, unrelatedOutput])
    await mkdir(path.dirname(file), { recursive: true });
  await mkdir(path.join(output, "src"), { recursive: true });
  await writeFile(copiedScript, scriptBytes, { flag: "wx" });
  await writeFile(keptSource, sourceBytes, { flag: "wx" });
  await writeFile(keptDependency, dependencyBytes, { flag: "wx" });
  await writeFile(unrelatedOutput, generatedBytes, { flag: "wx" });
  await writeFile(path.join(output, "src", "contracts.js"), generatedBytes, { flag: "wx" });
  assert.deepEqual(await readFile(copiedScript), scriptBytes);
  for (const attempt of ["generated output exists", "generated output is already absent"]) {
    context.diagnostic(attempt);
    const result = await runCli(process.execPath, [copiedScript], {
      cwd: allocation,
      timeoutMilliseconds: 10_000,
    });
    assert.deepEqual(result, { stdout: "", stderr: "" });
    await assert.rejects(stat(output), { code: "ENOENT" });
    assert.deepEqual(await readFile(keptSource), sourceBytes);
    assert.deepEqual(await readFile(keptDependency), dependencyBytes);
    assert.deepEqual(await readFile(unrelatedOutput), generatedBytes);
    assert.deepEqual(await readFile(copiedScript), scriptBytes);
  }
  context.diagnostic(
    "cleanup source binding " +
      JSON.stringify({
        path: copiedScript,
        originalPath: originalScript,
        sourceSha256: createHash("sha256").update(scriptBytes).digest("hex"),
      }),
  );
});
