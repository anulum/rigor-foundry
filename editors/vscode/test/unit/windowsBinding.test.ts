// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native binding metadata staging and byte preservation

/**
 * Stage the actual packaged native image and vendor inputs through the public metadata command.
 * Verify package resolution, immutable compiler provenance and repeatable non-overwriting output.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

void test("stages a reproducible self-reference without replacing the native build", async () => {
  const source = path.resolve(__dirname, "../../..");
  const fixtures = path.join(source, "out", "fixtures");
  await mkdir(fixtures, { recursive: true });
  const allocation = await mkdtemp(path.join(fixtures, "rigor-native-binding-"));
  const root = path.join(allocation, "editor");
  const inputs = [
    "scripts/stage-windows-binding.mjs",
    "native/koffi-source.json.license",
    "native/koffi/provenance.json",
    "native/koffi/src/koffi/index.cjs",
    "native/koffi/src/koffi/src/static.cjs",
    "native/koffi/build/koffi/win32_x64/koffi.node",
  ];
  const original = new Map<string, Buffer>();
  for (const relative of inputs) {
    const bytes = await readFile(path.join(source, relative));
    original.set(relative, bytes);
    const destination = path.join(root, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, bytes, { flag: "wx" });
  }
  const command = path.join(root, "scripts/stage-windows-binding.mjs");
  const first = await runCli(process.execPath, [command], {
    cwd: root,
    timeoutMilliseconds: 10_000,
  });
  await writeFile(path.join(allocation, "first.stdout"), first.stdout, "utf8");
  await writeFile(path.join(allocation, "first.stderr"), first.stderr, "utf8");
  const native = path.join(root, "native/koffi");
  const files = [
    "package.json",
    "package.json.license",
    "binding-provenance.json",
    "binding-provenance.json.license",
  ];
  const staged = new Map<string, { bytes: Buffer; modified: bigint }>();
  for (const relative of files) {
    const filename = path.join(native, relative);
    staged.set(relative, {
      bytes: await readFile(filename),
      modified: (await stat(filename, { bigint: true })).mtimeNs,
    });
  }
  const loader = createRequire(path.join(native, "src/koffi/src/static.cjs"));
  assert.equal(
    loader.resolve("@koromix/koffi-win32-x64"),
    path.join(native, "build/koffi/win32_x64/koffi.node"),
  );
  const manifest: unknown = JSON.parse(await readFile(path.join(native, "package.json"), "utf8"));
  assert.deepEqual(manifest, {
    name: "@koromix/koffi-win32-x64",
    private: true,
    type: "commonjs",
    exports: { ".": "./build/koffi/win32_x64/koffi.node" },
  });
  const firstObservation: unknown = JSON.parse(first.stdout);
  assert.ok(typeof firstObservation === "object" && firstObservation !== null);
  assert.ok("stagedFiles" in firstObservation && firstObservation.stagedFiles === 4);
  assert.ok("nativeBuildProvenanceSha256" in firstObservation);
  assert.equal(
    firstObservation.nativeBuildProvenanceSha256,
    createHash("sha256")
      .update(await readFile(path.join(native, "provenance.json")))
      .digest("hex"),
  );
  const second = await runCli(process.execPath, [command], {
    cwd: root,
    timeoutMilliseconds: 10_000,
  });
  await writeFile(path.join(allocation, "second.stdout"), second.stdout, "utf8");
  await writeFile(path.join(allocation, "second.stderr"), second.stderr, "utf8");
  assert.deepEqual(JSON.parse(second.stdout) as unknown, { ...firstObservation, stagedFiles: 0 });
  for (const [relative, observed] of staged) {
    const filename = path.join(native, relative);
    assert.deepEqual(await readFile(filename), observed.bytes);
    assert.equal((await stat(filename, { bigint: true })).mtimeNs, observed.modified);
  }
  const packagePath = path.join(native, "package.json");
  const changed = (await readFile(packagePath, "utf8")) + "\n";
  await writeFile(packagePath, changed, "utf8");
  await assert.rejects(
    runCli(process.execPath, [command], { cwd: root, timeoutMilliseconds: 10_000 }),
    (error: unknown): boolean => {
      assert.ok(error instanceof CommandExecutionFailure);
      assert.match(error.output.stderr, /existing binding asset differs/);
      assert.equal(error.output.stdout, "");
      return true;
    },
  );
  assert.equal(await readFile(packagePath, "utf8"), changed);
  for (const [relative, bytes] of original) {
    assert.deepEqual(await readFile(path.join(root, relative)), bytes);
  }
  for (const [relative, observed] of staged) {
    if (relative === "package.json") continue;
    assert.deepEqual(await readFile(path.join(native, relative)), observed.bytes);
  }
  const script = original.get("scripts/stage-windows-binding.mjs");
  assert.ok(script);
  await writeFile(
    path.join(allocation, "source-origin.json"),
    JSON.stringify(
      {
        schema: 1,
        copies: [
          {
            url: pathToFileURL(command).href,
            source: "editors/vscode/scripts/stage-windows-binding.mjs",
            sha256: createHash("sha256").update(script).digest("hex"),
          },
        ],
      },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
});
