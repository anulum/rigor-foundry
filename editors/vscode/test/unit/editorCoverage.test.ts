// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — source-exact genuine raw V8 transfer

/**
 * Execute the actual maintained protocol tests from byte-identical copied sources.
 * Admit their genuine local V8 files, relocate only proven source paths and enforce real c8 owner results.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { runCli } from "../../src/cli.js";
import { editorInputs, sealProfileFiles } from "../../scripts/editor-profile-inputs.mjs";
import { nativeInputs } from "../../scripts/native-artifact-inputs.mjs";
import {
  requireEditorOwnerCoverage,
  stageEditorCoverage,
} from "../../scripts/editor-coverage.mjs";

void test("transfers actual copied-source V8 and refuses missing or changed producer input", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-coverage-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const foreign = path.join(editor, "out/fixtures", path.basename(allocation), "copied-editor");
  context.after(async () => {
    await rm(foreign, { recursive: true, force: true });
  });
  const names = [
    "test/unit/workbenchProtocol.test.ts",
    "test/support/workbenchProtocol.ts",
    "out/test/unit/workbenchProtocol.test.js",
    "out/test/unit/workbenchProtocol.test.js.map",
    "out/test/support/workbenchProtocol.js",
    "out/test/support/workbenchProtocol.js.map",
  ];
  for (const name of names) {
    const target = path.join(foreign, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, await readFile(path.join(editor, name)), { flag: "wx" });
    assert.deepEqual(await readFile(target), await readFile(path.join(editor, name)));
  }
  const producer = path.join(allocation, "producer");
  const raw = path.join(producer, "v8");
  await mkdir(raw, { recursive: true });
  const executable = process.execPath;
  const args = [
    "--test",
    "--test-concurrency=1",
    path.join(foreign, "out/test/unit/workbenchProtocol.test.js"),
  ];
  const environment: NodeJS.ProcessEnv = { ...process.env, NODE_V8_COVERAGE: raw };
  delete environment["NODE_TEST_CONTEXT"];
  const result = await runCli(executable, args, {
    cwd: foreign,
    timeoutMilliseconds: 15_000,
    environment,
  });
  assert.match(result.stdout, /# fail 0/u);
  await writeFile(
    path.join(producer, "actual-command.json"),
    JSON.stringify({ executable, args, result }) + "\n",
    { flag: "wx" },
  );
  const inputs = await editorInputs(editor);
  const identity = { venue: "local", scope: "actual targeted protocol test process" };
  await writeFile(
    path.join(producer, "profile.json"),
    JSON.stringify(
      {
        schema: 1,
        kind: "local-target",
        identity,
        profile: "actual-local-protocol",
        editorUri: pathToFileURL(editor + path.sep).href,
        node: process.version,
        inputs,
        native: await nativeInputs(editor, editor),
      },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
  await mkdir(path.join(producer, "fixtures"), { recursive: true });
  await writeFile(
    path.join(producer, "fixtures/source-origin.json"),
    JSON.stringify(
      {
        schema: 1,
        copies: await Promise.all(
          names.map(async (name) => ({
            url: pathToFileURL(path.join(foreign, name)).href,
            source: "editors/vscode/" + name,
            sha256: createHash("sha256")
              .update(await readFile(path.join(foreign, name)))
              .digest("hex"),
          })),
        ),
      },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
  await sealProfileFiles(producer);
  const originals = new Map<string, Buffer>();
  for (const name of await readdir(raw)) originals.set(name, await readFile(path.join(raw, name)));
  assert.ok(originals.size > 0);
  const staged = path.join(allocation, "union");
  const admitted = await stageEditorCoverage(
    editor,
    [producer],
    identity,
    ["actual-local-protocol"],
    staged,
  );
  assert.equal(admitted.mappedProfiles, originals.size);
  assert.deepEqual(admitted.owners, inputs.owners);
  const entries = await readdir(staged);
  let seen = 0;
  for (const name of entries) {
    const data: unknown = JSON.parse(await readFile(path.join(staged, name), "utf8"));
    assert.ok(
      typeof data === "object" && data !== null && "result" in data && Array.isArray(data.result),
    );
    seen += data.result.filter(
      (value: unknown) =>
        typeof value === "object" &&
        value !== null &&
        "url" in value &&
        value.url ===
          pathToFileURL(path.join(editor, "out/test/unit/workbenchProtocol.test.js")).href,
    ).length;
  }
  assert.ok(seen > 0, "actual foreign maintained code must reach its exact current source URL");
  const config = JSON.parse(await readFile(path.join(editor, "c8.config.json"), "utf8")) as Record<
    string,
    unknown
  >;
  const owner = "test/unit/workbenchProtocol.test.ts";
  const report = path.join(allocation, "report");
  const configFile = path.join(allocation, "whole-one-owner.json");
  await writeFile(
    configFile,
    JSON.stringify({
      ...config,
      include: [owner],
      "temp-directory": staged,
      "reports-dir": report,
      reporter: ["json", "json-summary"],
      all: true,
    }) + "\n",
    { flag: "wx" },
  );
  const c8args = [
    path.join(editor, "node_modules/c8/bin/c8.js"),
    "report",
    "--config",
    configFile,
  ];
  await runCli(process.execPath, c8args, { cwd: editor, timeoutMilliseconds: 15_000 });
  await requireEditorOwnerCoverage(editor, path.join(report, "coverage-summary.json"), [owner]);
  await assert.rejects(
    requireEditorOwnerCoverage(editor, path.join(report, "coverage-summary.json"), inputs.owners),
    /owner denominator differs/u,
  );
  await assert.rejects(
    stageEditorCoverage(
      editor,
      [producer],
      identity,
      ["actual-local-protocol", "missing-required-role"],
      path.join(allocation, "missing"),
    ),
    /producer set/u,
  );
  await assert.rejects(
    stageEditorCoverage(
      editor,
      [producer],
      { ...identity, scope: "different actual context" },
      ["actual-local-protocol"],
      path.join(allocation, "wrong-context"),
    ),
    /AssertionError/u,
  );
  const altered = path.join(allocation, "altered");
  await cp(producer, altered, { recursive: true, errorOnExist: true, force: false });
  const originalName = [...originals.keys()][0];
  assert.ok(originalName);
  const bytes = originals.get(originalName);
  assert.ok(bytes);
  await writeFile(
    path.join(altered, "v8", originalName),
    Buffer.concat([bytes, Buffer.from("\n")]),
  );
  await assert.rejects(
    stageEditorCoverage(
      editor,
      [altered],
      identity,
      ["actual-local-protocol"],
      path.join(allocation, "changed"),
    ),
    /evidence file differs/u,
  );
  for (const [name, bytes] of originals) {
    assert.deepEqual(await readFile(path.join(raw, name)), bytes);
    context.diagnostic(
      name + " original sha256 " + createHash("sha256").update(bytes).digest("hex"),
    );
  }
  for (const name of names)
    assert.deepEqual(
      await readFile(path.join(foreign, name)),
      await readFile(path.join(editor, name)),
    );
  const evidence = path.join(editor, "out/fixtures", path.basename(allocation));
  await mkdir(evidence, { recursive: true });
  await cp(producer, path.join(evidence, "original-producer"), {
    recursive: true,
    errorOnExist: true,
    force: false,
  });
  await cp(report, path.join(evidence, "actual-owner-report"), {
    recursive: true,
    errorOnExist: true,
    force: false,
  });
  await writeFile(
    path.join(evidence, "source-admission.json"),
    JSON.stringify(admitted, null, 2) + "\n",
    { flag: "wx" },
  );
  context.diagnostic(
    "original targeted V8, source identity and actual owner report retained at " + evidence,
  );
});
