// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — genuine Node coverage metadata contracts

/**
 * Collect original V8 files from real maintained CLI and protocol-test processes.
 * Reject contradictory cached maps even when their enclosing file manifest is resealed.
 * @module
 */

import assert from "node:assert/strict";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { runCli } from "../../src/cli.js";
import {
  admitProfileFiles,
  editorInputs,
  sealProfileFiles,
} from "../../scripts/editor-profile-inputs.mjs";
import { nativeInputs, record } from "../../scripts/native-artifact-inputs.mjs";
import { stageEditorCoverage } from "../../scripts/editor-coverage.mjs";

void test("admits original unmapped CLI data and refuses contradictory resolved map metadata", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-metadata-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const producer = path.join(allocation, "producer");
  const raw = path.join(producer, "v8");
  await mkdir(raw, { recursive: true });
  const environment: NodeJS.ProcessEnv = { ...process.env, NODE_V8_COVERAGE: raw };
  delete environment["NODE_TEST_CONTEXT"];
  const artifact = path.join(allocation, "actual-native-artifact");
  const lintScript = path.join(editor, "node_modules/eslint/bin/eslint.js");
  const originFile = path.join(producer, "fixtures/source-origin.json");
  const invocations = [
    ["pack", [path.join(editor, "scripts/native-artifact.mjs"), "pack", artifact]],
    ["verify", [path.join(editor, "scripts/native-artifact.mjs"), "verify", artifact]],
    [
      "protocol",
      [
        "--test",
        "--test-concurrency=1",
        path.join(editor, "out/test/unit/workbenchProtocol.test.js"),
      ],
    ],
    [
      "lint-config",
      ["--preserve-symlinks-main", lintScript, "--print-config", "src/extension.ts"],
    ],
    [
      "artifact-copies",
      [
        "--test",
        "--test-concurrency=1",
        path.join(editor, "out/test/unit/nativeArtifact.test.js"),
      ],
    ],
  ] as const;
  for (const [name, args] of invocations) {
    const result = await runCli(process.execPath, [...args], {
      cwd: editor,
      environment,
      timeoutMilliseconds: 15_000,
    });
    if (name === "protocol" || name === "artifact-copies") {
      assert.match(result.stdout, /# fail 0/u);
      if (name === "artifact-copies") {
        const match = /^# native artifact source and original receipt retained at (.+)$/mu.exec(
          result.stdout,
        );
        assert.ok(match?.[1]);
        await mkdir(path.dirname(originFile));
        await cp(path.join(match[1], "source-origin.json"), originFile, {
          errorOnExist: true,
          force: false,
        });
      }
    } else if (name === "lint-config") {
      const rules = record(record(JSON.parse(result.stdout))["rules"]);
      assert.deepEqual(rules["@typescript-eslint/consistent-type-imports"], [2]);
      assert.deepEqual(rules["@typescript-eslint/explicit-function-return-type"], [2]);
    } else {
      const observed = record(JSON.parse(result.stdout));
      assert.equal(observed["mode"], name);
      assert.equal(observed["venue"], "local");
    }
    await writeFile(
      path.join(producer, name + ".actual-command.json"),
      JSON.stringify({ executable: process.execPath, args, result }) + "\n",
      { flag: "wx" },
    );
  }
  const inputs = await editorInputs(editor);
  const identity = { venue: "local", scope: "actual maintained CLI and protocol processes" };
  await writeFile(
    path.join(producer, "profile.json"),
    JSON.stringify({
      schema: 1,
      kind: "local-target",
      identity,
      profile: "actual-cli-and-protocol",
      editorUri: pathToFileURL(editor + path.sep).href,
      node: process.version,
      inputs,
      native: await nativeInputs(editor, editor),
    }) + "\n",
    { flag: "wx" },
  );
  await sealProfileFiles(producer);
  const originals = new Map<string, Buffer>();
  for (const name of await readdir(raw)) originals.set(name, await readFile(path.join(raw, name)));
  assert.ok(originals.size >= invocations.length);
  const records = [...originals].map(([name, bytes]) => ({
    name,
    value: record(JSON.parse(bytes.toString("utf8"))),
  }));
  assert.ok(records.some(({ value }) => value["source-map-cache"] === undefined));
  const protocolUrl = pathToFileURL(
    path.join(editor, "out/test/unit/workbenchProtocol.test.js"),
  ).href;
  const mapped = records.find(
    ({ value }) =>
      value["source-map-cache"] !== undefined &&
      Object.hasOwn(record(value["source-map-cache"]), protocolUrl),
  );
  assert.ok(mapped);
  const cached = record(record(mapped.value["source-map-cache"])[protocolUrl]);
  assert.ok(cached["data"] !== null && cached["data"] !== undefined);
  assert.equal(cached["url"], null, "actual supported Node resolves maps with a null URL");
  const union = path.join(allocation, "union");
  const admitted = await stageEditorCoverage(
    editor,
    [producer],
    identity,
    ["actual-cli-and-protocol"],
    union,
  );
  assert.equal(admitted.mappedProfiles, originals.size);
  const unownedUrl = pathToFileURL(lintScript).href;
  const unowned = records.find(
    ({ value }) =>
      Array.isArray(value["result"]) &&
      value["result"].some((row: unknown) => record(row)["url"] === unownedUrl),
  );
  assert.ok(unowned, "actual lint dependency must retain its original script URL");
  const originalRows = unowned.value["result"];
  assert.ok(Array.isArray(originalRows));
  const originalRow = originalRows.map(record).find((row) => row["url"] === unownedUrl);
  assert.ok(originalRow);
  const output = admitted.originals.find((entry) => entry["file"] === "v8/" + unowned.name);
  assert.ok(output && typeof output["derivative"] === "string");
  const derivative = record(
    JSON.parse(await readFile(path.join(union, output["derivative"]), "utf8")),
  );
  const derivedRows = derivative["result"];
  assert.ok(Array.isArray(derivedRows));
  assert.deepEqual(
    derivedRows.map(record).find((row) => row["url"] === unownedUrl),
    originalRow,
  );
  assert.ok(!inputs.owners.includes("node_modules/eslint/bin/eslint.js"));
  const contradictory = path.join(allocation, "contradictory");
  await cp(producer, contradictory, { recursive: true, errorOnExist: true, force: false });
  cached["url"] = "file:///contradictory-resolved-map.js.map";
  await writeFile(
    path.join(contradictory, "v8", mapped.name),
    JSON.stringify(mapped.value) + "\n",
  );
  await rm(path.join(contradictory, "files.json"));
  await sealProfileFiles(contradictory);
  await assert.rejects(
    stageEditorCoverage(
      editor,
      [contradictory],
      identity,
      ["actual-cli-and-protocol"],
      path.join(allocation, "refused"),
    ),
    /resolved Node source maps require a null cache URL/u,
  );
  const originBytes = await readFile(originFile);
  for (const defect of ["undeclared", "ambiguous"]) {
    const invalid = path.join(allocation, defect);
    await cp(producer, invalid, { recursive: true, errorOnExist: true, force: false });
    const origin = record(JSON.parse(originBytes.toString("utf8")));
    const copies = origin["copies"];
    assert.ok(Array.isArray(copies));
    const source = copies
      .map(record)
      .find((entry) => entry["source"] === "editors/vscode/scripts/native-artifact.mjs");
    assert.ok(source);
    const replacement =
      defect === "undeclared"
        ? "undeclared-source.json"
        : "editors/vscode/scripts/editor-coverage.mjs";
    copies.push({
      ...source,
      source: replacement,
      sha256: inputs.sources["editors/vscode/scripts/editor-coverage.mjs"],
    });
    await writeFile(
      path.join(invalid, "fixtures/source-origin.json"),
      JSON.stringify(origin) + "\n",
    );
    await rm(path.join(invalid, "files.json"));
    await sealProfileFiles(invalid);
    await assert.rejects(
      stageEditorCoverage(
        editor,
        [invalid],
        identity,
        ["actual-cli-and-protocol"],
        path.join(allocation, defect + "-refused"),
      ),
      defect === "undeclared" ? /copied editor source differs/u : /ambiguous copied source owner/u,
    );
  }
  await admitProfileFiles(producer);
  const incomplete = path.join(allocation, "incomplete-generated-host");
  await cp(producer, incomplete, { recursive: true, errorOnExist: true, force: false });
  const claimedHost = record(
    JSON.parse(await readFile(path.join(incomplete, "profile.json"), "utf8")),
  );
  claimedHost["kind"] = "supported-host";
  const generated = record(record(claimedHost["inputs"])["generated"]);
  assert.equal(typeof generated["out/test/unit/workbenchProtocol.test.js.map"], "string");
  Reflect.deleteProperty(generated, "out/test/unit/workbenchProtocol.test.js.map");
  await writeFile(path.join(incomplete, "profile.json"), JSON.stringify(claimedHost) + "\n");
  await rm(path.join(incomplete, "files.json"));
  await sealProfileFiles(incomplete);
  const missingOutput = path.join(allocation, "missing-generated-refused");
  await assert.rejects(
    stageEditorCoverage(
      editor,
      [incomplete],
      identity,
      ["actual-cli-and-protocol"],
      missingOutput,
    ),
    /supported editor profile requires every emitted file/u,
  );
  await assert.rejects(lstat(missingOutput), { code: "ENOENT" });
  for (const [name, bytes] of originals)
    assert.deepEqual(await readFile(path.join(raw, name)), bytes);
  const evidence = path.join(editor, "out/fixtures", path.basename(allocation));
  await mkdir(evidence, { recursive: true });
  await rename(producer, path.join(evidence, "original-producer"));
  await writeFile(path.join(evidence, "source-admission.json"), JSON.stringify(admitted) + "\n", {
    flag: "wx",
  });
  context.diagnostic("original CLI/protocol raw and source admission retained at " + evidence);
});
