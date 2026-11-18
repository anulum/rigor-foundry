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
import { fileURLToPath, pathToFileURL } from "node:url";
import { runCli } from "../../src/cli.js";
import {
  admitProfileFiles,
  editorInputs,
  sealProfileFiles,
} from "../../scripts/editor-profile-inputs.mjs";
import { nativeInputs, record } from "../../scripts/native-artifact-inputs.mjs";
import { relocateEditorV8, stageEditorCoverage } from "../../scripts/editor-coverage.mjs";

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
  const producerRoot = "file:///D:/editor/";
  const capturedRoot = "file:///d:/editor/";
  const relativeTest = "out/test/unit/workbenchProtocol.test.js";
  const capturedUrl = new URL(relativeTest, capturedRoot).href;
  const declaredUrl = new URL(relativeTest, producerRoot).href;
  const actualRows = mapped.value["result"];
  assert.ok(Array.isArray(actualRows));
  const actualRow = actualRows.map(record).find((row) => row["url"] === protocolUrl);
  assert.ok(actualRow);
  const map = record(cached["data"]);
  const sourceUrls = map["sources"];
  assert.ok(Array.isArray(sourceUrls));
  const localRoot = pathToFileURL(editor + path.sep).href;
  interface DriveTrace extends Record<string, unknown> {
    result: readonly Record<string, unknown>[];
    "source-map-cache": Record<string, Record<string, unknown>>;
  }
  const driveTrace: DriveTrace = {
    result: [{ ...actualRow, url: capturedUrl }],
    "source-map-cache": {
      [declaredUrl]: {
        ...cached,
        data: {
          ...map,
          sources: sourceUrls.map((source: unknown) => {
            assert.ok(typeof source === "string" && source.startsWith(localRoot));
            return new URL(source.slice(localRoot.length), capturedRoot).href;
          }),
        },
      },
    },
  };
  const drivePrefixes = { [producerRoot]: "" };
  assert.deepEqual(await relocateEditorV8(editor, driveTrace, inputs, drivePrefixes), driveTrace);
  const producerProfile = record(
    JSON.parse(await readFile(path.join(producer, "profile.json"), "utf8")),
  );
  const driveProfile = "win32-drive-replay";
  const resolvedCache = driveTrace["source-map-cache"][declaredUrl];
  const unresolvedCache = { ...resolvedCache, data: null };
  const compatibleTrace: DriveTrace = {
    result: [{ ...actualRow, url: declaredUrl }],
    "source-map-cache": { [capturedUrl]: unresolvedCache },
  };
  const convergingTrace: DriveTrace = {
    result: [...driveTrace.result, ...compatibleTrace.result],
    "source-map-cache": {
      ...driveTrace["source-map-cache"],
      ...compatibleTrace["source-map-cache"],
    },
  };
  const reverseTrace: DriveTrace = {
    result: [...compatibleTrace.result, ...driveTrace.result],
    "source-map-cache": {
      ...compatibleTrace["source-map-cache"],
      ...driveTrace["source-map-cache"],
    },
  };

  /**
   * Seal local replay records and run the real supported-profile admission.
   * @param name - Isolated replay scenario.
   * @param traces - Node observations with controlled drive spelling variants.
   * @returns Original admissions and derivative path for counter and cache checks.
   */
  async function stageDriveRecords(
    name: string,
    traces: readonly DriveTrace[],
  ): Promise<{ admission: Awaited<ReturnType<typeof stageEditorCoverage>>; union: string }> {
    const driveProducer = path.join(allocation, name);
    await mkdir(path.join(driveProducer, "v8"), { recursive: true });
    await writeFile(
      path.join(driveProducer, "profile.json"),
      JSON.stringify({
        ...producerProfile,
        kind: "supported-host",
        profile: driveProfile,
        editorUri: producerRoot,
      }) + "\n",
    );
    for (const [i, trace] of traces.entries()) {
      await writeFile(
        path.join(driveProducer, "v8", String(i) + ".json"),
        JSON.stringify(trace) + "\n",
      );
    }
    await sealProfileFiles(driveProducer);
    const union = path.join(allocation, name + "-union");
    const admission = await stageEditorCoverage(
      editor,
      [driveProducer],
      identity,
      [driveProfile],
      union,
    );
    return { admission, union };
  }

  const replays: { name: string; traces: DriveTrace[] }[] = [
    { name: "alternate-cache-key", traces: [driveTrace] },
    { name: "resolved-cache-first", traces: [convergingTrace] },
    { name: "unresolved-cache-first", traces: [reverseTrace] },
    { name: "two-traces-resolved-first", traces: [driveTrace, compatibleTrace] },
    { name: "two-traces-unresolved-first", traces: [compatibleTrace, driveTrace] },
    { name: "equivalent-maps", traces: [driveTrace, driveTrace] },
  ];
  for (const { name, traces } of replays) {
    const { admission, union } = await stageDriveRecords(name, traces);
    assert.equal(admission.mappedProfiles, traces.length);
    assert.deepEqual(admission.owners, inputs.owners);
    const derivativeCache: Record<string, unknown>[] = [];
    for (const [i, original] of admission.originals.entries()) {
      const derivative = original["derivative"];
      assert.ok(typeof derivative === "string");
      const data = record(JSON.parse(await readFile(path.join(union, derivative), "utf8")));
      assert.ok(traces[i]);
      const expectedRows: Record<string, unknown>[] = traces[i].result.map(
        (): Record<string, unknown> => actualRow,
      );
      assert.deepEqual(data["result"], expectedRows);
      derivativeCache.push(record(data["source-map-cache"]));
    }
    for (const earlier of derivativeCache.slice(0, -1)) assert.deepEqual(earlier, {});
    assert.deepEqual(derivativeCache.at(-1), { [protocolUrl]: cached });
  }
  const conflicting: DriveTrace = {
    ...compatibleTrace,
    "source-map-cache": { [capturedUrl]: { ...unresolvedCache, lineLengths: [1] } },
  };
  await assert.rejects(
    stageDriveRecords("conflicting-maps", [driveTrace, conflicting]),
    /conflicting editor cache metadata/u,
  );
  const encodedProtocolUrl = protocolUrl.replace(
    /workbenchProtocol\.test\.js$/u,
    "%77orkbenchProtocol.test.js",
  );
  assert.notEqual(encodedProtocolUrl, protocolUrl);
  assert.equal(pathToFileURL(fileURLToPath(encodedProtocolUrl)).href, protocolUrl);
  const overlaps = [
    { name: "literal-overlapping-cache", key: protocolUrl },
    { name: "encoded-overlapping-cache", key: encodedProtocolUrl },
  ];
  for (const { name, key } of overlaps) {
    const unownedKey: DriveTrace = {
      ...driveTrace,
      "source-map-cache": { ...driveTrace["source-map-cache"], [key]: cached },
    };
    await assert.rejects(
      stageDriveRecords(name, [driveTrace, unownedKey]),
      /unowned V8 cache key overlaps an editor owner/u,
    );
    await assert.rejects(
      relocateEditorV8(editor, unownedKey, inputs, drivePrefixes, true),
      /unowned V8 cache key overlaps an editor owner/u,
    );
  }
  assert.deepEqual(
    await relocateEditorV8(editor, driveTrace, inputs, { "file:///D:/Editor/": "" }, true),
    driveTrace,
  );
  await assert.rejects(
    relocateEditorV8(
      editor,
      driveTrace,
      inputs,
      { ...drivePrefixes, [capturedRoot]: "src/" },
      true,
    ),
    /ambiguous editor path alias/u,
  );
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
  const lintConfigUrl = pathToFileURL(path.join(editor, "eslint.config.mjs")).href;
  const originalConfig = originalRows
    .map(record)
    .find(
      (row) => typeof row["url"] === "string" && row["url"].startsWith(lintConfigUrl + "?mtime="),
    );
  assert.ok(originalConfig, "actual ESLint imports its configuration with an mtime query");
  assert.deepEqual(
    derivedRows.map(record).find((row) => row["url"] === lintConfigUrl),
    { ...originalConfig, url: lintConfigUrl },
    "admit the actual ESLint file URL at its verified consumer filename",
  );
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
