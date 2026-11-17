// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — exact supported-profile V8 admission

/**
 * Admit complete source/run-bound original profiles and relocate only verified source URLs.
 * Preserve every original script/function/range/count and retain immutable raw files.
 * @module
 */

import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { digest, nativeInputs, readMember, record } from "./native-artifact-inputs.mjs";
import { admitProfileFiles, editorInputs } from "./editor-profile-inputs.mjs";

/**
 * Relocate one byte-bound raw V8 file without filtering or altering its function ranges.
 * @param {string} editor - Consumer's actual source and compiler output root.
 * @param {Record<string, unknown>} raw - Original admitted V8 object.
 * @param {import("./editor-profile-inputs.mjs").EditorInputInventory} inputs - Exact consumer input identities.
 * @param {Record<string, string>} aliases - Producer/verified fixture URL prefixes to editor-relative paths.
 * @returns {Promise<Record<string, unknown>>} Derivative object with source-exact URL/map paths only.
 */
export async function relocateEditorV8(editor, raw, inputs, aliases) {
  const result = raw["result"];
  assert.ok(Array.isArray(result), "V8 profile requires original result entries");
  const cache = raw["source-map-cache"] === undefined ? {} : record(raw["source-map-cache"]);
  const rewritten = { ...cache };
  const rows = [];
  const prefixes = Object.keys(aliases).sort((left, right) => right.length - left.length);
  for (const value of result) {
    const row = record(value);
    const url = row["url"];
    assert.ok(typeof url === "string");
    const prefix = prefixes.find((candidate) =>
      candidate.endsWith("/") ? url.startsWith(candidate) : url === candidate,
    );
    if (prefix === undefined) {
      rows.push(row);
      continue;
    }
    const base = aliases[prefix];
    assert.ok(typeof base === "string");
    const relative = base + decodeURIComponent(url.slice(prefix.length));
    assert.ok(!relative.includes("\\") && !relative.split("/").includes(".."));
    const expected = inputs.generated[relative] ?? inputs.sources["editors/vscode/" + relative];
    if (expected === undefined) {
      rows.push(row);
      continue;
    }
    assert.equal(digest(await readMember(editor, relative)), expected);
    const local = pathToFileURL(path.join(editor, relative)).href;
    const clone = { ...row, url: local };
    assert.deepEqual({ ...clone, url }, row, "V8 function/range/count data must remain unchanged");
    rows.push(clone);
    if (cache[/** @type {string} */ (url)] === undefined) continue;
    const original = record(cache[/** @type {string} */ (url)]);
    const updated = { ...original };
    if (original["data"] !== undefined && original["data"] !== null) {
      const mapName = relative + ".map";
      assert.ok(inputs.generated[mapName], "owned V8 source map is not declared");
      const mapBytes = await readMember(editor, mapName);
      assert.equal(
        digest(mapBytes),
        inputs.generated[mapName],
        "editor emitted source map changed",
      );
      const sourceMap = record(JSON.parse(mapBytes.toString("utf8")));
      const sources = sourceMap["sources"];
      assert.ok(Array.isArray(sources) && sources.every((source) => typeof source === "string"));
      const oldMapUrl = new URL(/** @type {string} */ (url) + ".map");
      const oldSources = sources.map(
        (source) => new URL(/** @type {string} */ (source), oldMapUrl).href,
      );
      assert.deepEqual(
        original["data"],
        { ...sourceMap, sources: oldSources },
        "V8 cached map differs from exact emitted map",
      );
      const newMapUrl = pathToFileURL(path.join(editor, mapName));
      updated["data"] = {
        ...sourceMap,
        sources: sources.map((source) => new URL(/** @type {string} */ (source), newMapUrl).href),
      };
      assert.equal(original["url"], null, "resolved Node source maps require a null cache URL");
    }
    Reflect.deleteProperty(rewritten, url);
    rewritten[local] = updated;
  }
  return { ...raw, result: rows, "source-map-cache": rewritten };
}

/**
 * Verify every source-origin witness retained by real constructor CLI tests.
 * @param {string} directory - Admitted producer artifact.
 * @param {Record<string, string>} files - Its already verified immutable member hashes.
 * @param {{sources: Record<string, string>, generated: Record<string, string>}} inputs - Exact source and emitted-code inventories.
 * @returns {Promise<Record<string, string>>} Proven fixture source URL prefixes.
 */
async function fixtureAliases(directory, files, inputs) {
  /** @type {Record<string, string>} Original copied-repository source prefixes. */
  const aliases = {};
  for (const name of Object.keys(files).filter((name) => name.endsWith("/source-origin.json"))) {
    const origin = record(JSON.parse((await readMember(directory, name)).toString("utf8")));
    assert.equal(origin["schema"], 1);
    const copies = origin["copies"];
    assert.ok(Array.isArray(copies) && copies.length > 0);
    for (const value of copies) {
      const copy = record(value);
      const source = copy["source"];
      const url = copy["url"];
      const hash = copy["sha256"];
      assert.ok(typeof source === "string" && typeof url === "string" && typeof hash === "string");
      assert.equal(new URL(url).protocol, "file:");
      const relative = source.startsWith("editors/vscode/") ? source.slice(15) : undefined;
      assert.equal(
        hash,
        inputs.sources[source] ??
          (relative === undefined ? undefined : inputs.generated[relative]),
        "copied editor source differs",
      );
      if (relative === undefined) continue;
      assert.ok(
        aliases[url] === undefined || aliases[url] === relative,
        "ambiguous copied source owner",
      );
      aliases[url] = relative;
    }
  }
  return aliases;
}

/**
 * @typedef {object} EditorCoverageAdmission - Original producer admissions and the complete denominator for a derivative V8 union.
 * @property {string[]} owners - Complete retained source-owner denominator.
 * @property {Record<string, unknown>[]} originals - Admitted original producer identities and hashes.
 * @property {number} mappedProfiles - Number of original V8 profiles relocated into the union.
 */

/**
 * Admit an exact declared producer set before constructing a derivative complete V8 union.
 * Local data callers may declare their real targeted context; the hosted CLI fixes all required roles.
 * @param {string} editor - Exact consumer source and compiled output.
 * @param {string[]} directories - Downloaded original producer artifacts.
 * @param {Record<string, string>} identity - Expected genuine invocation identity.
 * @param {string[]} required - Complete expected role/profile identifiers.
 * @param {string} destination - Absent owned derivative V8 directory.
 * @returns {Promise<EditorCoverageAdmission>} Original admissions and complete denominator.
 */
export async function stageEditorCoverage(editor, directories, identity, required, destination) {
  assert.ok(required.length > 0 && new Set(required).size === required.length);
  const inputs = await editorInputs(editor);
  const native = await nativeInputs(editor, editor);
  const producers = [];
  for (const directory of directories) {
    const files = await admitProfileFiles(directory);
    const metadata = record(
      JSON.parse((await readMember(directory, "profile.json")).toString("utf8")),
    );
    assert.equal(metadata["schema"], 1);
    assert.deepEqual(metadata["identity"], identity);
    assert.equal(metadata["node"], process.version);
    const source = record(metadata["inputs"]);
    assert.deepEqual(source["sources"], inputs.sources, "editor producer source differs");
    assert.deepEqual(source["owners"], inputs.owners, "editor producer owner set differs");
    const generated = record(source["generated"]);
    for (const [name, hash] of Object.entries(generated))
      assert.equal(inputs.generated[name], hash, "editor emitted code/maps differ");
    if (metadata["kind"] === "supported-host")
      assert.deepEqual(
        generated,
        inputs.generated,
        "supported editor profile requires every emitted file",
      );
    assert.deepEqual(metadata["native"], native, "editor native build payload differs");
    const profile = metadata["profile"];
    assert.equal(typeof profile, "string");
    const prefix = metadata["editorUri"];
    assert.ok(typeof prefix === "string" && prefix.startsWith("file:") && prefix.endsWith("/"));
    const aliases = { [prefix]: "", ...(await fixtureAliases(directory, files, inputs)) };
    const rawNames = Object.keys(files).filter(
      (name) => name.startsWith("v8/") && name.endsWith(".json"),
    );
    assert.ok(rawNames.length > 0, "required editor producer has no original V8 data");
    producers.push({
      directory,
      files,
      metadata,
      profile: /** @type {string} */ (profile),
      aliases,
      rawNames,
    });
  }
  assert.deepEqual(
    producers.map((producer) => producer.profile).sort(),
    [...required].sort(),
    "incomplete or duplicated editor producer set",
  );
  await mkdir(destination, { recursive: false });
  /** @type {Record<string, unknown>[]} Original unmodified file and source admissions. */
  const originals = [];
  let sequence = 0;
  for (const producer of producers) {
    for (const name of producer.rawNames) {
      const bytes = await readMember(producer.directory, name);
      assert.equal(digest(bytes), producer.files[name]);
      const raw = record(JSON.parse(bytes.toString("utf8")));
      const relocated = await relocateEditorV8(editor, raw, inputs, producer.aliases);
      const filename = String(sequence++) + ".json";
      await writeFile(path.join(destination, filename), JSON.stringify(relocated) + "\n", {
        flag: "wx",
      });
      originals.push({
        producer: producer.profile,
        file: name,
        originalSha256: digest(bytes),
        derivative: filename,
        derivativeSha256: digest(JSON.stringify(relocated) + "\n"),
        functionsRangesCountsUnchanged: true,
      });
    }
  }
  return { owners: inputs.owners, originals, mappedProfiles: sequence };
}

/**
 * Require exactly the declared whole-owner denominator and every original 100 percent metric.
 * @param {string} editor - Actual source root.
 * @param {string} summaryFile - Genuine c8 json-summary output.
 * @param {string[]} owners - Complete caller-declared source owner cohort.
 * @returns {Promise<void>} Completion only after the exact full cohort passes.
 */
export async function requireEditorOwnerCoverage(editor, summaryFile, owners) {
  const report = record(
    JSON.parse(
      (await readMember(path.dirname(summaryFile), path.basename(summaryFile))).toString("utf8"),
    ),
  );
  const entries = Object.keys(report)
    .filter((name) => name !== "total")
    .map((name) => path.relative(editor, name).split(path.sep).join("/"))
    .sort();
  assert.deepEqual(entries, [...owners].sort(), "editor coverage owner denominator differs");
  for (const [name, value] of Object.entries(report)) {
    const row = record(value);
    for (const metric of ["statements", "branches", "functions", "lines"]) {
      const counts = record(row[metric]);
      assert.equal(counts["pct"], 100, "incomplete whole editor owner: " + name);
      assert.equal(counts["skipped"], 0, "editor owner coverage exclusions are forbidden");
    }
  }
}
