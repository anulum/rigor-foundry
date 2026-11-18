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
import { fileURLToPath, pathToFileURL } from "node:url";
import { digest, nativeInputs, readMember, record } from "./native-artifact-inputs.mjs";
import { admitProfileFiles, editorInputs } from "./editor-profile-inputs.mjs";

/**
 * Give an admitted Windows file URL a stable drive spelling for alias matching.
 * @param {string} url - Original or declared file URL.
 * @returns {string} The URL with only its drive letter folded.
 */
function windowsDriveKey(url) {
  return url.replace(/^file:\/\/\/[A-Z](?=:\/)/u, (drive) => drive.toLowerCase());
}

/**
 * Remove module query and fragment suffixes while preserving exact file path spelling.
 * @param {string} url - Original script, cache or declared file URL.
 * @returns {string} The URL used for source ownership and pathname resolution.
 */
function undecoratedUrl(url) {
  return url.replace(/[?#].*$/su, "");
}

/**
 * Match the file URL identity used by the pinned c8 source-map cache consumer.
 * @param {string} url - Original or relocated cache key.
 * @returns {string} The consumer's path-derived file URL.
 */
function consumerCacheKey(url) {
  return pathToFileURL(fileURLToPath(url)).href;
}

/**
 * Merge cache records that name the same verified generated file.
 * @param {Record<string, unknown> | undefined} previous - Previously admitted cache record.
 * @param {Record<string, unknown>} current - Another record for the same generated file.
 * @returns {Record<string, unknown>} The equivalent or most complete admitted record.
 */
function mergeEditorCache(previous, current) {
  if (previous === undefined) return current;
  const { data: previousMap, url: previousUrl, ...previousDetails } = previous;
  const { data: currentMap, url: currentUrl, ...currentDetails } = current;
  assert.deepEqual(previousDetails, currentDetails, "conflicting editor cache metadata");
  if (previousMap != null && currentMap == null) return previous;
  if (previousMap == null && currentMap != null) return current;
  assert.deepEqual(previousMap, currentMap, "conflicting editor cache maps");
  assert.deepEqual(previousUrl, currentUrl, "conflicting editor cache URLs");
  return previous;
}

/**
 * Relocate one verified source-map cache record using the observed cache key.
 * @param {string} editor - Consumer's source and compiler output root.
 * @param {import("./editor-profile-inputs.mjs").EditorInputInventory} inputs - Exact input identities.
 * @param {string} origin - Observed source-map cache key.
 * @param {string} relative - Verified editor-relative path to emitted JavaScript.
 * @param {Record<string, unknown>} original - Original cache record under the observed key.
 * @param {(url: string) => string} normalize - Admitted URL identity.
 * @returns {Promise<Record<string, unknown>>} Record with a verified consumer map.
 */
async function relocateEditorCache(editor, inputs, origin, relative, original, normalize) {
  if (original["data"] == null) return original;
  const mapName = relative + ".map";
  assert.ok(inputs.generated[mapName], "owned V8 source map is not declared");
  const mapBytes = await readMember(editor, mapName);
  assert.equal(digest(mapBytes), inputs.generated[mapName], "editor emitted source map changed");
  const sourceMap = record(JSON.parse(mapBytes.toString("utf8")));
  const sources = sourceMap["sources"];
  assert.ok(Array.isArray(sources) && sources.every((source) => typeof source === "string"));
  const observedMap = record(original["data"]);
  const observedSources = observedMap["sources"];
  assert.ok(
    Array.isArray(observedSources) &&
      observedSources.every((source) => typeof source === "string"),
    "V8 cached map source paths are invalid",
  );
  const originMap = new URL(undecoratedUrl(origin) + ".map");
  assert.deepEqual(
    {
      ...observedMap,
      sources: observedSources.map((source) => normalize(/** @type {string} */ (source))),
    },
    {
      ...sourceMap,
      sources: sources.map((source) =>
        normalize(new URL(/** @type {string} */ (source), originMap).href),
      ),
    },
    "V8 cached map differs from exact emitted map",
  );
  assert.equal(original["url"], null, "resolved Node source maps require a null cache URL");
  const localMap = pathToFileURL(path.join(editor, mapName));
  return {
    ...original,
    data: {
      ...sourceMap,
      sources: sources.map((source) => new URL(/** @type {string} */ (source), localMap).href),
    },
  };
}

/**
 * Relocate one byte-bound raw V8 file without filtering or altering its function ranges.
 * @param {string} editor - Consumer's actual source and compiler output root.
 * @param {Record<string, unknown>} raw - Original admitted V8 object.
 * @param {import("./editor-profile-inputs.mjs").EditorInputInventory} inputs - Exact consumer input identities.
 * @param {Record<string, string>} aliases - Producer/verified fixture URL prefixes to editor-relative paths.
 * @param {boolean} [windowsDriveUrls] - Whether the admitted producer used Windows file URLs.
 * @param {Map<string, Record<string, unknown>>} [unionCache] - Shared verified records, written once after admitting all traces.
 * @returns {Promise<Record<string, unknown>>} Derivative object with source-exact URL/map paths only.
 */
export async function relocateEditorV8(
  editor,
  raw,
  inputs,
  aliases,
  windowsDriveUrls = false,
  unionCache,
) {
  const result = raw["result"];
  assert.ok(Array.isArray(result), "V8 profile requires original result entries");
  const cache = raw["source-map-cache"] === undefined ? {} : record(raw["source-map-cache"]);
  const rewritten = { ...cache };
  const normalize = windowsDriveUrls ? windowsDriveKey : (/** @type {string} */ url) => url;
  /** @type {Map<string, {relative: string, local: string}>} */
  const owned = new Map();
  const rows = [];
  /** @type {Map<string, string>} */
  const declared = new Map();
  for (const [alias, base] of Object.entries(aliases)) {
    const key = normalize(undecoratedUrl(alias));
    assert.ok(!declared.has(key) || declared.get(key) === base, "ambiguous editor path alias");
    declared.set(key, base);
  }
  const prefixes = [...declared.keys()].sort((left, right) => right.length - left.length);
  for (const value of result) {
    const row = record(value);
    const url = row["url"];
    assert.ok(typeof url === "string");
    const pathname = undecoratedUrl(url);
    const key = normalize(pathname);
    /** @type {string | undefined} */
    const prefix = prefixes.find((candidate) =>
      candidate.endsWith("/") ? key.startsWith(candidate) : key === candidate,
    );
    if (prefix === undefined) {
      rows.push(row);
      continue;
    }
    const base = declared.get(prefix);
    assert.ok(typeof base === "string");
    const relative = base + decodeURIComponent(pathname.slice(prefix.length));
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
    owned.set(key, { relative, local });
  }
  /** @type {Map<string, Record<string, unknown>>} */
  const collected = unionCache ?? new Map();
  for (const [origin, value] of Object.entries(cache)) {
    const owner = owned.get(normalize(undecoratedUrl(origin)));
    if (owner === undefined) continue;
    const current = await relocateEditorCache(
      editor,
      inputs,
      origin,
      owner.relative,
      record(value),
      normalize,
    );
    collected.set(owner.local, mergeEditorCache(collected.get(owner.local), current));
    Reflect.deleteProperty(rewritten, origin);
  }
  if (unionCache === undefined) {
    const unowned = new Set(Object.keys(rewritten).map(consumerCacheKey));
    for (const [local, value] of collected) {
      assert.ok(
        !unowned.has(consumerCacheKey(local)),
        "unowned V8 cache key overlaps an editor owner",
      );
      rewritten[local] = value;
    }
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
    assert.ok(typeof profile === "string");
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
      profile,
      aliases,
      windowsDriveUrls:
        metadata["kind"] === "native-build" ||
        (metadata["kind"] === "supported-host" && profile.startsWith("win32-")),
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
  /** @type {Map<string, Record<string, unknown>>} */
  const unionCache = new Map();
  /** @type {Set<string>} */
  const unownedCacheKeys = new Set();
  /** @type {{producer: string, file: string, originalSha256: string, trace: Record<string, unknown>} | undefined} */
  let pending;
  /**
   * Write one derivative and record its exact bytes.
   * @param {{producer: string, file: string, originalSha256: string, trace: Record<string, unknown>}} entry - Admitted derivative.
   * @returns {Promise<void>} Completion after writing and recording the derivative.
   */
  async function writeDerivative(entry) {
    const filename = String(originals.length) + ".json";
    const payload = JSON.stringify(entry.trace) + "\n";
    await writeFile(path.join(destination, filename), payload, { flag: "wx" });
    originals.push({
      producer: entry.producer,
      file: entry.file,
      originalSha256: entry.originalSha256,
      derivative: filename,
      derivativeSha256: digest(payload),
      functionsRangesCountsUnchanged: true,
    });
  }
  for (const producer of producers) {
    for (const name of producer.rawNames) {
      const bytes = await readMember(producer.directory, name);
      assert.equal(digest(bytes), producer.files[name]);
      const raw = record(JSON.parse(bytes.toString("utf8")));
      const trace = await relocateEditorV8(
        editor,
        raw,
        inputs,
        producer.aliases,
        producer.windowsDriveUrls,
        unionCache,
      );
      for (const cacheKey of Object.keys(record(trace["source-map-cache"]))) {
        unownedCacheKeys.add(consumerCacheKey(cacheKey));
      }
      if (pending !== undefined) await writeDerivative(pending);
      pending = { producer: producer.profile, file: name, originalSha256: digest(bytes), trace };
    }
  }
  assert.ok(pending);
  for (const local of unionCache.keys()) {
    assert.ok(
      !unownedCacheKeys.has(consumerCacheKey(local)),
      "unowned V8 cache key overlaps an editor owner",
    );
  }
  // c8 overwrites repeated cache keys while reading reports. Publish each owned key once.
  pending.trace["source-map-cache"] = {
    ...record(pending.trace["source-map-cache"]),
    ...Object.fromEntries(
      [...unionCache.entries()].sort(([left], [right]) => left.localeCompare(right)),
    ),
  };
  await writeDerivative(pending);
  return { owners: inputs.owners, originals, mappedProfiles: originals.length };
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
