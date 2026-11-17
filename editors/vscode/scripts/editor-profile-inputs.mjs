// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — editor profile source and file manifests

/**
 * Bind actual maintained sources, emitted JavaScript/maps and terminal evidence files.
 * Resolve admitted host metadata independently of a producer's claims.
 * @module
 */

import assert from "node:assert/strict";
import { lstat, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  digest,
  git,
  members,
  nativeInputs,
  readMember,
  record,
  sourceInputs,
  sourcePaths,
} from "./native-artifact-inputs.mjs";

/**
 * Read the declared minimum/current host profiles.
 * @param {string} editor - Actual editor source root.
 * @returns {Promise<Record<string, unknown>[]>} Required platform/version/archive identities.
 */
export async function hostProfiles(editor) {
  const data = record(
    JSON.parse((await readMember(editor, "native/editor-hosts.json")).toString("utf8")),
  );
  assert.equal(data["schema"], 1);
  assert.equal(data["architecture"], "x64");
  const profiles = data["profiles"];
  assert.ok(Array.isArray(profiles) && profiles.length === 4);
  const result = profiles.map(record);
  assert.equal(new Set(result.map((p) => p["id"])).size, 4);
  return result;
}

/**
 * Locate the actual application CLI within the declared host archive layout.
 * @param {string} executable - Installed application executable, without a shell wrapper.
 * @param {Record<string, unknown>} profile - Exact supported archive profile.
 * @returns {Promise<string>} Contained ordinary CLI script in the installed host.
 */
export async function hostCliScript(executable, profile) {
  const relative = profile["cliRelativePath"] ?? "resources/app/out/cli.js";
  assert.ok(typeof relative === "string");
  await readMember(path.dirname(executable), relative);
  return path.join(path.dirname(executable), ...relative.split("/"));
}

/**
 * Bind the actual clean GitHub source and run, without synthesising hosted identity locally.
 * @param {string} editor - Actual source root.
 * @returns {Record<string, string>} Current immutable invocation identity.
 */
export function githubIdentity(editor) {
  assert.equal(
    process.env["GITHUB_ACTIONS"],
    "true",
    "editor profiles require actual GitHub execution",
  );
  const root = path.resolve(editor, "../..");
  const revision = git(root, ["rev-parse", "HEAD"]).trim();
  assert.equal(process.env["GITHUB_SHA"], revision);
  const repository = process.env["GITHUB_REPOSITORY"];
  const runId = process.env["GITHUB_RUN_ID"];
  const runAttempt = process.env["GITHUB_RUN_ATTEMPT"];
  assert.ok(repository && runId && runAttempt);
  assert.match(repository, /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u);
  assert.match(runId, /^[1-9][0-9]*$/u);
  assert.match(runAttempt, /^[1-9][0-9]*$/u);
  assert.equal(
    git(root, ["status", "--porcelain", "--untracked-files=all", "--", ...sourcePaths]),
    "",
  );
  return { venue: "github", revision, repository, runId, runAttempt };
}

/**
 * @typedef {object} EditorInputInventory - Exact source, compiler-output and owner inventories for one editor profile.
 * @property {Record<string, string>} sources - Maintained input paths and SHA-256 digests.
 * @property {Record<string, string>} generated - Emitted JavaScript and source-map SHA-256 digests.
 * @property {string[]} owners - Sorted complete editor, test and script owner paths.
 */

/**
 * Inventory all maintained editor owners plus exact emitted code and source maps.
 * @param {string} editor - Current source and compiler output root.
 * @returns {Promise<EditorInputInventory>} Source-bound input inventory.
 */
export async function editorInputs(editor) {
  const sources = await sourceInputs(path.resolve(editor, "../.."));
  /** @type {Record<string, string>} Complete emitted JavaScript and map digests. */
  const generated = {};
  const output = path.join(editor, "out");
  for (const group of ["src", "scripts", "test"]) {
    const directory = path.join(output, group);
    try {
      assert.ok(
        (await lstat(output)).isDirectory(),
        "compiler output root must be a real directory",
      );
      await lstat(directory);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") continue;
      throw error;
    }
    for (const name of await members(directory)) {
      if (!/\.(?:js|mjs|map)$/u.test(name)) continue;
      const relative = "out/" + group + "/" + name;
      generated[relative] = digest(await readMember(editor, relative));
    }
  }
  const prefix = "editors/vscode/";
  const owners = Object.keys(sources)
    .filter((name) => name.startsWith(prefix))
    .map((name) => name.slice(prefix.length))
    .filter(
      (name) =>
        /^(?:src|test)\/.*\.(?:ts|mjs)$/u.test(name) ||
        /^scripts\/.*\.mjs$/u.test(name) ||
        /^[^/]+\.config\.mjs$/u.test(name),
    )
    .sort();
  assert.ok(owners.length >= 59, "every original editor/test/script owner remains required");
  return { sources, generated, owners };
}

/**
 * Hash every terminal evidence member into a separate immutable manifest.
 * The caller invokes this after the instrumented producer process has exited.
 * @param {string} directory - Owned completed producer directory.
 * @returns {Promise<void>} Manifest written once after all exact members were read.
 */
export async function sealProfileFiles(directory) {
  const files = await members(directory);
  assert.ok(!files.includes("files.json"), "editor evidence is already sealed");
  /** @type {Record<string, string>} Original evidence file digests. */
  const hashes = {};
  for (const name of files) hashes[name] = digest(await readMember(directory, name));
  await writeFile(path.join(directory, "files.json"), JSON.stringify(hashes, null, 2) + "\n", {
    flag: "wx",
  });
}

/**
 * Verify the complete original terminal producer inventory before any raw coverage is read.
 * @param {string} directory - Downloaded producer artifact root.
 * @returns {Promise<Record<string, string>>} Exact admitted original file hashes.
 */
export async function admitProfileFiles(directory) {
  const files = record(JSON.parse((await readMember(directory, "files.json")).toString("utf8")));
  assert.deepEqual(await members(directory), [...Object.keys(files), "files.json"].sort());
  /** @type {Record<string, string>} Runtime-validated hashes. */
  const admitted = {};
  for (const [name, hash] of Object.entries(files)) {
    assert.equal(typeof hash, "string");
    assert.equal(digest(await readMember(directory, name)), hash, "editor evidence file differs");
    admitted[name] = /** @type {string} */ (hash);
  }
  return admitted;
}

/**
 * Preserve a genuine native builder's source/run identity for the required coverage union.
 * @param {string} editor - Builder's actual current source root.
 * @param {string} directory - Its completed native coverage directory.
 * @param {string} artifact - Its actual native transport artifact.
 * @returns {Promise<void>} Native role metadata written without modifying its original V8 data.
 */
export async function recordNativeBuild(editor, directory, artifact) {
  const identity = githubIdentity(editor);
  assert.equal(process.env["GITHUB_JOB"], "vscode-native");
  assert.equal(process.platform, "win32");
  const native = record(JSON.parse((await readMember(artifact, "receipt.json")).toString("utf8")));
  const expected = {
    ...identity,
    producer: "vscode-native",
    platform: "win32",
    architecture: "x64",
    node: process.version,
  };
  assert.deepEqual(native["identity"], expected);
  const inputs = await editorInputs(editor);
  await writeFile(
    path.join(directory, "profile.json"),
    JSON.stringify(
      {
        schema: 1,
        kind: "native-build",
        identity,
        profile: "native-build",
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
}
