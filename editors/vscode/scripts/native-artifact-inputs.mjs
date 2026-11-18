// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native artifact source and payload admission

/**
 * Check the complete owned native payload against its locked compiler inputs and binding.
 * Inventory current editor sources independently from generated native outputs.
 * @module
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";

export const nativeMembers = [
  "src/koffi/index.cjs",
  "src/koffi/src/static.cjs",
  "notices/KOFFI-MIT.txt",
  "notices/NODE-ADDON-API-MIT.txt",
  "notices/NODE-API-HEADERS-MIT.txt",
  "build/koffi/win32_x64/koffi.node",
];
export const artifactMembers = [
  ...nativeMembers.map((name) => "native/koffi/" + name),
  "native/koffi/provenance.json",
  "native/koffi/package.json",
  "native/koffi/package.json.license",
  "native/koffi/binding-provenance.json",
  "native/koffi/binding-provenance.json.license",
  "LICENSE.txt",
];
export const buildFlags = "NODE_JS_LINK_FLAGS=/DELAYLOAD:NODE.EXE;delayimp.lib";

/** Repository paths bound by both source digests and clean-checkout admission. */
export const sourcePaths = Object.freeze([
  "editors/vscode",
  ".github/actions/install-editor-host/action.yml",
  ".github/actions/setup-native-python/action.yml",
  ".github/workflows/ci-vscode.yml",
  "LICENSE",
]);

/**
 * Require a JSON object while retaining field-specific runtime validation.
 * @param {unknown} value - Parsed manifest value.
 * @returns {Record<string, unknown>} Manifest fields awaiting validation.
 */
export function record(value) {
  assert.ok(typeof value === "object" && value !== null && !Array.isArray(value));
  return /** @type {Record<string, unknown>} */ (value);
}

/**
 * Hash original bytes without rewriting their representation.
 * @param {Uint8Array | string} bytes - Original input.
 * @returns {string} Lowercase SHA-256.
 */
export function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Read one contained ordinary member without accepting filesystem aliases or changed identity.
 * @param {string} root - Trusted source or artifact root.
 * @param {string} relative - Portable member name.
 * @returns {Promise<Buffer>} Unchanged member bytes.
 */
export async function readMember(root, relative) {
  assert.ok(relative.length > 0 && !relative.includes("\\") && !relative.includes("\0"));
  const parts = relative.split("/");
  assert.ok(parts.every((part) => part !== "" && part !== "." && part !== ".."));
  let current = root;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    assert.ok((await lstat(current)).isDirectory(), "artifact parent must be a real directory");
  }
  const filename = path.join(root, ...parts);
  const before = await lstat(filename, { bigint: true });
  assert.ok(before.isFile(), "artifact member must be a regular file");
  assert.equal(await realpath(filename), path.join(await realpath(root), ...parts));
  const bytes = await readFile(filename);
  const after = await lstat(filename, { bigint: true });
  assert.deepEqual(
    [after.dev, after.ino, after.size, after.mtimeNs, after.ctimeNs],
    [before.dev, before.ino, before.size, before.mtimeNs, before.ctimeNs],
    "artifact member changed while being read",
  );
  assert.equal(BigInt(bytes.length), after.size);
  return bytes;
}

/**
 * Inventory exact ordinary members and reject linked or special entries before admission.
 * @param {string} root - Directory to inventory.
 * @param {string} [prefix] - Portable prefix inside the same root.
 * @returns {Promise<string[]>} Sorted portable member names.
 */
export async function members(root, prefix = "") {
  assert.ok((await lstat(root)).isDirectory(), "artifact root must be a real directory");
  const result = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const relative = prefix + entry.name;
    if (entry.isDirectory())
      result.push(...(await members(path.join(root, entry.name), relative + "/")));
    else {
      assert.ok(entry.isFile(), "artifact must not contain linked or special entries");
      result.push(relative);
    }
  }
  return result.sort();
}

/**
 * Execute an actual bounded read-only Git query without shell interpretation.
 * @param {string} root - Current repository.
 * @param {string[]} args - Literal Git arguments.
 * @returns {string} Original UTF-8 output.
 */
export function git(root, args) {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    shell: false,
    timeout: 10000,
    maxBuffer: 16777216,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, "native artifact requires an actual Git source checkout");
  return result.stdout;
}

/**
 * Bind all maintained editor inputs, the producer workflow and the repository licence.
 * @param {string} root - Actual repository checkout.
 * @returns {Promise<Record<string, string>>} Exact current source member digests.
 */
export async function sourceInputs(root) {
  const names = git(root, [
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
    "-z",
    "--",
    ...sourcePaths,
  ])
    .split("\0")
    .filter(
      (name) =>
        name !== "" &&
        !/^editors\/vscode\/(?:node_modules|out|\.vscode-test|native\/koffi)(?:\/|$)/u.test(
          name,
        ) &&
        name !== "editors/vscode/LICENSE.txt" &&
        !name.endsWith(".vsix"),
    );
  /** @type {Record<string, string>} Complete named source inputs. */
  const result = {};
  for (const name of [...new Set(names)].sort())
    result[name] = digest(await readMember(root, name));
  assert.ok(result["editors/vscode/scripts/build-windows-native.mjs"]);
  assert.ok(result[".github/workflows/ci-vscode.yml"] && result["LICENSE"]);
  assert.ok(result[".github/actions/setup-native-python/action.yml"]);
  return result;
}

/**
 * Validate every real native image, loader, notice and binding member against current source.
 * This checks original bytes and provenance; execution qualification belongs to Windows hosts.
 * @param {string} editor - Current editor source root.
 * @param {string} payload - Root containing the complete native payload.
 * @returns {Promise<Record<string, string>>} Complete verified payload digests.
 */
export async function nativeInputs(editor, payload) {
  assert.deepEqual(
    await members(path.join(payload, "native/koffi")),
    artifactMembers
      .filter((name) => name.startsWith("native/koffi/"))
      .map((name) => name.slice(13))
      .sort(),
    "native payload contains omitted or unexpected members",
  );
  /** @type {Record<string, string>} Exact native payload digests. */
  const result = {};
  for (const name of artifactMembers) result[name] = digest(await readMember(payload, name));
  const manifest = record(
    JSON.parse((await readMember(editor, "native/koffi-source.json")).toString("utf8")),
  );
  const lock = record(
    JSON.parse((await readMember(editor, "package-lock.json")).toString("utf8")),
  );
  const locked = record(record(lock["packages"])["node_modules/koffi"]);
  const provenance = record(
    JSON.parse((await readMember(payload, "native/koffi/provenance.json")).toString("utf8")),
  );
  assert.equal(provenance["producer"], "rigor-foundry-windows-native-v1");
  assert.equal(provenance["version"], "3.3.5");
  assert.equal(provenance["version"], manifest["version"]);
  assert.equal(locked["version"], manifest["version"]);
  assert.equal(locked["integrity"], manifest["integrity"]);
  assert.equal(locked["resolved"], manifest["resolved"]);
  assert.equal(provenance["archiveIntegrity"], manifest["integrity"]);
  assert.equal(provenance["archiveSha256"], manifest["tarball_sha256"]);
  assert.deepEqual(provenance["sourceFiles"], manifest["files"]);
  assert.equal(provenance["platform"], "win32");
  assert.equal(provenance["architecture"], "x64");
  assert.equal(provenance["node"], process.version);
  assert.equal(provenance["buildFlags"], buildFlags);
  const staged = record(provenance["members"]);
  assert.deepEqual(Object.keys(staged).sort(), [...nativeMembers].sort());
  for (const name of nativeMembers) assert.equal(staged[name], result["native/koffi/" + name]);
  const originalFiles = record(manifest["files"]);
  for (const [output, source] of [
    ["src/koffi/index.cjs", "src/koffi/index.cjs"],
    ["src/koffi/src/static.cjs", "src/koffi/src/static.cjs"],
    ["notices/KOFFI-MIT.txt", "LICENSE.txt"],
    ["notices/NODE-ADDON-API-MIT.txt", "vendor/node-addon-api/LICENSE.md"],
    ["notices/NODE-API-HEADERS-MIT.txt", "vendor/node-api-headers/LICENSE"],
  ]) {
    assert.ok(output !== undefined && source !== undefined);
    assert.equal(staged[output], originalFiles[source]);
  }
  const binding = record(
    JSON.parse(
      (await readMember(payload, "native/koffi/binding-provenance.json")).toString("utf8"),
    ),
  );
  assert.equal(binding["producer"], "rigor-foundry-windows-binding-v1");
  assert.equal(binding["nativeBuildProvenanceSha256"], result["native/koffi/provenance.json"]);
  assert.deepEqual(binding["members"], {
    "package.json": result["native/koffi/package.json"],
    "package.json.license": result["native/koffi/package.json.license"],
  });
  assert.deepEqual(
    JSON.parse((await readMember(payload, "native/koffi/package.json")).toString("utf8")),
    {
      name: "@koromix/koffi-win32-x64",
      private: true,
      type: "commonjs",
      exports: { ".": "./build/koffi/win32_x64/koffi.node" },
    },
  );
  const licence = digest(await readMember(editor, "native/koffi-source.json.license"));
  assert.equal(result["native/koffi/package.json.license"], licence);
  assert.equal(result["native/koffi/binding-provenance.json.license"], licence);
  assert.equal(
    result["LICENSE.txt"],
    digest(await readMember(path.resolve(editor, "../.."), "LICENSE")),
  );
  return result;
}
