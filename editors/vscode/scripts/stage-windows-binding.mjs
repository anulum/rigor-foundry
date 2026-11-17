// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — owned Windows package resolution metadata

/**
 * Stage reproducible package self-reference metadata for an existing qualified native image.
 * Preserve the original compiler provenance and refuse to overwrite different binding assets.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Require a parsed metadata record without assuming its field types.
 * @param {unknown} value - Parsed build metadata.
 * @returns {Record<string, unknown>} Fields awaiting their specific checks.
 */
function record(value) {
  assert.ok(typeof value === "object" && value !== null && !Array.isArray(value));
  return /** @type {Record<string, unknown>} */ (value);
}

/**
 * Hash exact asset bytes without changing their encoding or layout.
 * @param {Uint8Array} bytes - Original input or reproducibly encoded metadata.
 * @returns {string} Lowercase SHA-256.
 */
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const native = path.join(root, "native/koffi");
const provenanceBytes = await readFile(path.join(native, "provenance.json"));
const provenance = record(JSON.parse(provenanceBytes.toString("utf8")));
assert.equal(provenance["producer"], "rigor-foundry-windows-native-v1");
assert.equal(provenance["platform"], "win32");
assert.equal(provenance["architecture"], "x64");
const members = record(provenance["members"]);
for (const relative of [
  "src/koffi/index.cjs",
  "src/koffi/src/static.cjs",
  "build/koffi/win32_x64/koffi.node",
]) {
  const filename = path.join(native, relative);
  assert.ok((await lstat(filename)).isFile(), "native binding inputs must be regular files");
  const expected = members[relative];
  assert.equal(typeof expected, "string", "native binding input is not pinned");
  assert.equal(digest(await readFile(filename)), expected, "native binding input changed");
}
const packageBytes = Buffer.from(
  JSON.stringify(
    {
      name: "@koromix/koffi-win32-x64",
      private: true,
      type: "commonjs",
      exports: { ".": "./build/koffi/win32_x64/koffi.node" },
    },
    null,
    2,
  ) + "\n",
);
const license = await readFile(path.join(root, "native/koffi-source.json.license"));
const bindingBytes = Buffer.from(
  JSON.stringify(
    {
      producer: "rigor-foundry-windows-binding-v1",
      nativeBuildProvenanceSha256: digest(provenanceBytes),
      members: {
        "package.json": digest(packageBytes),
        "package.json.license": digest(license),
      },
    },
    null,
    2,
  ) + "\n",
);
const assets = new Map([
  ["package.json", packageBytes],
  ["package.json.license", license],
  ["binding-provenance.json", bindingBytes],
  ["binding-provenance.json.license", license],
]);
/** @type {Map<string, Uint8Array>} New assets; existing matching bytes are retained. */
const pending = new Map();
for (const [relative, bytes] of assets) {
  const filename = path.join(native, relative);
  if (existsSync(filename)) {
    assert.ok((await lstat(filename)).isFile(), "binding assets must be regular files");
    assert.deepEqual(await readFile(filename), bytes, "existing binding asset differs");
  } else {
    pending.set(filename, bytes);
  }
}
for (const [filename, bytes] of pending) {
  await writeFile(filename, bytes, { flag: "wx" });
}
process.stdout.write(
  JSON.stringify({
    nativeBuildProvenanceSha256: digest(provenanceBytes),
    nativeImageSha256: members["build/koffi/win32_x64/koffi.node"],
    packageManifestSha256: digest(packageBytes),
    bindingProvenanceSha256: digest(bindingBytes),
    stagedFiles: pending.size,
  }) + "\n",
);
