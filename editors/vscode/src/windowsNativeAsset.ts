// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — pinned native Windows package image

/**
 * Verify and preload the exact packaged native image before the unchanged vendor loader runs.
 * Keep alternate native initializers from executing through upstream fallback discovery.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

if (process.platform !== "win32" || process.arch !== "x64") {
  throw new Error("native Windows resources require a qualified Windows x64 host");
}

const nativeRoot = path.resolve(__dirname, "../../native/koffi");
const nativeImage = path.join(nativeRoot, "build/koffi/win32_x64/koffi.node");
const nativeRequire = createRequire(__filename);

/**
 * Reject another cached Koffi image before it can be mistaken for the owned package binding.
 */
export function assertWindowsNativeImage(): void {
  const owned = realpathSync.native(nativeImage);
  for (const filename of Object.keys(nativeRequire.cache)) {
    if (path.basename(filename) === "koffi.node")
      assert.equal(realpathSync.native(filename), owned, "another native Koffi image was loaded");
  }
}

const provenanceBytes = readFileSync(path.join(nativeRoot, "provenance.json"));
const provenance: unknown = JSON.parse(provenanceBytes.toString("utf8"));
assert.ok(
  typeof provenance === "object" && provenance !== null && "members" in provenance,
  "native package provenance is unavailable",
);
const members: unknown = provenance.members;
assert.ok(typeof members === "object" && members !== null, "native package members are invalid");
for (const relative of [
  "src/koffi/index.cjs",
  "src/koffi/src/static.cjs",
  "build/koffi/win32_x64/koffi.node",
]) {
  assert.ok(relative in members, "native package member is not pinned");
  const expected: unknown = Reflect.get(members, relative);
  assert.equal(typeof expected, "string", "native package digest is invalid");
  assert.equal(
    createHash("sha256")
      .update(readFileSync(path.join(nativeRoot, relative)))
      .digest("hex"),
    expected,
    "native package member differs from build provenance",
  );
}
const binding: unknown = JSON.parse(
  readFileSync(path.join(nativeRoot, "binding-provenance.json"), "utf8"),
);
assert.ok(
  typeof binding === "object" && binding !== null && "members" in binding,
  "native binding provenance is unavailable",
);
assert.ok("producer" in binding && binding.producer === "rigor-foundry-windows-binding-v1");
assert.ok("nativeBuildProvenanceSha256" in binding);
assert.equal(
  binding.nativeBuildProvenanceSha256,
  createHash("sha256").update(provenanceBytes).digest("hex"),
  "native binding does not match the compiled image provenance",
);
const bindingMembers: unknown = binding.members;
assert.ok(typeof bindingMembers === "object" && bindingMembers !== null);
assert.ok("package.json" in bindingMembers);
assert.equal(typeof bindingMembers["package.json"], "string");
assert.equal(
  createHash("sha256")
    .update(readFileSync(path.join(nativeRoot, "package.json")))
    .digest("hex"),
  bindingMembers["package.json"],
  "native binding manifest differs from its provenance",
);
const staticRequire = createRequire(path.join(nativeRoot, "src/koffi/src/static.cjs"));
const resolvedImage = realpathSync.native(staticRequire.resolve("@koromix/koffi-win32-x64"));
assert.equal(
  resolvedImage,
  realpathSync.native(nativeImage),
  "native binding resolves another image",
);
assert.equal(
  createHash("sha256").update(readFileSync(resolvedImage)).digest("hex"),
  Reflect.get(members, "build/koffi/win32_x64/koffi.node"),
  "resolved native binding image differs from build provenance",
);
assert.equal(
  existsSync(path.resolve(nativeRoot, "../@koromix/koffi-win32-x64")),
  false,
  "an alternate native Koffi candidate exists before the owned image",
);
assertWindowsNativeImage();
// A failed explicit load aborts this import. The vendor loader must never run after failure.
nativeRequire(nativeImage);
assertWindowsNativeImage();
