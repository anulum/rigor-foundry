// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — actual native pointer representation contract

/**
 * Compare the exported decoder with a real borrowed process pseudo-handle and explicit invalid inputs.
 * Keep the native binding import inside the actual Windows test; no foreign loader is substituted.
 * @module
 */

import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";

void test(
  "native pointer decoding preserves actual native output and refuses unsupported inputs",
  { skip: process.platform !== "win32" },
  async () => {
    const { getCurrentProcess, nativePointer } = await import("../../src/windowsAbi.js");
    const actual = getCurrentProcess();
    assert.equal(typeof actual, "bigint");
    assert.equal(nativePointer(actual), actual);
    assert.equal(nativePointer(null), null);
    for (const invalid of [0, NaN, "0x1", undefined, {}, []])
      assert.throws(() => nativePointer(invalid), /pointer has an unsupported representation/u);
  },
);

void test(
  "unsupported hosts refuse before a native image is loaded",
  { skip: process.platform === "win32" },
  async () => {
    const localRequire = createRequire(__filename);
    const before = Object.keys(localRequire.cache).filter((name) => name.endsWith("koffi.node"));
    await assert.rejects(
      import("../../src/windowsNativeAsset.js"),
      /native Windows resources require a qualified Windows x64 host/u,
    );
    assert.deepEqual(
      Object.keys(localRequire.cache).filter((name) => name.endsWith("koffi.node")),
      before,
    );
  },
);
