// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — actual Windows rejection of Linux-only test entry points

/**
 * Require Linux-specific entry points to reject an actual unsupported Windows host.
 * Exercise their maintained setup diagnostics without replacing platform or filesystem APIs.
 * @module
 */

import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

for (const [moduleName, diagnostic] of [
  ["cli.test.js", "Linux process test registration failed:"],
  ["fileAccess.test.js", "Linux native filesystem test setup failed:"],
] as const) {
  void test(
    "Linux-only entry point refuses actual Windows: " + moduleName,
    { skip: process.platform !== "win32" },
    async () => {
      const entryPoint = path.resolve(__dirname, "../linux", moduleName);
      const failure = await runCli(process.execPath, [entryPoint], {
        cwd: path.resolve(__dirname, "../../.."),
        timeoutMilliseconds: 10_000,
      }).catch((error: unknown): CommandExecutionFailure => {
        assert.ok(error instanceof CommandExecutionFailure);
        return error;
      });
      assert.ok(failure instanceof CommandExecutionFailure);
      assert.equal(failure.message, "RigorFoundry CLI failed with exit code 1");
      assert.equal(failure.output.stdout, "");
      assert.ok(failure.output.stderr.includes(diagnostic));
      assert.match(failure.output.stderr, /win32/u);
      assert.match(failure.output.stderr, /linux/u);
    },
  );
}
