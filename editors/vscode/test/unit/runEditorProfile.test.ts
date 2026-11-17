// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — required profile authority refusal

/**
 * Invoke the real complete-profile CLI with required invocation metadata withheld.
 * Refuse before any host/suite execution and preserve an existing caller-owned destination.
 * @module
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

void test("complete host entry point refuses missing CI authority before execution", async (context) => {
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-profile-authority-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const marker = path.join(allocation, "existing");
  await writeFile(marker, "preserved", { flag: "wx" });
  const program = path.resolve(__dirname, "../../../scripts/run-editor-profile.mjs");
  const environment = { ...process.env };
  delete environment["GITHUB_ACTIONS"];
  await assert.rejects(
    runCli(process.execPath, [program, "1.125.0", allocation], {
      cwd: allocation,
      timeoutMilliseconds: 10_000,
      environment,
    }),
    (error: unknown): boolean => {
      assert.ok(error instanceof CommandExecutionFailure);
      assert.match(error.output.stderr, /require actual GitHub execution/u);
      assert.equal(error.output.stdout, "");
      return true;
    },
  );
  assert.equal(await readFile(marker, "utf8"), "preserved");
});
