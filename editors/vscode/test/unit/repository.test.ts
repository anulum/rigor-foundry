// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — original fixture error after unavailable diagnostic files

/**
 * Exercise the complete public fixture producer with real conflicting output directories.
 * Preserve the original filesystem refusal when writing its failure metadata also refuses.
 * @module
 */

import assert from "node:assert/strict";
import { glob, mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { setInterval as interval } from "node:timers/promises";
import { inspect } from "node:util";
import { runCli } from "../../src/cli.js";
import { createEvidenceRepository } from "../support/repository.js";

if (process.env["RIGOR_FOUNDRY_FIXTURE_ERROR_OBSERVER"] === "1") {
  void test("records the original real fixture filesystem refusal", async () => {
    const observation = process.env["RIGOR_FOUNDRY_FIXTURE_ERROR_RECORD"];
    assert.ok(observation);
    let refused: unknown;
    await assert.rejects(createEvidenceRepository(), (error: unknown): boolean => {
      refused = error;
      return true;
    });
    assert.ok(refused instanceof Error);
    assert.ok("code" in refused && typeof refused.code === "string");
    assert.ok("path" in refused && typeof refused.path === "string");
    assert.ok(["EISDIR", "EPERM", "EACCES"].includes(refused.code));
    assert.equal(path.basename(refused.path), "command-5.stdout");
    await writeFile(
      observation,
      JSON.stringify({
        code: refused.code,
        path: refused.path,
        message: refused.message,
        originalRefusalRetained: true,
      }) + "\n",
      "utf8",
    );
  });
} else {
  void test(
    "preserves the original fixture refusal when diagnostic files are directories",
    { timeout: 90_000 },
    async (context) => {
      const extensionRoot = path.resolve(__dirname, "../../..");
      const fixtures = path.join(extensionRoot, "out", "fixtures");
      await mkdir(fixtures, { recursive: true });
      const allocation = await mkdtemp(path.join(fixtures, "rigor-repository-trace-"));
      const record = path.join(allocation, "original-refusal.json");
      const environment = { ...process.env };
      delete environment["NODE_TEST_CONTEXT"];
      const completion = Promise.allSettled([
        runCli(process.execPath, ["--test", __filename], {
          cwd: extensionRoot,
          timeoutMilliseconds: 60_000,
          environment: {
            ...environment,
            TMPDIR: allocation,
            TMP: allocation,
            TEMP: allocation,
            RIGOR_FOUNDRY_FIXTURE_ERROR_OBSERVER: "1",
            RIGOR_FOUNDRY_FIXTURE_ERROR_RECORD: record,
          },
        }),
      ]);
      context.after(async () => {
        await writeFile(
          path.join(allocation, "process-outcome.txt"),
          inspect(await completion, { depth: null, maxStringLength: null }) + "\n",
        );
      });
      let stem: string | undefined;
      for await (const directory of interval(1, allocation, {
        signal: AbortSignal.timeout(10_000),
      })) {
        const matches: string[] = [];
        for await (const name of glob("rigor-native-evidence-*/.rigor/command-5.argv.json", {
          cwd: directory,
        })) {
          matches.push(name);
        }
        const trace = matches[0];
        if (trace === undefined) continue;
        stem = path.join(directory, trace).slice(0, -".argv.json".length);
        await mkdir(stem + ".stdout");
        await mkdir(stem + ".failure.json");
        break;
      }
      assert.ok(stem);
      const outcomes = await completion;
      const outcome = outcomes[0];
      assert.ok(outcome);
      assert.equal(outcome.status, "fulfilled");
      const output = outcome.value.stdout + outcome.value.stderr;
      const printedStem = stem.replaceAll("\\", "\\\\");
      assert.ok(output.includes("RigorFoundry fixture trace write failed at " + printedStem));
      assert.ok(output.includes(printedStem + ".failure.json"));
      const root = path.dirname(path.dirname(stem));
      assert.ok(
        output.includes("RigorFoundry native fixture failure at " + root.replaceAll("\\", "\\\\")),
      );
      const observed: unknown = JSON.parse(await readFile(record, "utf8"));
      assert.ok(typeof observed === "object" && observed !== null);
      assert.ok("path" in observed && observed.path === stem + ".stdout");
      assert.ok(
        "originalRefusalRetained" in observed && observed.originalRefusalRetained === true,
      );
      assert.equal((await stat(stem + ".stdout")).isDirectory(), true);
      assert.equal((await stat(stem + ".failure.json")).isDirectory(), true);
      const argv: unknown = JSON.parse(await readFile(stem + ".argv.json", "utf8"));
      assert.ok(typeof argv === "object" && argv !== null && "args" in argv);
      assert.ok(Array.isArray(argv.args));
      assert.equal(argv.args[0], "bootstrap");
      assert.equal((await stat(path.join(root, "native-evidence-policy.json"))).isFile(), true);
      const sourceRoot =
        process.env["RIGOR_FOUNDRY_SOURCE_ROOT"] ?? path.resolve(extensionRoot, "../..");
      for (const name of ["src/rigor_foundry/git_inventory.py", "tests/test_git_inventory.py"]) {
        assert.deepEqual(
          await readFile(path.join(root, name)),
          await readFile(path.join(sourceRoot, name)),
        );
      }
      await writeFile(path.join(allocation, "child.stdout"), outcome.value.stdout, "utf8");
      await writeFile(path.join(allocation, "child.stderr"), outcome.value.stderr, "utf8");
    },
  );
}
