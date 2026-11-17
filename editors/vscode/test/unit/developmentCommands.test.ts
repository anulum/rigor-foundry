// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — genuine failed fixture setup evidence

/**
 * Call the complete public fixture producer in a real child with invalid Git configuration.
 * Preserve actual process output, original failure type/cause, locator and complete copied source.
 * Require unit entry points to fail when their real evidence fixture cannot be prepared.
 * @module
 */

import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

/**
 * Verify real setup failure retention without replacing Git, RigorFoundry or the process runner.
 * @returns Completion after the failed public fixture's actual streams and source have been verified.
 */
async function run(): Promise<void> {
  await test("retains real failed fixture streams and the original public failure", async () => {
    const scenario = await mkdtemp(path.join(tmpdir(), "rigor-fixture-failure-"));
    const invalidConfig = path.join(scenario, "invalid-gitconfig");
    await writeFile(invalidConfig, "[broken\n", "utf8");
    const producer = path.resolve(__dirname, "../support/repository.js");
    const runner = path.resolve(__dirname, "../../src/cli.js");
    const program = [
      'const assert = require("node:assert/strict");',
      "const { createEvidenceRepository } = require(" + JSON.stringify(producer) + ");",
      "const { CommandExecutionFailure } = require(" + JSON.stringify(runner) + ");",
      "(async () => {",
      "  try { await createEvidenceRepository(); throw new Error('unexpected fixture success'); }",
      "  catch (error) {",
      "    assert.ok(error instanceof CommandExecutionFailure);",
      "    assert.ok(error.cause instanceof Error);",
      "    assert.match(error.output.stderr, /bad config line/u);",
      "    process.stdout.write(JSON.stringify({publicFailureType: true, causeRetained: true, output: error.output}));",
      "  }",
      "})().catch(error => { console.error(error); process.exitCode = 1; });",
    ].join("\n");
    await writeFile(path.join(scenario, "child-program.cjs"), program, "utf8");
    const args = ["-e", program];
    await writeFile(
      path.join(scenario, "child.argv.json"),
      JSON.stringify({ executable: process.execPath, args, cwd: scenario }) + "\n",
      "utf8",
    );
    const result = await runCli(process.execPath, args, {
      cwd: scenario,
      timeoutMilliseconds: 60_000,
      environment: {
        ...process.env,
        GIT_CONFIG_GLOBAL: invalidConfig,
        GIT_CONFIG_NOSYSTEM: "1",
        LC_ALL: "C",
      },
    });
    await writeFile(path.join(scenario, "child.stdout"), result.stdout, "utf8");
    await writeFile(path.join(scenario, "child.stderr"), result.stderr, "utf8");
    const observed: unknown = JSON.parse(result.stdout);
    assert.ok(typeof observed === "object" && observed !== null && "output" in observed);
    assert.ok("publicFailureType" in observed && observed.publicFailureType === true);
    assert.ok("causeRetained" in observed && observed.causeRetained === true);
    const locator = /^RigorFoundry native fixture failure at (.+); command trace (.+)$/mu.exec(
      result.stderr,
    );
    assert.ok(locator, "the actual failed public setup must report its owned fixture and command");
    const root = locator[1];
    const stem = locator[2];
    assert.ok(root && stem);
    assert.equal(path.dirname(stem), path.join(root, ".rigor"));
    assert.deepEqual(
      {
        stdout: await readFile(stem + ".stdout", "utf8"),
        stderr: await readFile(stem + ".stderr", "utf8"),
      },
      observed.output,
    );
    const failure: unknown = JSON.parse(await readFile(stem + ".failure.json", "utf8"));
    assert.ok(typeof failure === "object" && failure !== null);
    assert.ok("fixtureRoot" in failure && failure.fixtureRoot === root);
    assert.ok("commandTrace" in failure && failure.commandTrace === stem);
    assert.ok("capturedOutput" in failure && failure.capturedOutput === true);
    const sourceRoot =
      process.env["RIGOR_FOUNDRY_SOURCE_ROOT"] ?? path.resolve(__dirname, "../../../../..");
    for (const name of ["src/rigor_foundry/git_inventory.py", "tests/test_git_inventory.py"]) {
      assert.deepEqual(
        await readFile(path.join(root, name)),
        await readFile(path.join(sourceRoot, name)),
      );
    }
    const artifactRoot = path.resolve(__dirname, "../..", "fixtures", path.basename(scenario));
    await mkdir(artifactRoot, { recursive: true });
    await cp(root, path.join(artifactRoot, "workspace"), {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
    await cp(scenario, path.join(artifactRoot, "scenario"), {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
  });

  for (const [moduleName, diagnostic] of [
    ["contracts.test.js", "Evidence contract test setup failed:"],
    ["store.test.js", "Evidence store test setup failed:"],
  ] as const) {
    await test(
      "unit entry point refuses failed evidence setup: " + moduleName,
      async (context) => {
        const allocation = await mkdtemp(path.join(tmpdir(), "rigor-unit-setup-failure-"));
        context.after(async () => {
          await rm(allocation, { recursive: true, force: true });
        });
        const invalidConfig = path.join(allocation, "invalid-gitconfig");
        await writeFile(invalidConfig, "[broken\n", "utf8");
        const failure = await runCli(process.execPath, [path.join(__dirname, moduleName)], {
          cwd: allocation,
          timeoutMilliseconds: 60_000,
          maximumOutputBytes: 1_048_576,
          environment: {
            ...process.env,
            TMPDIR: allocation,
            TMP: allocation,
            TEMP: allocation,
            GIT_CONFIG_GLOBAL: invalidConfig,
            GIT_CONFIG_NOSYSTEM: "1",
            LC_ALL: "C",
          },
        }).catch((error: unknown): CommandExecutionFailure => {
          assert.ok(error instanceof CommandExecutionFailure);
          return error;
        });
        assert.ok(failure instanceof CommandExecutionFailure);
        assert.equal(failure.message, "RigorFoundry CLI failed with exit code 1");
        assert.ok(failure.output.stderr.includes(diagnostic));
        assert.doesNotMatch(failure.output.stderr, /bad config line/u);
        const locator = /^RigorFoundry native fixture failure at (.+); command trace (.+)$/mu.exec(
          failure.output.stderr,
        );
        assert.ok(locator);
        const root = locator[1];
        const stem = locator[2];
        assert.ok(root && stem);
        assert.equal(path.dirname(root), allocation);
        assert.equal(path.dirname(stem), path.join(root, ".rigor"));
        assert.equal(await readFile(stem + ".stdout", "utf8"), "");
        assert.match(await readFile(stem + ".stderr", "utf8"), /bad config line/u);
        assert.equal(await readFile(invalidConfig, "utf8"), "[broken\n");
      },
    );
  }
}

void run();
